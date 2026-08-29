#!/usr/bin/env python3
"""Patch libPresentationController.so to bypass MHS2 map signature validation.

Background
----------
MHS2 units validate navigation map data against per-region ``content.sig``
signature files at load time. Maps produced by ``main.py`` (converted from an
MHI2 archive) have a restructured layout, so their original signatures no
longer match and the units refuse to load them.

Inside ``libPresentationController.so`` a single function reports the result of
each signature check to its caller. Decompiled, it looks like::

    void report(obj, name, valid):
        if (valid == 0):                     # signature check FAILED
            if (tracingActive(chan, 4)):
                trace("Result: signature check of " + name + " failed");
            forward(obj, /*isInvalid=*/1);   # <-- REJECT
        else:                                # signature check PASSED
            if (tracingActive(chan, 1)):
                trace("Result: signature check of " + name + " successful");
            forward(obj, /*isInvalid=*/0);   # <-- ACCEPT

The failure branch reaches ``forward(obj, 1)`` from two places -- once when
tracing is inactive and once after emitting the "failed" trace message -- and
each is compiled as::

    mov   r0, r5           ; obj
    mov   r1, #1           ; isInvalid = 1
    bl    <forward>
    b     <return>

The bypass rewrites the ``mov r1, #1`` immediate to ``mov r1, #0`` at *both*
failure exits -- a single byte each (``0x01`` -> ``0x00``). ``forward`` is then
always told the signature is valid, so invalid / missing signatures are
accepted, while the original control flow and the "signature check ... failed"
diagnostic are left untouched.

This is the exact, size-preserving change found in the known-good prebuilt
library. Rather than NOP-ing the conditional branch into the failure block
(which discards the block and mislabels failures as "successful" in any trace
output), it flips only the value the function reports -- the most surgical
bypass, and the one that reproduces the shipped prebuilt byte-for-byte.

The reporter is located by its unique prologue and the two exits by their
instruction pattern, so the patch reproduces on any build regardless of where
the function moved between firmware versions.

Usage
-----
    python3 patch_libpresentationcontroller.py <libPresentationController.so> [output]

With no output path the patched file is written next to the input with a
``.patched`` suffix. The input file is never modified in place.
"""

import re
import sys

_ANY = rb"[\x00-\xff]"

# Anchor: the unique prologue of the signature-result reporter. The only byte
# that varies between builds is the ``ldr r4, [pc, #imm]`` literal-pool
# displacement (wild-carded). The ``sub sp, sp, #0x30`` frame setup is present
# in some builds and optimised away (tail-call) in others, so it is optional.
_CONTEXT = re.compile(
    rb"\xf0\x41\x2d\xe9"              # push  {r4, r5, r6, r7, r8, lr}
    rb"\x00\x00\x52\xe3"              # cmp   r2, #0
    + _ANY + rb"[\x40-\x4f]\x9f\xe5"  # ldr   r4, [pc, #imm]
    rb"(?:\x30\xd0\x4d\xe2)?"         # sub   sp, sp, #0x30      (optional)
    rb"\x00\x50\xa0\xe1"              # mov   r5, r0
    rb"\x01\x60\xa0\xe1"              # mov   r6, r1
    rb"\x04\x40\x8f\xe0",             # add   r4, pc, r4
    re.DOTALL,
)

# A failure exit: mov r0,r5 ; mov r1,#imm ; bl <forward> ; b <return>.
# The bl/b displacements move between builds, so those operands are wild-carded.
_MOV_R0_R5 = rb"\x05\x00\xa0\xe1"
_MOV_R1_1 = rb"\x01\x10\xa0\xe3"      # mov r1, #1   (as shipped: isInvalid = 1)
_MOV_R1_0 = rb"\x00\x10\xa0\xe3"      # mov r1, #0   (after patching)
_BL_ANY = _ANY * 3 + rb"\xeb"        # bl <forward>
_B_ANY = _ANY * 3 + rb"\xea"         # b  <return>

_SITE_ORIG = re.compile(_MOV_R0_R5 + _MOV_R1_1 + _BL_ANY + _B_ANY, re.DOTALL)
_SITE_PATCHED = re.compile(_MOV_R0_R5 + _MOV_R1_0 + _BL_ANY + _B_ANY, re.DOTALL)

# How far past the prologue the reporter's body extends. Both failure exits sit
# well inside this; scoping the search to the single function found by the
# anchor is what keeps the (individually common) exit pattern unambiguous.
_WINDOW = 0x200

# Position of the patched immediate within a site match, and its byte values.
_IMM_OFFSET = 4
_IMM_ORIG = 0x01
_IMM_NOP = 0x00


class PatchError(Exception):
    pass


def _branch_target(data: bytes, off: int) -> int:
    """Absolute target (in file-offset space) of the ARM b/bl word at ``off``."""
    word = int.from_bytes(data[off:off + 4], "little")
    imm = word & 0x00FFFFFF
    if imm & 0x00800000:               # sign-extend the 24-bit displacement
        imm -= 0x01000000
    return off + 8 + (imm << 2)


def find_patch_sites(data: bytes) -> list[int]:
    """Return the file offsets of the two ``mov r1, #1`` immediates to flip.

    Raises PatchError if the library is already patched, if the reporter cannot
    be located, or if the failure exits do not look as expected -- signalling
    the fingerprint needs review rather than risking a wrong patch.
    """
    anchors = list(_CONTEXT.finditer(data))
    if not anchors:
        raise PatchError("signature-check site not found; unrecognised library version")
    if len(anchors) > 1:
        offs = ", ".join(hex(m.start()) for m in anchors)
        raise PatchError("ambiguous: multiple candidate functions (%s)" % offs)

    base = anchors[0].start()
    window = data[base:base + _WINDOW]
    orig = [base + m.start() for m in _SITE_ORIG.finditer(window)]
    patched = [base + m.start() for m in _SITE_PATCHED.finditer(window)]

    if not orig:
        if len(patched) == 2:
            raise PatchError("library is already patched (both failure exits report valid)")
        raise PatchError("signature-check exits not found; unrecognised library version")
    if len(orig) != 2 or patched:
        found = ", ".join(hex(o) for o in sorted(orig + patched))
        raise PatchError(
            "unexpected failure-exit layout (%d unpatched, %d patched: %s)"
            % (len(orig), len(patched), found)
        )

    # Both genuine exits must call the same reporter and return to the same
    # epilogue; if they disagree we have matched something else.
    s0, s1 = orig
    if (_branch_target(data, s0 + 8) != _branch_target(data, s1 + 8)
            or _branch_target(data, s0 + 12) != _branch_target(data, s1 + 12)):
        raise PatchError("failure exits disagree on call/return target; fingerprint needs review")

    return [s0 + _IMM_OFFSET, s1 + _IMM_OFFSET]


def patch_bytes(data: bytes) -> tuple[bytes, list[int]]:
    """Return (patched_data, [offsets_changed])."""
    sites = find_patch_sites(data)
    out = bytearray(data)
    for off in sites:
        assert out[off] == _IMM_ORIG, "unexpected byte at patch site 0x%X" % off
        out[off] = _IMM_NOP
    assert len(out) == len(data), "patch changed file size"
    return bytes(out), sites


def main(argv):
    if not 2 <= len(argv) <= 3:
        sys.exit("usage: %s <libPresentationController.so> [output]" % argv[0])

    src = argv[1]
    dst = argv[2] if len(argv) == 3 else src + ".patched"

    with open(src, "rb") as f:
        data = f.read()

    try:
        patched, sites = patch_bytes(data)
    except PatchError as e:
        sys.exit("error: %s" % e)

    with open(dst, "wb") as f:
        f.write(patched)

    print("patched signature validation bypass")
    print("  input : %s (%d bytes)" % (src, len(data)))
    print("  output: %s (%d bytes)" % (dst, len(patched)))
    print("  sites : %s" % ", ".join("0x%X" % s for s in sites))
    print("  change: mov r1, #1 -> mov r1, #0  (isInvalid 1 -> 0) at both failure exits")


if __name__ == "__main__":
    main(sys.argv)
