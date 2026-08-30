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

The bypass rewrites every *rejecting* ``forward(obj, 1)`` call to
``forward(obj, 0)`` -- a single byte each (the immediate ``0x01`` -> ``0x00``).
``forward`` is then always told the signature is valid, so invalid / missing
signatures are accepted, while the original control flow and the "signature
check ... failed" diagnostic are left untouched. This is the exact,
size-preserving change found in the known-good prebuilt library; unlike
NOP-ing the conditional branch into the failure block, it flips only the value
the function reports.

Locating the rejecting calls across builds
------------------------------------------
The reporting function is found by its unique prologue. Every ``forward`` call
loads ``obj`` (kept in ``r5``) as the first argument, which distinguishes it
from the ``tracingActive`` calls (which pass a trace channel in ``r0``), so a
rejecting call is::

    mov   r0, r5           ; obj
    mov   r1, #1           ; isInvalid = 1        <-- byte flipped to #0
    <tail>

The compiler emits ``<tail>`` in two forms depending on the build:

  * ``bl <forward> ; b <epilogue>``            -- a normal call, or
  * ``pop {r4-r8, lr} ; b <forward>``          -- a tail call.

and it may emit the rejecting call once (both failure paths merged) or twice
(one per path). The patcher therefore matches either tail and flips *all*
rejecting calls it finds inside the function -- so it handles both the
duplicated-exit builds (e.g. the original prebuilt: two sites) and the
tail-call/merged-exit builds (e.g. K0137: one site) from the same fingerprint.
The search is bounded to the function body using the function's own
literal-pool reference, so unrelated ``mov r0,r5 ; mov r1,#1`` sequences
elsewhere in the binary are never touched.

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
    + _ANY + rb"[\x40-\x4f]\x9f\xe5"  # ldr   r4, [pc, #imm]     (imm -> literal pool)
    rb"(?:\x30\xd0\x4d\xe2)?"         # sub   sp, sp, #0x30      (optional)
    rb"\x00\x50\xa0\xe1"              # mov   r5, r0             (obj saved in r5)
    rb"\x01\x60\xa0\xe1"              # mov   r6, r1
    rb"\x04\x40\x8f\xe0",             # add   r4, pc, r4
    re.DOTALL,
)

# A rejecting forward call: mov r0,r5 ; mov r1,#imm ; <tail>. The ``mov r0, r5``
# (obj) prefix is what marks a forward call; the tail is either a plain call
# (``bl <forward>``) or a tail call (``pop {r4-r8, lr}``), each followed by a
# branch. Operands that move between builds are wild-carded.
_MOV_R0_R5 = rb"\x05\x00\xa0\xe1"     # mov r0, r5   (obj -> arg 0)
_MOV_R1_1 = rb"\x01\x10\xa0\xe3"      # mov r1, #1   (isInvalid = 1, as shipped)
_MOV_R1_0 = rb"\x00\x10\xa0\xe3"      # mov r1, #0   (isInvalid = 0, after patch)
_POP_FRAME = rb"\xf0\x41\xbd\xe8"     # pop {r4, r5, r6, r7, r8, lr}
_BL_ANY = _ANY * 3 + rb"\xeb"        # bl <forward>
_B_ANY = _ANY * 3 + rb"\xea"         # b  <forward|epilogue>
_TAIL = rb"(?:" + _BL_ANY + rb"|" + _POP_FRAME + rb")" + _B_ANY

_SITE_REJECT = re.compile(_MOV_R0_R5 + _MOV_R1_1 + _TAIL, re.DOTALL)
_SITE_ACCEPT = re.compile(_MOV_R0_R5 + _MOV_R1_0 + _TAIL, re.DOTALL)

# Position of the patched immediate within a site match, and its byte values.
_IMM_OFFSET = 4
_IMM_REJECT = 0x01
_IMM_ACCEPT = 0x00


class PatchError(Exception):
    pass


def _function_end(data: bytes, base: int) -> int:
    """Offset just past the reporter's code, from its ``ldr r4, [pc, #imm]``.

    The prologue's ``ldr r4, [pc, #imm]`` references r4's base value in the
    function's literal pool, which the compiler places immediately after the
    code. That reference therefore bounds the code body and never reaches into
    the next function, whatever the build.
    """
    ldr = base + 8                                   # 3rd instruction of the prologue
    imm = data[ldr] | ((data[ldr + 1] & 0x0F) << 8)  # 12-bit ldr displacement
    return ldr + 8 + imm                             # ARM: pc is (insn + 8)


def find_patch_sites(data: bytes) -> list[int]:
    """Return the file offsets of the ``mov r1, #1`` immediates to flip.

    Raises PatchError if the library is already patched, if the reporter cannot
    be located, or if it looks unlike any known build -- signalling the
    fingerprint needs review rather than risking a wrong patch.
    """
    anchors = list(_CONTEXT.finditer(data))
    if not anchors:
        raise PatchError("signature-check site not found; unrecognised library version")
    if len(anchors) > 1:
        offs = ", ".join(hex(m.start()) for m in anchors)
        raise PatchError("ambiguous: multiple candidate functions (%s)" % offs)

    base = anchors[0].start()
    region = data[base:_function_end(data, base)]
    reject = [base + m.start() for m in _SITE_REJECT.finditer(region)]

    if not reject:
        if _SITE_ACCEPT.search(region):
            raise PatchError("library is already patched (no rejecting forward calls remain)")
        raise PatchError("signature-check exits not found; unrecognised library version")

    return [off + _IMM_OFFSET for off in reject]


def patch_bytes(data: bytes) -> tuple[bytes, list[int]]:
    """Return (patched_data, [offsets_changed])."""
    sites = find_patch_sites(data)
    out = bytearray(data)
    for off in sites:
        assert out[off] == _IMM_REJECT, "unexpected byte at patch site 0x%X" % off
        out[off] = _IMM_ACCEPT
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
    print("  change: mov r1, #1 -> mov r1, #0  (isInvalid 1 -> 0) at %d rejecting forward call%s"
          % (len(sites), "" if len(sites) == 1 else "s"))


if __name__ == "__main__":
    main(sys.argv)
