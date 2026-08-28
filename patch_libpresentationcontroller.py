#!/usr/bin/env python3
"""Patch libPresentationController.so to bypass MHS2 map signature validation.

Background
----------
MHS2 units validate navigation map data against per-region ``content.sig``
signature files at load time. Maps produced by ``main.py`` (converted from an
MHI2 archive) have a restructured layout, so their original signatures no
longer match and the units refuse to load them.

Inside ``libPresentationController.so`` the signature-check result is consumed
by a small reporting function. Decompiled, it looks like::

    void report(obj, arg, valid):
        if (valid == 0):                 # signature check FAILED
            if (traceActive(chan, 4)) trace(...);
            forward(obj, /*isInvalid=*/1);
        else:                            # signature check PASSED
            if (traceActive(chan, 1)) trace(...);
            forward(obj, /*isInvalid=*/0);

In ARM this compiles to::

    cmp   r2, #0
    ...
    add   r4, pc, r4
    beq   <invalid_path>     <-- taken when the signature is INVALID
    ...  mov r1, #0 ; forward(obj, 0)   (valid path, falls through)

The bypass replaces that single ``beq`` with a ``mov r0, r0`` NOP
(``0xE1A00000``). Execution then always falls through to the "valid" path and
calls ``forward(obj, 0)`` regardless of the real check result, so invalid /
missing signatures are accepted. ``r0`` is reloaded immediately afterwards, so
clobbering it in the NOP has no effect.

This is exactly the 3-byte, size-preserving change found in the known-good
patched library, and this script reproduces it on any version of the library by
matching the surrounding instruction sequence rather than a fixed offset (the
offset moves between firmware versions).

Usage
-----
    python3 patch_libpresentationcontroller.py <libPresentationController.so> [output]

With no output path the patched file is written next to the input with a
``.patched`` suffix. The input file is never modified in place.
"""

import re
import sys

# ARM (little-endian) instruction fingerprint of the signature-result reporter.
# Bytes that vary between builds are wild-carded:
#   * the two ``ldr rX, [pc, #imm]`` displacements (literal-pool offsets), and
#   * the ``beq`` branch displacement and the final ``bl`` target.
# The ``sub sp, sp, #0x30`` frame setup is present in some builds and optimised
# away (tail-call) in others, so it is optional.
_ANY = rb"[\x00-\xff]"

_CONTEXT = (
    rb"\xf0\x41\x2d\xe9"              # push  {r4, r5, r6, r7, r8, lr}
    rb"\x00\x00\x52\xe3"              # cmp   r2, #0
    + _ANY + rb"[\x40-\x4f]\x9f\xe5"  # ldr   r4, [pc, #imm]
    rb"(?:\x30\xd0\x4d\xe2)?"         # sub   sp, sp, #0x30      (optional)
    rb"\x00\x50\xa0\xe1"              # mov   r5, r0
    rb"\x01\x60\xa0\xe1"              # mov   r6, r1
    rb"\x04\x40\x8f\xe0"              # add   r4, pc, r4
)
_TAIL = (
    _ANY + rb"[\x70-\x7f]\x9f\xe5"    # ldr   r7, [pc, #imm]
    rb"\x01\x10\xa0\xe3"              # mov   r1, #1
    rb"\x07\x70\x84\xe0"              # add   r7, r4, r7
    rb"\x07\x00\xa0\xe1"              # mov   r0, r7
    + _ANY * 3 + rb"\xeb"             # bl    TraceClientManagerProxy::isTracingActive
)

# Slot as shipped (a short forward ``beq``) and after patching (``mov r0, r0``).
# These are regex fragments (the engine decodes the ``\xNN`` escapes), so they
# are concatenated directly rather than escaped.
_SLOT_ORIG = _ANY + rb"\x00\x00\x0a"   # beq   <invalid_path>
_SLOT_NOP = rb"\x00\x00\xa0\xe1"       # mov   r0, r0   (NOP)

# Actual replacement bytes (a plain, non-raw literal: four real bytes).
NOP = b"\x00\x00\xa0\xe1"

_RE_UNPATCHED = re.compile(_CONTEXT + b"(" + _SLOT_ORIG + b")" + _TAIL, re.DOTALL)
_RE_PATCHED = re.compile(_CONTEXT + _SLOT_NOP + _TAIL, re.DOTALL)


class PatchError(Exception):
    pass


def find_patch_site(data: bytes) -> int:
    """Return the file offset of the ``beq`` to NOP, raising on ambiguity.

    Raises PatchError if the library is already patched, if the site is not
    found, or if more than one candidate matches (which should never happen for
    a genuine library and signals the fingerprint needs review).
    """
    unpatched = list(_RE_UNPATCHED.finditer(data))
    patched = list(_RE_PATCHED.finditer(data))

    if not unpatched:
        if patched:
            raise PatchError("library is already patched (NOP already present)")
        raise PatchError("signature-check site not found; unrecognised library version")
    if len(unpatched) > 1:
        offs = ", ".join(hex(m.start(1)) for m in unpatched)
        raise PatchError("ambiguous: multiple candidate sites (%s)" % offs)

    return unpatched[0].start(1)


def patch_bytes(data: bytes) -> tuple[bytes, int, bytes]:
    """Return (patched_data, offset, original_4_bytes)."""
    off = find_patch_site(data)
    original = data[off:off + 4]
    patched = data[:off] + NOP + data[off + 4:]
    assert len(patched) == len(data), "patch changed file size"
    return patched, off, original


def main(argv):
    if not 2 <= len(argv) <= 3:
        sys.exit("usage: %s <libPresentationController.so> [output]" % argv[0])

    src = argv[1]
    dst = argv[2] if len(argv) == 3 else src + ".patched"

    with open(src, "rb") as f:
        data = f.read()

    try:
        patched, off, original = patch_bytes(data)
    except PatchError as e:
        sys.exit("error: %s" % e)

    with open(dst, "wb") as f:
        f.write(patched)

    print("patched signature validation bypass")
    print("  input : %s (%d bytes)" % (src, len(data)))
    print("  output: %s (%d bytes)" % (dst, len(patched)))
    print("  offset: 0x%X" % off)
    print("  change: %s -> %s  (beq -> mov r0, r0 / NOP)"
          % (original.hex(" "), NOP.hex(" ")))


if __name__ == "__main__":
    main(sys.argv)
