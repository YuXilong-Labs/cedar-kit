#!/usr/bin/env python3
# Created by yuxilong on 2026/10/16.
"""Replace only a known root certificate, length and pin in every Mach-O slice."""

import hashlib
import struct
import subprocess


def require(condition, message):
    """Keep security checks active under python -O too."""
    if not condition:
        raise ValueError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def slices(data):
    require(data[:4] == bytes.fromhex("cafebabe"), "Unsupported Mach-O fat format")
    count = struct.unpack_from(">I", data, 4)[0]
    require(0 < count <= 16, "Invalid slice count")
    result = []
    for index in range(count):
        cpu, subtype, offset, size, _ = struct.unpack_from(
            ">IIIII", data, 8 + index * 20
        )
        arch = {
            (0x100000C, 0): "arm64",
            (0x100000C, 2): "arm64e",
            (0x1000007, 3): "x86_64",
        }.get((cpu, subtype & 0xFFFFFF))
        require(arch is not None, "Unsupported architecture")
        require(
            offset >= 8 + count * 20 and size >= 32 and offset + size <= len(data),
            "Invalid slice bounds",
        )
        require(
            all(
                offset + size <= start or offset >= start + length
                for _, start, length in result
            ),
            "Overlapping slices",
        )
        result.append((arch, offset, size))
    require(len({arch for arch, _, _ in result}) == count, "Duplicate architecture")
    return result


def file_offset(image, address, length):
    require(
        image[:4] == bytes.fromhex("cffaedfe"), "Expected 64-bit little-endian Mach-O"
    )
    count, commands_size = struct.unpack_from("<II", image, 16)
    require(32 + commands_size <= len(image), "Truncated load commands")
    cursor = 32
    for _ in range(count):
        require(cursor + 8 <= 32 + commands_size, "Truncated load command")
        command, size = struct.unpack_from("<II", image, cursor)
        require(
            size >= 8 and cursor + size <= 32 + commands_size, "Invalid load command"
        )
        if command == 0x19:
            require(size >= 72, "Truncated segment")
            vmaddr, _, offset, file_size = struct.unpack_from(
                "<QQQQ", image, cursor + 24
            )
            if vmaddr <= address and address + length <= vmaddr + file_size:
                mapped = offset + address - vmaddr
                require(mapped + length <= len(image), "Unmapped segment data")
                return mapped
        cursor += size
    raise ValueError(f"Unmapped address: {address:#x}")


def symbol_offsets(binary, arch, image):
    output = subprocess.check_output(
        ["xcrun", "nm", "-arch", arch, "-n", str(binary)], text=True
    )
    values = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[-1] in {
            "_kLKSRootCertDER",
            "_kLKSRootCertDERLength",
        }:
            require(parts[-1] not in values, "Duplicate root symbol")
            values[parts[-1]] = int(parts[0], 16)
    require(len(values) == 2, f"Missing root symbols in {arch}; manual review required")
    length_offset = file_offset(image, values["_kLKSRootCertDERLength"], 8)
    length = struct.unpack_from("<Q", image, length_offset)[0]
    require(0 < length <= 16384, "Invalid root length")
    root_offset = file_offset(image, values["_kLKSRootCertDER"], length)
    return root_offset, length_offset, length


def patch_image(image, root_offset, length_offset, old_length, root, expected_hash):
    require(0 < len(root) <= old_length, "Replacement root exceeds original DER slot")
    require(
        sha256(image[root_offset : root_offset + old_length]) == expected_hash,
        "Unknown upstream root; manual review required",
    )
    require(
        struct.unpack_from("<Q", image, length_offset)[0] == old_length,
        "Unexpected root length field",
    )
    pin = expected_hash.encode("ascii")
    require(image.count(pin) == 1, "Expected exactly one root SHA-256 pin per slice")
    pin_offset = image.index(pin)
    ranges = [(root_offset, old_length), (length_offset, 8), (pin_offset, 64)]
    for index, (start, length) in enumerate(ranges):
        require(0 <= start and start + length <= len(image), "Invalid patch bounds")
        require(
            all(
                start + length <= other or start >= other + size
                for other, size in ranges[:index]
            ),
            "Overlapping patch ranges",
        )
    changed = bytearray(image)
    changed[root_offset : root_offset + old_length] = root.ljust(old_length, b"\0")
    struct.pack_into("<Q", changed, length_offset, len(root))
    changed[pin_offset : pin_offset + 64] = sha256(root).encode("ascii")
    allowed = {i for start, length in ranges for i in range(start, start + length)}
    require(len(changed) == len(image), "Binary size changed")
    require(
        all(a == b or i in allowed for i, (a, b) in enumerate(zip(image, changed))),
        "Unexpected change outside root, length and pin",
    )
    return bytes(changed)


def patch_binary(binary, root, expected_hash, architectures):
    original = binary.read_bytes()
    layout = slices(original)
    require(
        {arch for arch, _, _ in layout} == set(architectures), "Architecture mismatch"
    )
    patched = bytearray(original)
    report = []
    for arch, offset, size in layout:
        image = original[offset : offset + size]
        root_offset, length_offset, old_length = symbol_offsets(binary, arch, image)
        patched[offset : offset + size] = patch_image(
            image, root_offset, length_offset, old_length, root, expected_hash
        )
        report.append(
            {
                "architecture": arch,
                "original_root_length": old_length,
                "root_length": len(root),
            }
        )
    binary.write_bytes(patched)
    return {"original_sha256": sha256(original), "slices": report}


def verify_binary(binary, root):
    """Recalculate offsets after codesign, which may move fat slices."""
    data = binary.read_bytes()
    for arch, offset, size in slices(data):
        image = data[offset : offset + size]
        root_offset, _, length = symbol_offsets(binary, arch, image)
        require(
            length == len(root) and image[root_offset : root_offset + length] == root,
            "Post-sign root verification failed",
        )
        require(
            image.count(sha256(root).encode("ascii")) == 1,
            "Post-sign pin verification failed",
        )
    return sha256(data)
