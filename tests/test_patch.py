# Created by yuxilong on 2026/10/16.
"""Reject unsafe or incompatible inputs before any release is published."""

from pathlib import Path
import struct
import stat
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from patch import file_offset, patch_image, sha256, slices
from release import release_version, validate_archive


class PatchTests(unittest.TestCase):
    def setUp(self):
        self.old = b"original test certificate"
        self.root = b"new test CA"
        self.image = self.old + bytes(8 - len(self.old) % 8)
        self.length_offset = len(self.image)
        self.image += struct.pack("<Q", len(self.old)) + bytes(16)
        self.image += sha256(self.old).encode() + b"executable bytes remain unchanged"

    def patch(self, image=None, root=None, digest=None):
        return patch_image(
            self.image if image is None else image,
            0,
            self.length_offset,
            len(self.old),
            self.root if root is None else root,
            sha256(self.old) if digest is None else digest,
        )

    def test_only_root_length_and_pin_change(self):
        changed = self.patch()
        self.assertEqual(len(changed), len(self.image))
        self.assertEqual(
            changed[: len(self.old)], self.root.ljust(len(self.old), b"\0")
        )
        self.assertEqual(
            struct.unpack_from("<Q", changed, self.length_offset)[0], len(self.root)
        )
        self.assertIn(sha256(self.root).encode(), changed)
        self.assertTrue(changed.endswith(b"executable bytes remain unchanged"))

    def test_unknown_root_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unknown upstream root"):
            self.patch(digest="0" * 64)

    def test_oversized_root_rejected(self):
        with self.assertRaisesRegex(ValueError, "exceeds"):
            self.patch(root=bytes(1286))

    def test_duplicate_pin_rejected(self):
        with self.assertRaisesRegex(ValueError, "exactly one"):
            self.patch(image=self.image + sha256(self.old).encode())

    def test_missing_pin_rejected(self):
        with self.assertRaisesRegex(ValueError, "exactly one"):
            self.patch(image=self.image.replace(sha256(self.old).encode(), b"x" * 64))

    def test_bad_length_rejected(self):
        image = bytearray(self.image)
        struct.pack_into("<Q", image, self.length_offset, 0)
        with self.assertRaisesRegex(ValueError, "length field"):
            self.patch(image=bytes(image))

    def test_double_patch_rejected(self):
        with self.assertRaises(ValueError):
            self.patch(image=self.patch())

    def test_load_segment_mapping_and_bounds(self):
        image = bytearray(200)
        image[:4] = bytes.fromhex("cffaedfe")
        struct.pack_into("<II", image, 16, 1, 72)
        struct.pack_into("<II", image, 32, 0x19, 72)
        struct.pack_into("<QQQQ", image, 56, 0x1000, 200, 0, 200)
        self.assertEqual(file_offset(image, 0x1080, 8), 128)
        with self.assertRaisesRegex(ValueError, "Unmapped"):
            file_offset(image, 0x10C0, 16)

    def test_fat_slice_bounds(self):
        image = bytearray(128)
        image[:4] = bytes.fromhex("cafebabe")
        struct.pack_into(">I", image, 4, 1)
        struct.pack_into(">IIIII", image, 8, 0x100000C, 0, 64, 64, 6)
        self.assertEqual(slices(image), [("arm64", 64, 64)])
        struct.pack_into(">I", image, 20, 100)
        with self.assertRaisesRegex(ValueError, "bounds"):
            slices(image)

    def test_release_tag_validation(self):
        self.assertEqual(release_version("v1.2.3", 2), "1.2.3-special.2")
        for tag in ["../escape", "1.2.3; echo secret", "1.2.3-rc1"]:
            with self.assertRaises(ValueError):
                release_version(tag, 1)

    def test_archive_traversal_rejected(self):
        scratch = Path(__file__).resolve().parents[1] / "build/tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            archive = Path(directory) / "test.zip"
            with zipfile.ZipFile(archive, "w") as zipped:
                zipped.writestr("LookInsideServer.xcframework/../../outside", "bad")
            with self.assertRaisesRegex(ValueError, "Unsafe archive"):
                validate_archive(archive)

    def test_symlink_parent_traversal_rejected(self):
        scratch = Path(__file__).resolve().parents[1] / "build/tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            archive = Path(directory) / "test.zip"
            with zipfile.ZipFile(archive, "w") as zipped:
                link = zipfile.ZipInfo("LookInsideServer.xcframework/x/y")
                link.create_system = 3
                link.external_attr = (stat.S_IFLNK | 0o777) << 16
                zipped.writestr(link, "../z")
            with self.assertRaisesRegex(ValueError, "Unsafe framework symlink"):
                validate_archive(archive)


if __name__ == "__main__":
    unittest.main()
