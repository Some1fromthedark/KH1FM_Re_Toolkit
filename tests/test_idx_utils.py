import unittest
from unittest.mock import patch, mock_open
import struct
import os

from .. import idx_utils

class TestIdxUtils(unittest.TestCase):

    # --- Test GetHash ---
    def test_get_hash(self):
        """Validate GetHash against known filename/hash pairs from Hashlist.txt."""
        # Build path relative to this test file
        hashlist_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "resources",
            "Hashlist.txt"
        )

        with open(hashlist_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        # Skip the first line (title/header)
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue  # skip empty lines

            # Expected format: "00000000\t=\tfilename.txt"
            try:
                hash_part, filename = line.split("\t=\t")
            except ValueError:
                self.fail(f"Invalid line format in Hashlist.txt: {line}")

            expected_hash = int(hash_part, 16)
            computed_hash = idx_utils.GetHash(filename)

            self.assertEqual(
                computed_hash,
                expected_hash,
                f"Hash mismatch for '{filename}': "
                f"expected 0x{expected_hash:08X}, got 0x{computed_hash:08X}"
            )

    # --- Test IdxEntry ---
    def test_idx_entry_init_and_str(self):
        """Test IdxEntry string representation."""
        entry = idx_utils.IdxEntry(0xABC, 1, 0x10, 0x200)
        output = str(entry)
        self.assertIn("abc", output)
        self.assertIn("0x10", output) # 0x10 in decimal

    def test_idx_entry_pack(self):
        """Test packing an entry back to binary."""
        entry = idx_utils.IdxEntry(0x1, 0x2, 0x10, 0x20)
        # Testing with an offset of 5 (start_block should become 11)
        packed = entry.pack(start_block_offset=5)
        unpacked = struct.unpack("<IIII", packed)
        self.assertEqual(unpacked, (1, 2, 11, 32))

    # --- Test Idx Class ---
    def test_idx_parsing(self):
        """Test parsing raw binary data into an Idx object."""
        # Create dummy binary data: 2 entries (16 bytes each)
        # Entry 1: Hash 1, Flags 0, Start 10, Size 100
        # Entry 2: Hash 2, Flags 0, Start 20, Size 200
        raw_data = struct.pack("<IIII", 1, 0, 10, 100) + \
                   struct.pack("<IIII", 2, 0, 20, 200)
        
        idx_obj = idx_utils.Idx(raw_data, start_block_offset=5)
        
        self.assertEqual(len(idx_obj.entries), 2)
        self.assertIn(1, idx_obj.entries)
        self.assertIn(2, idx_obj.entries)
        self.assertEqual(idx_obj.entries[1].flags, 0)
        self.assertEqual(idx_obj.entries[2].flags, 0)
        self.assertEqual(idx_obj.entries[1].start_block, 15) # 10 + 5 offset
        self.assertEqual(idx_obj.entries[2].start_block, 25) # 20 + 5 offset
        self.assertEqual(idx_obj.entries[1].file_size, 100)
        self.assertEqual(idx_obj.entries[2].file_size, 200)

    def test_idx_hash_collision_warning(self):
        """Test that a collision triggers a print warning."""
        raw_data = struct.pack("<IIII", 100, 0, 1, 10) + \
                   struct.pack("<IIII", 100, 0, 2, 20)
        
        with patch('builtins.print') as mocked_print:
            idx_utils.Idx(raw_data)
            mocked_print.assert_called_with("WARNING: Hash Collision @ 0x64")

    # --- Test create_idx_entry ---
    @patch("builtins.open", new_callable=mock_open, read_data=b"hello world")
    def test_create_idx_entry_success(self, mock_file):
        """Test creating an entry from a 'file'."""
        entry = idx_utils.create_idx_entry(0x123, "dummy.txt", is_compressed=False, start_block=50)
        self.assertEqual(entry.file_size, 11) # len("hello world")
        self.assertEqual(entry.file_hash, 0x123)

    @patch("builtins.open", new_callable=mock_open, read_data=b"hello world")
    def test_create_idx_entry_compression_error(self, mock_file):
        """Test that compression currently raises an Exception."""
        with self.assertRaises(Exception) as cm:
            idx_utils.create_idx_entry(0x1, "test.txt", is_compressed=True)
        self.assertIn("Compression is not yet supported", str(cm.exception))

if __name__ == "__main__":
    unittest.main()
