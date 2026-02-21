import struct

def GetHash(filename):
    filename_bytes = filename.encode("utf-8")
    file_hash = 0
    for b in filename_bytes:
        file_hash = (2 * file_hash) ^ ((int(b) << 16) % 69665)
    return file_hash & 0xFFFFFFFF

class Idx():
    def __init__(self, raw_data, start_block_offset=0):
        self.entries = {}
        self.start_block_offset = start_block_offset
        for i in range(len(raw_data) // 16):
            entry_start_off = i * 16
            file_hash, flags, start_block, file_len = struct.unpack("<IIII", raw_data[entry_start_off:entry_start_off + 16])
            if file_hash > 0:
                if file_hash in self.entries:
                    print(f"WARNING: Hash Collision @ {hex(file_hash)}")
                self.entries[file_hash] = IdxEntry(file_hash, flags, start_block + start_block_offset, file_len)

class IdxEntry():
    def __init__(self, file_hash, flags, start_block, file_size):
        self.file_hash = file_hash
        self.flags = flags
        self.start_block = start_block
        self.file_size = file_size
    
    def __str__(self):
        return f"File Hash: {hex(self.file_hash)}\nFlags: {self.flags}\nStart Block: {hex(self.start_block)}\nFile Size: {hex(self.file_size)}"

    def pack(self, start_block_offset=0):
        return struct.pack("<IIII", self.file_hash, self.flags, self.start_block - start_block_offset, self.file_size)

def create_idx_entry(file_hash, file_path, is_compressed, start_block=None):
    with open(file_path, 'rb') as f:
        file_content = f.read()
    if is_compressed:
        raise Exception("ERROR: File Compression is not yet supported")
    return IdxEntry(file_hash, is_compressed, start_block, len(file_content))

def main():
    pass

if __name__ == "__main__":
    main()