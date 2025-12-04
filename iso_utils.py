import struct

IS_DIR_FLAG = 2

class Iso:
    def __init__(self, iso_path, mode="r"):
        self.mode = mode
        if self.mode == "r":
            self.stream = open(iso_path, "rb")
            self.seek(0x8080)
            self.block_size, = struct.unpack("<H", self.read(2))
            self.seek(0x809E)
            self.primary_dir_block, = struct.unpack("<I", self.read(4))
            self.stream.seek(self.primary_dir_block * self.block_size)
            #print(f"Primary Dir Offset: {hex(self.stream.tell())}")
            self.entries = []
            entry = IsoDirEntry(self.stream)
            i = 0
            while entry.start_block is not None:
                self.entries.append(entry)
                #print(f"Entry {i} Filename: {entry.filename}")
                #print(f"Entry Start Block: {hex(entry.start_block)}")
                #print(f"Entry Data Size: {hex(entry.data_size)}")
                entry = IsoDirEntry(stream=self.stream)
                i += 1
            
        elif self.mode == "w":
            self.stream = open(iso_path, "wb")
        else:
            raise Exception("ERROR: Invalid ISO mode requested")
    
    def close(self):
        self.stream.close()

    def read(self, size=-1):
        return self.stream.read(size)
    
    def seek(self, offset):
        self.stream.seek(offset)
        
    def tell(self):
        return self.stream.tell()
        
    def write(self, data):
        self.stream.write(data)

class IsoDirEntry:
    def __init__(self, stream=None, start_block=None, data_size=None, creation_time=None, flags=None, unk_value=None, filename=None):
        if stream is not None:
            start_offset = stream.tell()
            entry_size, = struct.unpack("<H", stream.read(2))
            if entry_size > 0:
                self.start_block, _ = struct.unpack("<II", stream.read(8))
                self.data_size, _ = struct.unpack("<II", stream.read(8))
                self.creation_time = struct.unpack("<7B", stream.read(7))
                self.flags, _ = struct.unpack("<BH", stream.read(3))
                self.unk_value, _ = struct.unpack("<HH", stream.read(4))
                name_len, = struct.unpack("<B", stream.read(1))
                self.filename, = struct.unpack(f"{name_len}s", stream.read(name_len))
                self.filename = self.filename.decode("utf-8")
                stream.seek(start_offset + entry_size)
            else:
                # Default values
                self.start_block = None
                self.data_size = None
                self.creation_time = None
                self.flags = None
                self.unk_value = None
                self.filename = None
                # Undo the read
                stream.seek(stream.tell() - 2)
        else:
            # Default values
            self.start_block = None
            self.data_size = None
            self.creation_time = None
            self.flags = None
            self.unk_value = None
            self.filename = None
        if start_block is not None:
            self.start_block = start_block
        if data_size is not None:
            self.data_size = data_size
        if creation_time is not None:
            self.creation_time = creation_time
        if flags is not None:
            self.flags = flags
        if unk_value is not None:
            self.unk_value = unk_value
        if filename is not None:
            self.filename = filename

    def __str__(self):
        return f"Start Block: {hex(self.start_block)}\nData Size: {hex(self.data_size)}\nCreation Time: {self.creation_time}\nFlags: {self.flags}\nUnknown Value: {self.unk_value}\nFilename: {self.filename}\n"
        
    def pack(self):
        filename_len = len(self.filename)
        padding_len = 14 + ((filename_len + 1) % 2)
        entry_size = 33 + filename_len + padding_len
        packed_start_block = struct.pack("<I", self.start_block)
        packed_data_size = struct.pack("<I", self.data_size)
        packed_unk_value = struct.pack("<H", self.unk_value)
        packed_str = struct.pack("<H", entry_size)
        packed_str = packed_str + packed_start_block + packed_start_block[::-1]
        packed_str = packed_str + packed_data_size + packed_data_size[::-1]
        packed_str = packed_str + struct.pack("<7B", *self.creation_time)
        packed_str = packed_str + struct.pack("<BH", self.flags, 0)
        packed_str = packed_str + packed_unk_value + packed_unk_value[::-1]
        packed_str = packed_str + struct.pack(f"<B{filename_len}s", filename_len, self.filename.encode("utf-8"))
        packed_str = packed_str + b'\0'*padding_len
        return packed_str

def main():
    pass

if __name__ == "__main__":
    main()