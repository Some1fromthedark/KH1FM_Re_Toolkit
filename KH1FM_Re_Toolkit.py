import argparse
import json
import os
import struct

import idx_utils
import iso_utils

# Ported from C# implementation on Govanify's Github
def NGYXor(encrypted_data):
    decrypted_data = b''
    v84 = [ 164, 28, 107, 129, 48, 13, 35, 91, 92, 58, 167, 222, 219, 244, 115, 90, 160, 194, 112, 209, 40, 72, 170, 114, 98, 181, 154, 124, 124, 32, 224, 199, 34, 32, 114, 204, 38, 198, 188, 128, 45, 120, 181, 149, 219, 55, 33, 116, 6, 17, 181, 125, 239, 137, 72, 215, 1, 167, 110, 208, 110, 238, 124, 204 ]
    for i in range(len(encrypted_data)):
        input_byte = encrypted_data[i]
        key = v84[(len(encrypted_data) - i - 1) % len(v84)]
        output_byte = input_byte ^ key
        decrypted_data = decrypted_data + chr(input_byte ^ key).encode("utf-8")
    return decrypted_data

def map_iso(config):
    # Get the iso path from the config object
    iso_path = config.get("iso_path", "KHFM.iso")
    
    # Instantiate an Iso object
    iso = iso_utils.Iso(iso_path)
    
    # Determine the hash for kingdom.img
    kingdom_img_hash = idx_utils.GetHash("kingdom.img")
    
    idx = None
    visible_file_map = {}
    start_block_offset = 0
    # Iterate through the Iso file entries
    for entry in iso.entries:
        # Make sure the file entry is for a normal file and not a directory
        if entry.flags & iso_utils.IS_DIR_FLAG == 0:
            # Populate the start block map
            visible_file_map[idx_utils.GetHash(entry.filename[:-2].lower())] = entry
            # Check if this is the entry for KINGDOM.IDX
            if entry.filename == "KINGDOM.IDX;1":
                # Instantiate the Idx object from KINGDOM.IDX's data
                iso.seek(entry.start_block * iso.block_size)
                idx_content = iso.read(entry.data_size)
                idx = idx_utils.Idx(idx_content)
                # Iterate over the idx entries to find a hash that maps to a file we know
                for file_hash in idx.entries:
                    idx_entry = idx.entries[file_hash]
                    if file_hash in visible_file_map:
                        # Calculate the start block offset
                        start_block_offset = visible_file_map[file_hash].start_block - idx_entry.start_block
                        break
                # Check if we need to update the idx object
                if start_block_offset != 0:
                    # Instatiate the Idx object with the start block offset
                    idx = idx_utils.Idx(idx_content, start_block_offset=start_block_offset)
    
    # Validate that we successfully instantiated an Idx object
    if idx is None:
        raise Exception("ERROR: Failed to find kingdom.idx entry in iso")

    # Iterate over the idx entries to find the entry for KINGDOM.IMG
    for file_hash in idx.entries:
        idx_entry = idx.entries[file_hash]
        if file_hash == kingdom_img_hash:
            # Save the start offset and length of KINGDOM.IMG for later
            kingdom_start_offset = idx_entry.start_block * iso.block_size
            kingdom_length = idx_entry.file_size
            #print("KINGDOM.IMG:")
            #print(f"  Flags: {hex(idx_entry.flags)}")
            #print(f"  Start Offset: {hex(kingdom_start_offset)}")
            #print(f"  Size: {hex(kingdom_length)}")
            break
    else:
        raise Exception("ERROR: Failed to find kingdom.img entry in kingdom.idx")
    
    # Sort the Idx entries by their start block
    sorted_entries = sorted(list(idx.entries.values()), key=lambda item:item.start_block)
    #print("\nSorted Entries:")
    #for i, entry in enumerate(sorted_entries):
    #    print(f"--------------------\n IDX Entry {i}:\n--------------------")
    #    print(entry)
    
    # Initialize variables for mapping the iso
    depth = 0
    start_block = sorted_entries[0].start_block
    end_size = sorted_entries[-1].file_size // iso.block_size
    if sorted_entries[-1].file_size % iso.block_size == 0:
        end_size -= 1
    end_block = sorted_entries[-1].start_block + end_size
    entry_ind = 0
    padding_display_ind = 0
    padding_display_threshold = 1
    closing_blocks = []
    # Print the map of the iso to the console
    print("--------\nISO Map:\n--------")
    for i in range(start_block, end_block + 1):
        padding = "|"*depth
        if entry_ind < len(sorted_entries):
            entry = sorted_entries[entry_ind]
        else:
            entry = None
        if entry is not None and entry.start_block == i:
            if padding_display_ind == padding_display_threshold + 1:
                print(padding)
            print(f"{padding}", end="")
            while entry is not None and entry.start_block == i:
                print("+", end="")
                padding_display_ind = 0
                entry_block_size = entry.file_size // iso.block_size
                if entry.file_size % iso.block_size == 0:
                    entry_block_size -= 1
                if entry_block_size > 0:
                    depth += 1
                    closing_blocks.append(entry.start_block + entry_block_size)
                    closing_blocks = sorted(closing_blocks)
                else:
                    print("-", end="")
                entry_ind += 1
                if entry_ind < len(sorted_entries):
                    entry = sorted_entries[entry_ind]
                else:
                    entry = None
            print(f"{hex(i)}")
        elif len(closing_blocks) > 0 and closing_blocks[0] == i:
            if padding_display_ind == padding_display_threshold + 1:
                print(padding)
            decreased_depth = 0
            while len(closing_blocks) > 0 and closing_blocks[0] == i:
                decreased_depth += 1
                closing_blocks = closing_blocks[1:]
            depth -= decreased_depth
            padding = "|"*depth + "-"*decreased_depth
            print(f"{padding}{hex(i)}")
            padding_display_ind = 0
        elif padding_display_ind < padding_display_threshold:
            print(padding)
            padding_display_ind += 1
        elif padding_display_ind == padding_display_threshold:
            print("...")
            padding_display_ind += 1
            
    # Clean Up
    iso.close()

def decrypt(config):
    # Get the input and output paths from the config object
    input_path = config.get("input_path", None)
    output_path = config.get("output_path", None)
    if input_path is not None:
        # Read the input file from the input path
        with open(input_path, 'rb') as f:
            input_contents = f.read()
        # Decrypt the file
        output_contents = NGYXor(input_contents)
        if output_path is not None and len(output_contents) > 0:
            # Write the decrypted file to the output path
            with open(output_path, 'wb') as f:
                f.write(output_contents)

def patch(config):
    # Get the paths to the input ISO, hashlist, patches, and output from the config object
    iso_path = config.get("iso_path", "KHFM.iso")
    hashlist_path = config.get("hashlist_path", "resources/hashlist.txt")
    patch_paths = config.get("patch_paths", [])
    output_path = config.get("output_path", "KHFM.NEW.iso")

    # Instatiate an Iso object
    input_iso = iso_utils.Iso(iso_path)
    #print(f"ISO File Entries: {len(input_iso.entries)}")
    
    # Load the hashlist
    hashlist = {}
    with open(hashlist_path, 'r') as f:
        hashlist_lines = f.read().split("\n")
        for line in hashlist_lines:
            line_parts = line.split("\t=\t")
            if len(line_parts) == 2:
                file_hash, filename = line_parts
                file_hash = int(file_hash, 16)
                hashlist[file_hash] = filename
    
    # Calculate the hash for KINGDOM.IMG and KINGDOM.IDX
    kingdom_img_hash = idx_utils.GetHash("kingdom.img")
    kingdom_idx_hash = idx_utils.GetHash("kingdom.idx")
    system_cnf_hash = idx_utils.GetHash("system.cnf")
    
    idx = None
    start_block_offset = 0
    # Iterate over the ISO file entries
    for entry in input_iso.entries:
        # Verify that the file entry is for a normal file and not a directory
        if entry.flags & iso_utils.IS_DIR_FLAG == 0:
            filename = entry.filename[:-2]
            # Check if this is the KINGDOM.IDX entry
            if filename == "KINGDOM.IDX":
                # Instatiate the IDX object from the KINGDOM.IDX data in the ISO
                input_iso.seek(entry.start_block * input_iso.block_size)
                idx_content = input_iso.read(entry.data_size)
                idx = idx_utils.Idx(idx_content)
                # Verify the hash for KINGDOM.IDX exists in the idx entries
                if kingdom_idx_hash in idx.entries:
                    idx_entry = idx.entries[kingdom_idx_hash]
                    start_block_offset = entry.start_block - idx_entry.start_block
                else:
                    raise Exception("ERROR: Unable to find IDX Entry for kingdom.idx")
                # Check if we need to update the IDX object
                if start_block_offset != 0:
                    # Instantiate the IDX object again, this time accounting for the start block offset
                    idx = idx_utils.Idx(idx_content, start_block_offset=start_block_offset)
                else:
                    print("WARNING: The start block offset for KINGDOM.IDX is 0, which is probably not correct")
    
    # Iterate over the ISO file entries to construct the visible file map
    visible_file_map = {}
    for entry in input_iso.entries:
        # Verify that the file entry is for a normal file and not a directory
        if entry.flags & iso_utils.IS_DIR_FLAG == 0:
            filename = entry.filename[:-2]
            for file_hash in idx.entries:
                idx_entry = idx.entries[file_hash]
                if idx_entry.start_block == entry.start_block and idx_entry.file_size == entry.data_size:
                    # Map the file hash to the iso entry and filename for each Iso file entry
                    visible_file_map[file_hash] = entry, filename
                    break
            else:
                raise Exception(f"ERROR: Failed to map {filename} to a file hash from kingdom.idx")
    
    # Validate that we found KINGDOM.IDX
    if idx is None:
        raise Exception("ERROR: Failed to find kingdom.idx entry in the ISO")
    
    # Iterate over the IDX entries to find the entry from KINGDOM.IMG
    for file_hash in idx.entries:
        idx_entry = idx.entries[file_hash]
        if file_hash == kingdom_img_hash:
            # Store the start offset and length of KINGDOM.IMG
            kingdom_start_offset = idx_entry.start_block * input_iso.block_size
            kingdom_length = idx_entry.file_size
            #print("KINGDOM.IMG:")
            #print(f"  Flags: {hex(idx_entry.flags)}")
            #print(f"  Start Offset: {hex(kingdom_start_offset)}")
            #print(f"  Size: {hex(kingdom_length)}")
            break
    else:
        raise Exception("ERROR: Failed to find kingdom.img entry in kingdom.idx")
    
    # Calculate the end offset for KINGDOM.IMG
    kingdom_end_offset = kingdom_start_offset + kingdom_length
    
    wrapped_idx_entries = {}
    # Iterate over the IDX entries
    for file_hash in idx.entries:
        idx_entry = idx.entries[file_hash]
        # Calculate the start offset
        start_offset = idx_entry.start_block * input_iso.block_size
        # Use the start offset to determine the parent (KINGDOM or ISO) for the entry
        if file_hash == kingdom_img_hash or start_offset < kingdom_start_offset or start_offset >= kingdom_end_offset:
            parent = "iso"
        else:
            parent = "kingdom"
        # Determine if the idx entry has a iso dir entry (i.e. it is visible)
        visible = file_hash in visible_file_map
        # Store the parent and visibility with the idx entry
        wrapped_idx_entries[file_hash] = {"entry": idx_entry, "parent": parent, "visible": visible}
    
    iso_idx_entries = []
    visible_idx_entries = []
    hidden_idx_entries = []
    # Iterate through the wrapped idx entries
    for file_hash in wrapped_idx_entries:
        wrapped_entry = wrapped_idx_entries[file_hash]
        parent = wrapped_entry["parent"]
        visible = wrapped_entry["visible"]
        # Store entries that are have the ISO as a parent (visible + hidden)
        if parent == "iso":
            iso_idx_entries.append(wrapped_entry["entry"])
            if not visible:
                hidden_idx_entries.append(wrapped_entry["entry"])
        # Store entries that are visible in the ISO
        if visible:
            visible_idx_entries.append(wrapped_entry["entry"])
    
    #print(f"\nISO IDX Entries: {len(iso_idx_entries)}")
    #print(f"VISIBLE IDX Entries: {len(visible_idx_entries)}")
    #print(f"HIDDEN IDX Entries: {len(hidden_idx_entries)}")
    
    #print("\n--------------------\n ISO IDX Entries:\n--------------------")
    for i, idx_entry in enumerate(iso_idx_entries):
        #print(f"--------------------\n ISO IDX Entry {i}:\n--------------------")
        if idx_entry.file_hash in visible_file_map:
            _, filename = visible_file_map[idx_entry.file_hash]
            visible = True
        elif idx_entry.file_hash in hashlist:
            filename = hashlist[idx_entry.file_hash]
            visible = False
        else:
            filename = f"{hex(idx_entry.file_hash)[2:]}.bin"
            visible = False
        end_block = idx_entry.start_block + idx_entry.file_size // input_iso.block_size
        if idx_entry.file_size % input_iso.block_size == 0:
            end_block -= 1
        #print(f"Filename: {filename}")
        #print(idx_entry)
        #print(f"Start Offset: {hex(idx_entry.start_block * input_iso.block_size)}")
        #print(f"End Block: {hex(end_block)}")
        #print(f"Visible: {visible}")
    
    files_to_patch = {}
    updated_entry_point = None
    deny_list = ["system.cnf", "kingdom.idx", "kingdom.img"]
    print("\n--------------------\n Loading Patches\n--------------------")
    # Iterate over the patches
    for patch_path in patch_paths:
        print(f"{patch_path}:")
        # Read from the patch file
        with open(patch_path, 'r') as patch_f:
            patch_obj = json.load(patch_f)
            # Determine which files are being patched
            patch_files = patch_obj.get("files", [])
            # Iterate over the files to patch
            for file in patch_files:
                # Get the metadata for the file to patch
                target = file.get("patch_target", None)
                file_path = file.get("file_path", None)
                compressed = file.get("compressed", False)
                parent = file.get("parent", "kingdom").lower()
                visible = file.get("visible", False)
                entry_point = file.get("entry_point", False)
                # If the target wasn't specified, infer the target from the file_path
                if target is None:
                    target = file_path.replace('\\', '/').split('/')[-1]
                print(f"  Target: {target}")
                print(f"    File: {file_path}")
                print(f"    Compressed: {compressed}")
                print(f"    Parent: {parent}")
                print(f"    Visible: {visible}")
                print(f"    Entry Point: {entry_point}")
                if target not in deny_list:
                    if target not in files_to_patch:
                        if not entry_point or updated_entry_point is None:
                            files_to_patch[target] = target, file_path, compressed, parent, visible, entry_point
                            if entry_point:
                                updated_entry_point = target
                        else:
                            print(f"    WARNING: This will be ignored, the entry point is modified by a higher priority Patch")
                    else:
                        print(f"    WARNING: This will be ignored, {target} is modified by a higher priority Patch")
                else:
                    print(f"    WARNING: This will be ignored, {target} is on the deny list")
    
    if updated_entry_point is not None:
        entry_point_hash = idx_utils.GetHash(updated_entry_point)
    else:
        entry_point_hash = None
    
    iso_dir_entries_to_remove = {}
    iso_dir_entries_to_update = {}
    iso_dir_entries_to_add = {}
    
    idx_entries_to_remove = {}
    idx_entries_to_update = {}
    idx_entries_to_add = {}
    
    for target in files_to_patch:
        file_patch = files_to_patch[target]
        _, file_path, compressed, parent, visibility, _ = file_patch
        target_hash = idx_utils.GetHash(target)
        if file_path is None:
            # This is a file we are removing
            if target_hash in wrapped_idx_entries:
                iso_dir_entries_to_remove[target_hash] = file_patch
                idx_entries_to_remove[target_hash] = file_patch
            else:
                print(f"WARNING: Unable to remove {target}, it does not exist")
        elif target_hash in wrapped_idx_entries:
            # This is a file we are modifying
            wrapped_idx_entry = wrapped_idx_entries[target_hash]
            original_visibility = wrapped_idx_entry["visible"]
            idx_entries_to_update[target_hash] = file_patch
            if visibility != original_visibility:
                if original_visibility:
                    iso_dir_entries_to_remove[target_hash] = file_patch
                else:
                    iso_dir_entries_to_add[target_hash] = file_patch
            elif visibility:
                iso_dir_entries_to_update[target_hash] = file_patch
        else:
            # This is a file we are adding
            idx_entries_to_add[target_hash] = file_patch
            if visibility:
                iso_dir_entries_to_add[target_hash] = file_patch
    
    #print("\n--------------------\n Entries Info:\n--------------------")
    #print("ISO Dir Entries to Remove:")
    #print(iso_dir_entries_to_remove)
    #print("ISO Dir Entries to Update:")
    #print(iso_dir_entries_to_update)
    #print("ISO Dir Entries to Add:")
    #print(iso_dir_entries_to_add)
    #print("IDX Entries to Remove:")
    #print(idx_entries_to_remove)
    #print("IDX Entries to Update:")
    #print(idx_entries_to_update)
    #print("IDX Entries to Add:")
    #print(idx_entries_to_add)
    
    # Determine IDX Entries for new ISO
    new_idx_entries = {}
    original_hashes = [file_hash for file_hash in idx.entries]
    new_hashes = [file_hash for file_hash in idx_entries_to_add]
    visible_filtered_hashes = []
    kingdom_filtered_hashes = []
    hidden_filtered_hashes = []
    # Sort the original idx entries by their start block
    idx_entries = sorted([idx.entries[file_hash] for file_hash in original_hashes], key=lambda item:item.start_block)
    # Iterate over the sorted idx entries
    for idx_entry in idx_entries:
        file_hash = idx_entry.file_hash
        if file_hash in idx_entries_to_remove:
            # Move on to the next IDX Entry without adding this one
            continue
        if file_hash in idx_entries_to_update:
            file_patch = idx_entries_to_update[file_hash]
            _, file_path, compressed, _, _, _ = file_patch
            new_idx_entry = idx_utils.create_idx_entry(file_hash, file_path, int(compressed))
            _, _, _, parent, visibile, _ = idx_entries_to_update[file_hash]
        else:
            wrapped_idx_entry = wrapped_idx_entries[file_hash]
            unwrapped_entry = wrapped_idx_entry["entry"]
            new_idx_entry = idx_utils.IdxEntry(
                unwrapped_entry.file_hash,
                unwrapped_entry.flags,
                None,
                unwrapped_entry.file_size
            )
            #new_idx_entry = unwrapped_entry
            parent = wrapped_idx_entry["parent"]
            visible = wrapped_idx_entry["visible"]
        if parent == "kingdom":
            kingdom_filtered_hashes.append(file_hash)
        elif visible:
            visible_filtered_hashes.append(file_hash)
        else:
            hidden_filtered_hashes.append(file_hash)
        new_idx_entries[file_hash] = new_idx_entry
    # Iterate over the new files that are being added
    for file_hash in new_hashes:
        file_patch = idx_entries_to_add[file_hash]
        _, file_path, compressed, parent, visible, entry_point = file_patch
        new_idx_entry = idx_utils.create_idx_entry(file_hash, file_path, int(compressed))
        new_idx_entries[file_hash] = new_idx_entry
        if entry_point:
            visible_filtered_hashes = visible_filtered_hashes[:1] + [file_hash] + visible_filtered_hashes[1:]
        elif parent == "kingdom":
            kingdom_filtered_hashes.append(file_hash)
        elif visible:
            visible_filtered_hashes.append(file_hash)
        else:
            hidden_filtered_hashes.append(file_hash)
    # Combine the visible, kingdom, and hidden hash lists
    filtered_hashes = visible_filtered_hashes + kingdom_filtered_hashes + hidden_filtered_hashes
    # Sort the hashes for when we construct the new kingdom.idx file
    sorted_filtered_hashes = sorted(filtered_hashes)
    
    # Sort IDX Entries by the order we want them written to the ISO 
    idx_entries_list = [new_idx_entries[file_hash] for file_hash in filtered_hashes]
    
    # Determine the size of the new kingdom.idx and kingdom.img
    new_kingdom_idx_size = len(idx_entries_list) * 16
    new_kingdom_img_size = 0
    for file_hash in kingdom_filtered_hashes:
        idx_entry = new_idx_entries[file_hash]
        new_kingdom_img_size += idx_entry.file_size
        if new_kingdom_img_size % input_iso.block_size != 0:
            new_kingdom_img_size += input_iso.block_size - (new_kingdom_img_size % input_iso.block_size)
    
    # Update the file sizes for the new kingdom.idx and kingdom.img
    new_idx_entries[kingdom_idx_hash].file_size = new_kingdom_idx_size
    new_idx_entries[kingdom_img_hash].file_size = new_kingdom_img_size
    
    # Add the kingdom.idx and kingdom.img patches
    kingdom_idx_patch = "kingdom.idx", None, False, "iso", True, False
    kingdom_img_patch = "kingdom.img", None, False, "iso", False, False
    iso_dir_entries_to_update[kingdom_idx_hash] = kingdom_idx_patch
    idx_entries_to_update[kingdom_idx_hash] = kingdom_idx_patch
    idx_entries_to_update[kingdom_img_hash] = kingdom_img_patch
    
    # Check if we are updating the entry point
    if updated_entry_point is not None:
        # TODO: Instead of hard coding these values, just update the filename part of the original system.cnf
        new_system_cnf = f"BOOT2 = cdrom0:\\{updated_entry_point[:12].upper()};1\nVER = 1.00\nVMODE = NTSC\nHDDUNITPOWER = NICHDD\n"
        # Update the file size for system.cnf
        new_idx_entries[system_cnf_hash].file_size = len(new_system_cnf)
        # Add the system.cnf patch
        system_cnf_patch = "system.cnf", None, False, "iso", True, False
        iso_dir_entries_to_update[system_cnf_hash] = system_cnf_patch
        idx_entries_to_update[system_cnf_hash] = system_cnf_patch
    
    # Update each IDX Entry's start block
    idx_entry_start_block = 0
    kingdom_entries_block_offset = 0
    for idx_entry in idx_entries_list:
        if idx_entry.file_hash in kingdom_filtered_hashes:
            idx_entry.start_block = idx_entry_start_block + kingdom_entries_block_offset
            file_size_blocks = idx_entry.file_size // input_iso.block_size
            if idx_entry.file_size % input_iso.block_size != 0:
                file_size_blocks += 1
            kingdom_entries_block_offset += file_size_blocks
        else:
            idx_entry.start_block = idx_entry_start_block
            file_size_blocks = idx_entry.file_size // input_iso.block_size
            if idx_entry.file_size % input_iso.block_size != 0:
                file_size_blocks += 1
            idx_entry_start_block += file_size_blocks
    
    #for i, file_hash in enumerate(idx.entries):
    #    original_entry = idx.entries[file_hash]
    #    new_entry = new_idx_entries[file_hash]
    #    if original_entry.start_block - idx.start_block_offset != new_entry.start_block:
    #        print(hex(file_hash), hex(original_entry.start_block), hex(new_entry.start_block))
    
    # Determine ISO Dir Entries for new ISO
    new_iso_dir_entries = []
    # Iterate over the original ISO Dir Entries
    for iso_dir_entry in input_iso.entries:
        if iso_dir_entry.flags & iso_utils.IS_DIR_FLAG == 0:
            # This is a regular file
            # Trim the ;1 from the ISO Dir Entry's filename
            entry_filename = iso_dir_entry.filename[:-2]
            # Determine the file hash for this entry
            for file_hash in visible_file_map:
                _, filename = visible_file_map[file_hash]
                if entry_filename == filename:
                    break
            else:
                raise Exception("ERROR: Failure to locate ISO Dir Entry file hash")
            # Check if we are removing this file
            if file_hash in iso_dir_entries_to_remove:
                # Move on to the next ISO Dir Entry without adding this one
                continue
            # Get the idx entry for this file
            idx_entry = new_idx_entries[file_hash]
            # Create the new ISO Dir Entry
            new_iso_dir_entry = create_iso_dir_entry(
                idx_entry.start_block,
                idx_entry.file_size,
                iso_dir_entry.filename
            )
        else:
            # This is an entry for a directory, just copy it
            new_iso_dir_entry = iso_dir_entry
        # Add the new ISO Dir Entry
        new_iso_dir_entries.append(new_iso_dir_entry)
    # Iterate over the new files we are adding
    for file_hash in iso_dir_entries_to_add:
        file_patch = iso_dir_entries_to_add[file_hash]
        filename, _, _, _, _, entry_point = file_patch
        # Get the IDX Entry for the file
        idx_entry = new_idx_entries[file_hash]
        # Make the filename uppercase and append ";1"
        filename = f"{filename[:12].upper()};1"
        # Create the ISO Dir Entry
        new_iso_dir_entry = create_iso_dir_entry(
            idx_entry.start_block,
            idx_entry.file_size,
            filename
        )
        # Add the new ISO Dir Entry
        if entry_point:
            new_iso_dir_entries = new_iso_dir_entries[:3] + [new_iso_dir_entry] + new_iso_dir_entries[3:]
        else:
            new_iso_dir_entries.append(new_iso_dir_entry)
    
    # TODO: Calculate this instead of assuming it is 1
    primary_dir_size_blocks = 1
    initial_file_start_block = input_iso.primary_dir_block + primary_dir_size_blocks
    # Add the initial file start block to each of the ISO Dir Entries (except dirs)
    for iso_dir_entry in new_iso_dir_entries:
        if iso_dir_entry.flags & iso_utils.IS_DIR_FLAG == 0:
            iso_dir_entry.start_block += initial_file_start_block
    
    # Construct new ISO header by copying from original ISO
    output_iso = iso_utils.Iso(output_path, mode="w")
    input_iso.seek(0)
    for i in range(input_iso.primary_dir_block):
        output_iso.write(input_iso.read(input_iso.block_size))
    
    iso_dirs_start = output_iso.tell()
    # Write each ISO Dir Entry
    for iso_dir_entry in new_iso_dir_entries:
        output_iso.write(iso_dir_entry.pack())
    # Determine the length of the ISO Dir Entries
    iso_dirs_end = output_iso.tell()
    iso_dirs_len = iso_dirs_end - iso_dirs_start
    # Write padding if necessary to align with the start of a block
    if iso_dirs_len % input_iso.block_size != 0:
        padding = b"\0" * (input_iso.block_size - (iso_dirs_len % input_iso.block_size))
        output_iso.write(padding)
    
    # TODO: Investigate these blocks, they might be related to a full boot in PCSX2
    # Copy or Create the blocks between the ISO Dir Entries and the visible files
    #padding_block = b"\0" * input_iso.block_size
    #for i in range(len(new_iso_dir_entries) + 2):
    #    output_iso.write(padding_block)
    
    # Write visible files
    for file_hash in visible_filtered_hashes:
        if file_hash in idx_entries_to_update or file_hash in idx_entries_to_add:
            if file_hash in idx_entries_to_update:
                file_patch = idx_entries_to_update[file_hash]
            else:
                file_patch = idx_entries_to_add[file_hash]
            _, file_path, compressed, parent, _, _ = file_patch
            if parent == "iso":
                if file_hash != kingdom_idx_hash and file_hash != system_cnf_hash:
                    with open(file_path, 'rb') as f:
                        if compressed:
                            raise Exception("ERROR: File Compression is not yet supported")
                        else:
                            block_data = f.read(input_iso.block_size)
                            while(len(block_data) > 0):
                                output_iso.write(block_data)
                                block_data = f.read(input_iso.block_size)
                elif file_hash == kingdom_idx_hash:
                    for file_hash in sorted_filtered_hashes:
                        idx_entry = new_idx_entries[file_hash]
                        output_iso.write(idx_entry.pack())
                else:
                    output_iso.write(new_system_cnf.encode("utf-8"))
        else:
            original_iso_dir_entry, _ = visible_file_map[file_hash]
            input_iso.seek(original_iso_dir_entry.start_block * input_iso.block_size)
            block_count = original_iso_dir_entry.data_size // input_iso.block_size
            if original_iso_dir_entry.data_size % input_iso.block_size != 0:
                block_count += 1
            for i in range(block_count):
                output_iso.write(input_iso.read(input_iso.block_size))
            
        iso_len = output_iso.tell()
        if iso_len % input_iso.block_size != 0:
            padding = b"\0" * (input_iso.block_size - (iso_len % input_iso.block_size))
            output_iso.write(padding)
    
    # Write hidden files to the new ISO
    for file_hash in hidden_filtered_hashes:
        if file_hash in idx_entries_to_update or file_hash in idx_entries_to_add:
            if file_hash in idx_entries_to_update:
                file_patch = idx_entries_to_update[file_hash]
            else:
                file_patch = idx_entries_to_add[file_hash]
            _, file_path, compressed, parent, _, _ = file_patch
            if parent == "iso":
                if file_hash != kingdom_img_hash:
                    with open(file_path, 'rb') as f:
                        if compressed:
                            raise Exception("ERROR: File Compression is not yet supported")
                        else:
                            block_data = f.read(input_iso.block_size)
                            while(len(block_data) > 0):
                                output_iso.write(block_data)
                                block_data = f.read(input_iso.block_size)
                else:
                    for file_hash in kingdom_filtered_hashes:
                        if file_hash in idx_entries_to_update or file_hash in idx_entries_to_add:
                            if file_hash in idx_entries_to_update:
                                file_patch = idx_entries_to_update[file_hash]
                            else:
                                file_patch = idx_entries_to_add[file_hash]
                            _, file_path, compressed, parent, _, _ = file_patch
                            if parent == "kingdom":
                                with open(file_path, 'rb') as f:
                                    if compressed:
                                        raise Exception("ERROR: File Compression is not yet supported")
                                    else:
                                        block_data = f.read(input_iso.block_size)
                                        while(len(block_data) > 0):
                                            output_iso.write(block_data)
                                            block_data = f.read(input_iso.block_size)
                        else:
                            idx_entry = idx.entries[file_hash]
                            input_iso.seek(idx_entry.start_block * input_iso.block_size)
                            block_count = idx_entry.file_size // input_iso.block_size
                            if idx_entry.file_size % input_iso.block_size != 0:
                                block_count += 1
                            for i in range(block_count):
                                output_iso.write(input_iso.read(input_iso.block_size))
                        
                        iso_len = output_iso.tell()
                        if iso_len % input_iso.block_size != 0:
                            padding = b"\0" * (input_iso.block_size - (iso_len % input_iso.block_size))
                            output_iso.write(padding)
        else:
            idx_entry = idx.entries[file_hash]
            input_iso.seek(idx_entry.start_block * input_iso.block_size)
            block_count = idx_entry.file_size // input_iso.block_size
            if idx_entry.file_size % input_iso.block_size != 0:
                block_count += 1
            for i in range(block_count):
                output_iso.write(input_iso.read(input_iso.block_size))
        
        iso_len = output_iso.tell()
        if iso_len % input_iso.block_size != 0:
            padding = b"\0" * (input_iso.block_size - (iso_len % input_iso.block_size))
            output_iso.write(padding)
    
    # Update the size of the iso in the volume descriptor
    full_iso_size = output_iso.tell()
    full_iso_size_blocks = full_iso_size // input_iso.block_size
    if full_iso_size % input_iso.block_size != 0:
        full_iso_size_blocks += 1
    output_iso.seek(0x8050)
    packed_iso_size = struct.pack("<I", full_iso_size_blocks)
    output_iso.write(packed_iso_size + packed_iso_size[::-1])
    
    # Update the size of the primary directory in the . and .. directories
    output_iso.seek(input_iso.primary_dir_block * input_iso.block_size + 10)
    packed_iso_dirs_len = struct.pack("<I", iso_dirs_len)
    output_iso.write(packed_iso_dirs_len + packed_iso_dirs_len[::-1])
    output_iso.seek(input_iso.primary_dir_block * input_iso.block_size + 58)
    output_iso.write(packed_iso_dirs_len + packed_iso_dirs_len[::-1])
    
    # Clean Up
    input_iso.close()

def create_iso_dir_entry(start_block, data_size, filename):
    # Construct a new ISO Dir Entry
    return iso_utils.IsoDirEntry(
        start_block=start_block,
        data_size=data_size,
        creation_time=[0, 0, 0, 0, 0, 0, 0],
        flags=0,
        unk_value=1,
        filename=filename
    )

def main():
    # VERSION
    version = "1.1"

    # Valid run modes
    run_modes = ["decrypt", "patch", "map_iso"]
    
    # Set up argument parsing to accept a config json file as a positional argument
    parser = argparse.ArgumentParser()
    parser.add_argument("config_path", help="Path to the config to use")
    
    # Parse the args
    args = parser.parse_args()
    
    # Get the config path from the args
    config_path = args.config_path
    
    print("------------------------")
    print(f" KH1FM Re:Toolkit v {version}")
    print(" - Some1fromthedark")
    print("------------------------")
    
    # Load the contents of the config JSON object
    with open(config_path, 'r') as f:
        config_obj = json.load(f)
    
    # Get the mode from the config object
    mode = config_obj.get("mode", "decrypt")
    
    print(f"Running in {mode} mode")
    
    # Verify a supported mode was specified
    if mode in run_modes:
        # Perform the appropriate actions based on the specified mode
        if mode == "decrypt":
            decrypt(config_obj)
        elif mode == "map_iso":
            map_iso(config_obj)
        elif mode == "patch":
            patch(config_obj)
        else:
            raise Exception(f"ERROR: Support for {mode} was not implemented correctly!!!")
    else:
        raise Exception("ERROR: Unsupported Mode!")

if __name__ == "__main__":
    main()