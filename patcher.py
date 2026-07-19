#!/usr/bin/env python3
import os
import struct

PATCHES = {
    0x1400eb600: b"\xB8\x07\x00\x00\x00\xC3",  
    0x1400faff0: b"\xB8\x01\x00\x00\x00\xC3",  
}

def find_target_file():
    current_script = os.path.basename(__file__)
    files = [f for f in os.listdir('.') if os.path.isfile(f) and f != current_script and not f.endswith('.py')]
    return files[0] if files else None

def get_pe_info(data):
    pe_off = struct.unpack('<I', data[0x3c:0x40])[0]
    magic = struct.unpack('<H', data[pe_off+24:pe_off+26])[0]
    image_base = struct.unpack('<Q', data[pe_off+48:pe_off+56])[0] if magic == 0x20b else struct.unpack('<I', data[pe_off+52:pe_off+56])[0]
    
    num_sects = struct.unpack('<H', data[pe_off+6:pe_off+8])[0]
    opt_size = struct.unpack('<H', data[pe_off+20:pe_off+22])[0]
    sec_off = pe_off + 24 + opt_size
    
    sections = []
    for i in range(num_sects):
        off = sec_off + i * 40
        v_size = struct.unpack('<I', data[off+8:off+12])[0]
        v_addr = struct.unpack('<I', data[off+12:off+16])[0]
        r_size = struct.unpack('<I', data[off+16:off+20])[0]
        r_addr = struct.unpack('<I', data[off+20:off+24])[0]
        sections.append({'v_addr': v_addr, 'v_size': v_size, 'r_addr': r_addr})
    return image_base, sections

def rva_to_offset(va, image_base, sections):
    rva = va - image_base
    for sec in sections:
        if sec['v_addr'] <= rva < sec['v_addr'] + sec['v_size']:
            return rva - sec['v_addr'] + sec['r_addr']
    return None

def main():
    target = find_target_file()
    if not target:
        print("[-] No target binary found in directory.")
        return
        
    print(f"Patching: {target}")
    with open(target, 'rb') as f:
        data = bytearray(f.read())
        
    image_base, sections = get_pe_info(data)
    
    for va, patch in PATCHES.items():
        offset = rva_to_offset(va, image_base, sections)
        if offset:
            data[offset:offset+len(patch)] = patch
            print(f"[+] Patched VA 0x{va:X} at Offset 0x{offset:X}")
        else:
            print(f"[-] Failed to map VA 0x{va:X}")

    with open(f"patched_{target}", 'wb') as f:
        f.write(data)
    print(f"[+] Created: patched_{target}")

if __name__ == "__main__":
    main()