# code block extraction for project 2
# csc6580 reverse engineering
# perlman group
# dennis jump
# oct 30, 2026

import os
import sys
from elftools.elf.elffile import ELFFile, ELFError
from elftools.elf.sections import SymbolTableSection
from elftools.elf.sections import Symbol
from capstone import *

from elf_utilities import *
from analyze_elf import *
from start_address import *

def code_block_extraction(elf_contents:ELFFile, instruction_list:list[int,str,str],start_address:int)->list[str,str,str]:
    # just so we know that it works, here is the find the LEA-CALL-HLT address finder
    updated_instruction_list:list[str,str,str] = []
    alt_start = find_alternative_c_start(instruction_list,0,0)
    if alt_start == start_address: 
        print(f"alt start {alt_start:x} agrees with start address")
    else:
        print(f"alt start {alt_start:x} does not agree with start address {start_address:x}")
    # go through the instruction list to find code breaks
    # I am using known addresses with labels
    for i in range(len(instruction_list)):
        [address, mnemonic, operands] = instruction_list[i]
        # dj check that address might be a symbol - add blank line and print the label
        label:str = insert_address_label(elf_contents,address)
        if label != "" : updated_instruction_list.append([label,"",""])

        # put this into a function later
        # if the mnemonic is in the set of jmp commands or call
        # resolve the address to a label if possible       
        if mnemonic in jmp_cmd:
            if "[" in operands:
                if "[rip" in operands:
                    [rip_address, _, _] = instruction_list[i+1]
                    operands = resolve_rip_address(elf_contents,operands,rip_address)
                    None
                None
            elif "0x" in operands.lower():
                operands = resolve_immediate(elf_contents,operands)
                None
            else:
                print(f"unhandled operand for jmp set : {operands}")
                None
            None
        updated_instruction_list.append([f"0x{address:x}",mnemonic,operands])
        None
    return updated_instruction_list
# for the alternate start and maybe address resolution
# rip apart the rip reference and get the immediate offset
# there has to be a better way to get the immediate offset out of the operand
# this works but it looks brute force
def rip_offset(operands:str) -> int:
    if "[rip" not in operands: return 0
    # check the operation -- could be subtracting the offset
    add = "+" in operands 
    s_idx = operands.find("[rip")
    e_idx = operands.find("]")
    oper = operands[s_idx:e_idx]
    first_digit_idx = next((i for i, char in enumerate(oper) if char.isdigit()), -1)
    offset = oper[first_digit_idx:e_idx]
    print(f"offset = {offset}")
    i_offset = int(offset,16)
    if not add: i_offset = -i_offset 
    return i_offset

# find the magic lea-call-hlt sequence and extract the alternative start address
def find_alternative_c_start(instruction_list:list[int,str,str],section_start:int,section_size:int):
    alt_start:int = 0
    # go through the instruction list looking for the lea-call-hlt sequence
    for i in range(len(instruction_list)):
        [_, lea_mnemonic, lea_operands] = instruction_list[i]
        if lea_mnemonic.lower() == "lea" :
            # address of next instruction is the RIP for the LEA instruction base address
            [rip_address, call_mnemonic, _] = instruction_list[i+1]
            if call_mnemonic.lower() == "call":
                [_, hlt_mnemonic, _] = instruction_list[i+2]
                if hlt_mnemonic.lower() == "hlt":
                    print("found the end of the start up code")
                    # add the rip address and the immediate offset
                    alt_start = rip_address + rip_offset(lea_operands)
                    return alt_start
                None   
            None
        None
    return 0

# all of the code below will move to utilities when checked out

# resolve variable names when in [rip+0xnnn] form
def resolve_rip_address(elf_contents:ELFFile, operand:str,rip_address:int) -> str:
    # let's not for now
    return operand

# replaces the 0xnnnn immediate value in jmp commands with label of the address
def resolve_immediate(elf_contents:ELFFile, operand:str) -> str:
    target = int(operand,16)
    label = is_address_in_symbol_table(elf_contents,".symtab",target)
    if label == "": label = is_address_in_symbol_table(elf_contents,".dynsym",target)
    if label != "": operand = label
    return operand
# insert a blank line of separation and the label associated with a given address
def insert_address_label(elf_contents:ELFFile,address)->str:
    label = is_address_in_symbol_table(elf_contents,".symtab",address)
    if label == "": label = is_address_in_symbol_table(elf_contents,".dynsym",address)
    return label
    
# check to see if the address can be found as a value in a symbol table
# if found, return the string associated with the symbol    
def is_address_in_symbol_table(elf_contents:ELFFile, symbol_table:str, the_address:int) -> str:
#   print(f"entering is there a symbol for this address {the_address:x} in symbol table {symbol_table}")
    # dj get a reference to the symbol table
    sym_section = elf_contents.get_section_by_name(symbol_table)
    if sym_section:
        # dj iterate through the symbols
        for sym in sym_section.iter_symbols():
#            print(f"Name: {sym.name}, Value: {hex(sym['st_value'])}, Size:"f" {sym['st_size']}" )
            # dj if the symbol table name matches the target, then it is here
            if the_address == int(sym['st_value']): return sym.name
            None
        None
        function_name = get_plt_call_name(elf_contents,the_address)
        if function_name: return function_name + " wrt ..plt" 
    return "" # not found
# easier to get into the symbol table by index than name
# the index will be available when extracted from the .plt table PUSH command
def get_symbol_at_index(elf_contents:ELFFile, symbol_table:str, index:int) -> str:
#   print(f"entering is there a symbol for this address {the_address:x} in symbol table {symbol_table}")
    # dj get a reference to the symbol table
    sym_section = elf_contents.get_section_by_name(symbol_table)
    if sym_section:
        # dj iterate through the symbols
        sym = sym_section.get_symbol(index)
        if not sym: return ""
        return sym.name
    return "" # not found


plt_map = {}
# using the plt table to find see if an address falls into the .plt table range
# if it is there, get the name associated with the address
def get_plt_call_name(elf_contents:ELFFile, the_address:int) -> str:
    plt = elf_contents.get_section_by_name(".plt")
    if not plt: return ""
    plt_addr:int = plt['sh_addr'] 
    plt_size:int = plt['sh_size']
    # dj the target is in the plt table
    # this might not be needed as the map only gives back a value for direct hits
    # and the conditional on that address is there
    if not ((the_address >= plt_addr) and (the_address < (plt_addr + plt_size))): return ""
    if the_address in plt_map:
        return plt_map[the_address]
    return ""
#this builds the .plt map
# there is going to be a lot of calculating for this value during processing
# so do it once and get it out of the way
# put a .plt address into the map and get the associated function name
def build_plt_map(elf_contents:ELFFile):
    # check that the tables are there
    plt = elf_contents.get_section_by_name(".plt")
    if not plt: return 
    rela_plt = elf_contents.get_section_by_name(".rela.plt")
    if not rela_plt: return
    # get the stats of the tables
    plt_addr:int = plt['sh_addr'] 
    plt_size:int = plt['sh_size']
    rela_plt_addr:int = rela_plt['sh_addr'] 
    rela_plt_size:int = rela_plt['sh_size']
    rela_plt_count:int = elf_contents.structs.Elf_Rela.sizeof()
    # get the tables
    # .plt entries are 16 bytes long
    # the first entry is the relocation pointer and is skipped
    plt_data = plt.data()
    rela_plt_data = rela_plt.data()
    # go through the .plt table, 16 bytes at a time
    for j in range(16,plt_size,16):
        # here is the address that will be in the .text code or wherever binary code is sold
        function_address = plt_addr + j
        # there is a PUSH command in those 16 bytes.
        # not always at the same offset - that would be too easy
        # step through to find the 0x68 the binary code for PUSH
        for k in range(0,16):
            # find the 0x68 PUSH instruction
            if plt_data[j + k] == 0x68: # PUSH instruction
#                print(f"Found PUSH instruction at offset: 0x{j + k:x}")
                # the next 4 bytes are the offset into the .rela.plt section
                four_bytes = plt_data[(j + k + 1):(j + k + 1)+4]
#                print(f"four bytes {four_bytes[0]:x},{four_bytes[1]:x},{four_bytes[2]:x},{four_bytes[3]:x}")
                rela_offset = int.from_bytes(four_bytes,byteorder='little')
                k += 4 # skip the next 4 bytes since they are part of the PUSH instruction (danger if 0x68 appears in the offset)
#                print(f"Relocation offset: {rela_offset}")
                # Use the rela_offset to find the corresponding Elf64_Rela entry
                # Get to the right entry -- add 8 (sizeof uint64_t) to get to the rinfo field
                # Get that string of bytes and you have r_info
                rela_offset *= elf_contents.structs.Elf_Rela.sizeof()
                rela_offset += 8
                rela_plt_bytes = rela_plt_data[rela_offset:rela_offset+8]
#                print(rela_plt_bytes.hex())
                r_info = int.from_bytes(rela_plt_bytes,byteorder='little')
#                print(F"r_info = {r_info:x}")
                # the r_info field contains the symbol index and type of relocation
                # get the symbol index
                sym_index = (r_info >> 32) & 0x00000000FFFFFFFF
#                print(f"symbol index = {sym_index}")
                # use the r_info in the dynsym section to find the symbol name in the .dynstr section
#                print(f"call get symbol at index {sym_index}")
                function_name = get_symbol_at_index(elf_contents,".dynsym",sym_index)
                if not function_name : continue
#                print(f"plt map {function_name} at 0x{function_address:x}")
                plt_map[function_address] = function_name
                None
            None
        None
    None