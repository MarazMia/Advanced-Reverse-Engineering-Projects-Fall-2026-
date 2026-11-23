# elf utilities for project 3
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

jmp_cmd = {"jmp","ja","jae","jb","jbe","jc","jcxz","je",
           	"jecxz","jg","jge","jl","jle","jna","jnae","jnb",
            "jnbe","jnc","jne",	"jng","jnge","jnl","jnle","jno",
            "jnp","jns","jnz","jo","jp","jpe","jpo","jrcxz","js","jz","loop"} # "call",

#local error msg function
def elf_error(msg) -> None:
    """Print an error message."""
    print(f"ERROR: {msg}")
    None

def dump_instruction_list(code:list[int,str,str]):
    for [address,opcode,operands] in code:
        print(f"{address:x}  {opcode}  \t{operands}")            
        None
    None
def dump_updated_instruction_list(code:list[int,str,str,int,bool]):
    for [address,opcode,operands,rip_address,is_jmp] in code:
        jump_flag = "JMP" if is_jmp else ""
        print(f"0x{address:x}  {opcode}  \t{operands} \t0x{rip_address:x} {jump_flag}")            
        None
    None

def find_text_section(elf_contents:ELFFile) -> Section:
    # Get the .text section by name
    text_section = elf_contents.get_section_by_name('.text')
    if not text_section :
        elf_error("There is no .text section. Nice move, Stacy")
        return None
        None
    return text_section

def find_section(elf_contents:ELFFile, section_name:str) -> Section:
    # Get the .text section by name
    the_section = elf_contents.get_section_by_name(section_name)
    if not the_section :
        elf_error(f"There is no {section_name} section. Nice move, Stacy")
        return None
        None
    return the_section

# dj get the entry point from the Ehdr
def get_entry_point(elf_contents:ELFFile) -> int:
    ehdr = elf_contents.header
    return ehdr.e_entry # ['e_entry']

# dj find the section that contains the given address
# dj iterate through the sections, comparing the start and end of the section
# dj it's a winner if address at or between the address range
# dj return the section name and starting address
def find_section_with_this_address(elf_content:ELFFile, addr:int) -> list[str,int]:
    for section in elf_content.iter_sections():
        # dj get the starting address
        section_addr = section['sh_addr']
        # dj get the section size
        section_size = section['sh_size']
        # dj if the address within the borders of the section
        if (section_addr <= addr) and ((section_addr + section_size) > addr ):
#            print(hex(section['sh_addr']), section.name)
            return [section.name,section_addr]
    return ["",0]

# dj check if a symbol is within a symbol table
def is_symbol_in_table(elf_contents:ELFFile, symbol_table:str, symbol_name:str) -> bool:
#    print(f"entering find {symbol_name} in symbol table {symbol_table}")
    # dj get a reference to the symbol table
    sym_section = elf_contents.get_section_by_name(symbol_table)
    if sym_section:
        # dj iterate through the symbols
        for sym in sym_section.iter_symbols():
#            print(f"Name: {sym.name}, Value: {hex(sym['st_value'])}, Size:"f" {sym['st_size']}" )
            # dj if the symbol table name matches the target, then it is here
            if symbol_name == sym.name: return True
            None
#        print(f"symbol {symbol_name} in symbol section {symbol_table} not found")
        None
    else:
#        print(f"symbol section {symbol_table} not found")
        None
    # dj otherwise, it isn't
    return False

# dj now that we know that the symbol is in table (or presume it)
# follow the example of the search, except return the value when it is found
def get_symbol_value(elf_contents:ELFFile ,  symbol_table:str, symbol_name:str) -> int:
#    print(f"entering value of {symbol_name} in symbol table {symbol_table}")
    sym_section = elf_contents.get_section_by_name(symbol_table)
    if sym_section:
        for sym in sym_section.iter_symbols():
            if symbol_name == sym.name:
#                print(f"found {symbol_name} in {symbol_table} value {hex(sym['st_value'])}")
                return int(sym['st_value'])
            None
        None
    None
    return 0

# all of the code below will move to utilities when checked out
# this function receives a statement and the rip address
# it deconstructs the operands and attempts to resolve any [RIP+] operands

def resolve_operand_addresses(address:int, mnemonic:str, operands:str,rip_address:int, elf_contents:ELFFile) ->list[int,str,str]:
    # statements of this sort are either immediate or [] 
    # so handle the jmp family (we thank you) in a slightly different manner
    if mnemonic in jmp_cmd:
        if "[" in operands:
            if "[rip" in operands:
                operands = resolve_rip_address(elf_contents,operands,rip_address)
                return [address,mnemonic,operands]
        elif "0x" in operands.lower():
#            print(f"checking for immediate jump operand using {operands} ")
            operands = resolve_immediate(elf_contents,operands)
            return [address,mnemonic,operands]
        else:
#            print(f"checking for jump operand did not parse {operands} ")
            return [address,mnemonic,operands]
        None
    # some instructions have no operands, no reason to force it upon them -- skip them
    if not operands: return [address,mnemonic,operands]
    # check to see if there are 2 operands -- needs to be expanded for some specal 3 and 4 operand instructions
    two_parameters = "," in operands
    # of course, there might be 3 operands in some floating point instructions and imul and idiv
    if two_parameters:
        comma_location = operands.find(',')
        # isolate the operands 
        operand_1 = operands[0:comma_location].strip()
        operand_2 = operands[comma_location+1:].strip()
        # check to see if they can be resolved
        operand_1 = resolve_operand(operand_1,rip_address,elf_contents)
        operand_2 = resolve_operand(operand_2,rip_address,elf_contents)
        # put them back together again
        return [address, mnemonic,operand_1 + ", " + operand_2]
    # just one operand, just resolve it and return it
    return [address, mnemonic,resolve_operand(operands,rip_address,elf_contents)]

# resolve a single operand
# right now, the only thing is to check for [rip for that conversion and symbol inserted
def resolve_operand(operand:str, rip_address:int, elf_contents:ELFFile) -> str:
    if "[rip" in operand:
        offset = rip_offset(operand)
        operand_address = rip_address + offset
        label = is_address_in_symbol_table(elf_contents,".symtab",operand_address)
        if not label: label = is_address_in_symbol_table(elf_contents,".dynsym",operand_address)
        if not label: label = f"0x{operand_address:x}" 
        return "[rel " + label + "]"
    return operand

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
#    print(f"offset = {offset}")
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
#                    print("found the end of the start up code")
                    # add the rip address and the immediate offset
                    alt_start = rip_address + rip_offset(lea_operands)
                    return alt_start
                None   
            None
        None
    return 0

    
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
            
