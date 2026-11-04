# elf utilities for project 2
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

jmp_cmd = {"jmp","call","ja","jae","jb","jbe","jc","jcxz","je",
           	"jecxz","jg","jge","jl","jle","jna","jnae","jnb",
            "jnbe","jnc","jne",	"jng","jnge","jnl","jnle","jno",
            "jnp","jns","jnz","jo","jp","jpe","jpo","jrcxz","js","jz"}

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
def dump_updated_instruction_list(code:list[str,str,str]):
    for [address,opcode,operands] in code:
        print(f"{address}  {opcode}  \t{operands}")            
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
            print(hex(section['sh_addr']), section.name)
            return [section.name,section_addr]
    return ["",0]

# dj check if a symbol is within a symbol table
def is_symbol_in_table(elf_contents:ELFFile, symbol_table:str, symbol_name:str) -> bool:
    print(f"entering find {symbol_name} in symbol table {symbol_table}")
    # dj get a reference to the symbol table
    sym_section = elf_contents.get_section_by_name(symbol_table)
    if sym_section:
        # dj iterate through the symbols
        for sym in sym_section.iter_symbols():
#            print(f"Name: {sym.name}, Value: {hex(sym['st_value'])}, Size:"f" {sym['st_size']}" )
            # dj if the symbol table name matches the target, then it is here
            if symbol_name == sym.name: return True
            None
        print(f"symbol {symbol_name} in symbol section {symbol_table} not found")
        None
    else:
        print(f"symbol section {symbol_table} not found")
        None
    # dj otherwise, it isn't
    return False

# dj now that we know that the symbol is in table (or presume it)
# follow the example of the search, except return the value when it is found
def get_symbol_value(elf_contents:ELFFile ,  symbol_table:str, symbol_name:str) -> int:
    print(f"entering value of {symbol_name} in symbol table {symbol_table}")
    sym_section = elf_contents.get_section_by_name(symbol_table)
    if sym_section:
        for sym in sym_section.iter_symbols():
            if symbol_name == sym.name:
                print(f"found {symbol_name} in {symbol_table} value {hex(sym['st_value'])}")
                return int(sym['st_value'])
            None
        None
    None
    return 0

