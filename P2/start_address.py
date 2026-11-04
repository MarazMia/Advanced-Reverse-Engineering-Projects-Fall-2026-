# start_address for project 2
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
# dj function searches for block entry code
# dj get the start value from EHdr
# d jit then checks for a potential alternative entry point at "main"
# dj it takes the winner and looks for the section with that address
# dj return name of section and section base address and start address

def get_start_section_and_address(elf_contents:ELFFile) -> list[str,int,int]:
    # dj get the Ehdr entry point
    start = get_entry_point(elf_contents)
    print(f"EHdr entry point = 0x{start:x}")
    # dj start check for "main" entry
    main_start = 0
    # dj check the .symtab for an entry of __libc_start_main 
    # dj which validates that finding "main" in the symbol table is the C main   
    if is_symbol_in_table(elf_contents, ".symtab", "__libc_start_main"):
        # dj if there is a __libc_start_main in the .symtab, get the value for "main.c"
        main_start = get_symbol_value(elf_contents, ".symtab","main")
        print(f"symtab results = {main_start:x}")        
        None
    elif is_symbol_in_table(elf_contents, ".dynsym", "__libc_start_main"):
        # dj didn't find it in .symtab, so try the dynamic side .dynsym (or is that chinese lunch?)
        # dj found out that finding __libc_start_main doesn't mean that main is there too
        # dj check the main culprit ... the .symtab and return the associated value
        main_start = get_symbol_value(elf_contents, ".symtab","main")
        # dj OK try the dynamic one if there is none in the .symtab
        if main_start == 0: main_start = get_symbol_value(elf_contents, ".dynsym","main")
        print(f"dynsym results = {main_start:x}")
        None
    # dj if main was found, replace the Ehdr start
    if main_start > 0: start = main_start
    print(f"Final entry point = 0x{start:x}")
    # dj find the section with that address
    section_name:str = ""
    section_address:int = 0
    [section_name,section_address] = find_section_with_this_address(elf_contents, start)
    print(f"address is in section : {section_name} start_address: 0x{section_address:x}")
    return [section_name,section_address,start] # return section and address