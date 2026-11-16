# code block structuring
# code block extraction for project 4
# csc6580 reverse engineering
# perlman group
# dennis jump
# oct 30, 2026

import os
import sys
from typing import Any
from elftools.elf.elffile import ELFFile, ELFError
from elftools.elf.sections import SymbolTableSection
from elftools.elf.sections import Symbol
from capstone import *

from elf_utilities import *
from analyze_elf import *
from start_address import *
# f0a4 1022 cafe babe --- what is this code mean?
def code_block_structuring(instruction_blocks:list[int,bool,list[int,str,str,int,bool]],first_section:bool)->list[str,int,str,str]:
    # pick a non-zero starting number
    structured_output:list[str,int,str,str] = list()
    if first_section: structured_output.append(["    L := 1",0,"",""])
    for [_,is_jump_terminated,block_instructions] in instruction_blocks:
        did_blank_line = False
        for [address, mnemonic, operands, rip_address, is_target] in block_instructions:
            # if this instruction is the target of a jmp, then label this point
            if is_target: 
            #    print(f"L := 0x{address:x}")
                structured_output.append([f"    L := 0x{address:x}",0,"",""])
                None
            # blank line to start a block
            if not did_blank_line:
#                print("") # blank line at the start of a block
                structured_output.append([" ",0,"",""])
                did_blank_line = True
                None
            # if this block is jmp terminated, add the "if" prefix
            if is_jump_terminated: 
                structured_output.append(["if",0,"",""])
                #print("if")
                is_jump_terminated = False
                None
            # print the 
            # print(f"\t0x{address:x}:    {mnemonic:8}    {operands}")
            structured_output.append(["",address,mnemonic,operands])
            if mnemonic.lower() in jmp_cmd:
                structured_output.append(["then",0,"",""])
                structured_output.append([f"    L := {operands}",0,"",""])
                structured_output.append(["else",0,"",""])
                structured_output.append([f"    L := 0x{rip_address:x}",0,"",""])
                structured_output.append(["fi",0,"",""])
                None
            if mnemonic.lower() == "ret": 
                structured_output.append(["    L := 0x0",0,"",""])
            None
        None
    None
    return structured_output

