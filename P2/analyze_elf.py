# analyze elf for project 2
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

from start_address import *
from code_block_extraction import *
from elf_utilities import *

# ------- main control ----------------
# analyze elf keeps the elf file open throughout the preliminary analysis
# checks for the validity of the .text section
# passes it to the capstone for disassembly
# captures the results in a list of tuples for further testing
# in a later phase of the project

def analyze_elf(path: str):
    with open(path, "rb") as file:
        elf = ELFFile(file)
        # dj check the E header for the entry point
        section_name = ""
        start = 0
        section_address = 0
        build_plt_map(elf)
        [section_name,section_address,start] = get_start_section_and_address(elf)
        # dj get a reference to the .text section
        print(f"get contents of {section_name} section")
        the_section = find_section(elf,section_name)
        # dj don't fall for Stacy passing in an elf file without a .text section
        if not the_section: return -1
#        return
        # dj the disassembler has to have the machine for the object code
        # dj and whether it is written for 16-32-64 bit architecture
        # dj i pulled out the machine type - we would need to change that
        # dj into capstone parameter values
        # dj see the disassemble method -- i hard-coded the values to test easily
#       arch = elf.header['e_machine']
#       mode = CS_MODE_64
        # dj get the binary data ... or maybe a reference to it
        # dj haven't worried about it for the moment
        # dj it works
        the_contents = the_section.data()
        # dj get the size of the .text section
        the_size:int = the_section.data_size
        print(f"contents of {section_name} is {the_size} bytes long")
#        the_size = 4096
        # dj get entry point
        # dj send these to the disassembler
        instruction_list:list[int,str,str] = disassemble(the_contents,section_address)
        updated_instruction_list = code_block_extraction(elf,instruction_list,start)
        #
        # BEWARE: the instruction list is now list[str,str,str] so I can put address labels in the address field
        # I can expand the fields to list[int,str,str,str] if that is a hardship
        # either way, there will be a change
        #
        # dj testing that the disassembler did its job
        # dj and the code block extraction divided things up
        # dj dump the code to see what it looks like
        dump_updated_instruction_list(updated_instruction_list)        
        None
    None
# find_text_section checks the elf file for a .text section
# returns an ANY result - NULL would be a missing or corrupt .text section
# disassemble calls capstone disassembly for the .text file
def disassemble(text,base:int) -> list:
    # dj could pass arch and mode as parameters and generate
    # dj capstone equivalents for making this more flexible
    # dj this could come from the exec hdr at a later date as needed

#    md = Cs(arch,mode)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.syntax = CS_OPT_SYNTAX_INTEL
    instructionList:list = []
    print(f"disasm entry offset: {base:x}")
    for i in md.disasm(text, base):
        # dj for later things to come, I suspect
        # dj we may want to generate a List of instructions with
        # dj tuples for address mnemonic and op_str
        # dj and return the list instead of printing it
        # print(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")
        # dj oh, what the hell. I start writing and can't stop

        # found that disasm puts out an offset address which is the size of the from (probably .init)
        # and not the address that matches the entry address nor the main address
        # ... as an experiment, pass the size of the .init section and the base address of
        # .text or whatever section it is to get a good address
        address = i.address
        operands = i.op_str
# #        if i.mnemonic in jmp_cmd:
#         print(f"{i.mnemonic} {i.op_str}")
#         if "[rip" in i.op_str:
#             print(f"relative {i.mnemonic} {i.op_str}")                   
#             None
#         elif "0x" in i.op_str:
#             print(f"just hex {i.mnemonic} {i.op_str}")                   
#             target = int(i.op_str,16)
#             None
#         else:
#             print(f"unknown {i.mnemonic} {i.op_str}")                   
#             None
# #           operands = f"0x{target:x}"
# #           print(f"{i.mnemonic} {operands} target= {target:x}")
# #            None

        instructionList.append(( i.address,i.mnemonic,i.op_str))
        None
    return instructionList

