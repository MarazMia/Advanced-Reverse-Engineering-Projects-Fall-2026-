import os
import sys
from elftools.elf.elffile import ELFFile, ELFError
from capstone import *

def elf_error(msg) -> None:
    """Print an error message."""
    print(f"ELF ERROR: {msg}")
    None

def print_instruction_list(i_list:list):
    for instruction in i_list :
        print(f"0x{instruction[0]:x}:\t{instruction[1]}\t{instruction[2]}")
        None
    None

def analyze_elf(path: str):
    with open(path, "rb") as file:
        elf = ELFFile(file)
        # dj get a reference to the .text section
        text_section = find_text_section(elf)
        # dj don't fall for Stacy passing in an elf file without a .text section
        if not text_section: return -1
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
        text_contents = text_section.data()
        # dj get the size of the .text section
        text_size:int = text_section.data_size
        # mia send these to the disassembler
        instruction_list: list = disassemble(text_contents, text_section["sh_addr"])
        # dj testing that the disassembler did its job
        print_instruction_list(instruction_list)
        None
    None

def find_text_section(elf_contents):
    # Get the .text section by name
    text_section = elf_contents.get_section_by_name('.text')
    if not text_section :
        elf_error("There is no .text section. Nice move, Stacy")
        return None
        None
    return text_section

def disassemble(text,length:int) -> list:
    # dj could pass arch and mode as parameters and generate
    # dj capstone equivalents for making this more flexible
#    md = Cs(arch,mode)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    instructionList:list = []
    for i in md.disasm(text, length):
        # dj for later things to come, I suspect
        # dj we may want to generate a List of instructions with
        # dj tuples for address mnemonic and op_str
        # dj and return the list instead of printing it
        # print(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")
        # dj oh, what the hell. I start writing and can't stop
        instructionList.append((i.address,i.mnemonic,i.op_str))
    None
    return instructionList
