# analyze elf for project 3
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
from code_extraction import *
from code_structuring import *
from elf_utilities import *
from registers_dead_or_alive import *
import re
# ------- main control ----------------
# analyze elf keeps the elf file open throughout the preliminary analysis
# checks for the validity of the .text section
# passes it to the capstone for disassembly
# captures the results in a list of tuples for further testing
# in a later phase of the project

#from gemin is this little gem
pattern = r"^(?:0[xX])?[0-9a-fA-F]+$"
def is_hex(s: str) -> bool:
    # Matches an optional 0x/0X followed by one or more hex digits
    return bool(re.fullmatch(pattern, s))

def analyze_elf(path: str):
    with open(path, "rb") as file:
        elf = ELFFile(file)
        # dj check the E header for the entry point
        section_name = ""
        start = 0
        section_address = 0
#        build_plt_map(elf)
        [section_name,section_address,start] = get_start_section_and_address(elf)
        start_start = get_entry_point(elf)

#        print(f"section_name {section_name}")
#        print(f"section_address {section_address:x}")
#        print(f"start_start {start_start:x}")
#        print(f"start {start:x}")
        # dj get a reference to the .text section
#        print(f"get contents of {section_name} section")
        the_section = find_section(elf,section_name)
        # dj don't fall for Stacy passing in an elf file without a .text section
        if not the_section: return -1
        # dj get the binary data ... or maybe a reference to it
        # dj haven't worried about it for the moment
        # going to slice the section holding code at the main address
        # can't scan instructions for that address for the bogus "db" that might be there
        # get the offset from the entry_address (start-start) to the calculated start
        offset = start - start_start
#        print(f"offset {offset} {offset:x}")
        # slice the section data starting at the offset and the rest of the section
        the_contents = the_section.data()[offset:]
        # dj get the size of the .text section
        # the_size:int = the_contents.data_size # this isn't right, but not used at the moment
#        print(f"contents of {section_name} is {the_size} bytes long")
        # dj get calculated start point (main) for counting offset
        # dj send these to the disassembler

        # going to start with the section where the start / main address is
        # disasm that section
        # save the instructions into section_list (of instructions) with section name and address
        # scan the instructions for "call" and "jmp" type instructions
        # to get addresses of jump targets and call function addresses
        # get the section for the address IF that section is a new discovery
        # add the new section into the queue of sections to disassemble and add to the section list instructions
    
        section_list:list[str,int,list[int,str,str]] = list()
        used_sections:set[str] = {'.plt','.got'}
        initial_section = (section_name,start,offset)
        found_sections:set[tuple[str,int]] = set()
        found_sections.add(initial_section)
        while found_sections:
            # pick a section ... any section
            this_section = found_sections.pop()
            # extract name, start and offset. offset is only used for where main is to get to main
            _section_name = this_section[0]
            _section_start = this_section[1]
            _section_offset = this_section[2]
            # get a reference to the section and get its contents
            the_section = find_section(elf,_section_name)  
            the_contents = the_section.data()[_section_offset:]
            # disassemble the section
            instruction_list:list[int,str,str] = disassemble(the_contents,_section_start)
            # save the disasm instructions into the collection
            section_list.append([_section_name,_section_start,instruction_list])
            # we have this section none, skip over it and others when looking for more sections
            used_sections.add(_section_name)
            # scan the instructions to find addresses of other sections
            ref_sections = find_referenced_sections(elf,instruction_list,used_sections)
            # add any found sections to the sections to disassemble list (set)
            found_sections = found_sections.union(set(ref_sections))
            # clear the instruction_list
            instruction_list = list()
            None
 
        address:int = 0
        mnemonic:str = ""
        operands:str = ""
        # sort by starting address so that the appear in the proper order
        section_list.sort(key=lambda x: x[1])
        section_start:int = 0
        first_section = True
        # this holds the final annotated instructions pieced from various sections
        program_strucure:list[str,int,str,str] = list()
        # look at each set of instructions from each section
        for i in range(0,len(section_list)):
            # get the instructions for extraction and structuring
            [section_name,section_start,instruction_list] = section_list[i]
            # print(f"0x{section_start:x} section: {section_name}")
            updated_instruction_list:list[int,bool,list[int,str,str,int,bool]] = code_block_extraction(elf,instruction_list,section_start)
        #    block_strucure:list[str,int,str,str] = code_block_structuring(updated_instruction_list,first_section)
            first_section = False
            
            for i in range(0, len(updated_instruction_list)):
                program_strucure.append(updated_instruction_list[i])
                None
            updated_instruction_list = list()
        None
        # print out the results
        # pass program_structure to whatever comes next
        # struct:str = ""
        # for i in range(0, len(program_strucure)):
        #     [struct,address,mnemonic,operands] = program_strucure[i]
        #     if struct:
        #         print(struct)
        #         continue
        #     print(f"\t\tox{address:x}  {mnemonic:6}  {operands}")
        #     None
        # the block is NOT structured
        # list is block starting address, boolean True if JUMP terminated, 
        # list of instructions
        #   address (int),
        #   mnemonic (str),
        #   operands (str),
        #   rip_address (int),
        #   is_target (bool)
        dead_or_alive:list = registers_dead_or_alive(program_strucure)
        for i in range(0,len(dead_or_alive)):
            [starting_address, reg_list] = dead_or_alive[i].get_report_line()
            print(f"0x{starting_address:08x}:\t",end="")
            last_reg = len(reg_list) - 1
            for j in range(0,len(reg_list)):
                print(f"{reg_list[j]}",end="")
                if j != last_reg: print(", ",end="")
                None
            None
            print()
        None
    None


# find_text_section checks the elf file for a .text section
# returns an ANY result - NULL would be a missing or corrupt .text section
# disassemble calls capstone disassembly for the .text file
def disassemble(text,base:int) -> list[int,str,str]:
    # dj could pass arch and mode as parameters and generate
    # dj capstone equivalents for making this more flexible
    # dj this could come from the exec hdr at a later date as needed

#    md = Cs(arch,mode)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.syntax = CS_OPT_SYNTAX_INTEL
    instructionList:list = []
#    print(f"disasm entry offset: {base:x}")
    for i in md.disasm(text, base):
        # dj we may want to generate a List of instructions with
        # dj tuples for address mnemonic and op_str
        # dj and return the list instead of printing it
        instructionList.append(( i.address,i.mnemonic,i.op_str))
        None
    return instructionList

def find_referenced_sections(elf:ELFFile,instruction_list:list[int,str,str],used_sections:set[str]) -> set[tuple[str,int,int]]:
    address:int = 0
    mnemonic:str = ""
    operands:str = ""
    found_sections:set[tuple[str,int,int]] = set()
    # look at each instruction
    for i in range(0,len(instruction_list)):
        [address,mnemonic,operands] = instruction_list[i]
        # only interesting in "call" and jump type
        if (mnemonic.lower() == "call") or (mnemonic.lower() in jmp_cmd):
            # check operand for being a hex address
            if is_hex(operands):
                # get the address value
                call_address = int(operands,16)
                # find the section that has this address
                [_section_name, _section_address] = find_section_with_this_address(elf, call_address)
                # got it, got it, need it, got it
                if _section_name in used_sections: continue
                # only save sections that have a real address
                if (_section_address != 0):
#                    print(f"found address in section {section_name}")
                    section_group = (_section_name,_section_address,0)
                    # save it to add to sections to be disassembled
                    found_sections.add(section_group)
                    None
                None
            None
        None
    None
    return found_sections