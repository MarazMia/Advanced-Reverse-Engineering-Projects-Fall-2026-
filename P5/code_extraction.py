# code block extraction for project 3
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

def code_block_extraction(elf_contents:ELFFile, instruction_list:list[int,str,str],start_address:int)->list[int,bool,list[int,str,str,int,bool]]:
    # just so we know that it works, here is the find the LEA-CALL-HLT address finder
    alt_start = find_alternative_c_start(instruction_list,0,0)
#    if alt_start == start_address: 
#        print(f"alt start {alt_start:x} agrees with start address")
#    else:
#        print(f"alt start {alt_start:x} does not agree with start address {start_address:x}")
    # go through the instruction list to find code breaks
    # I am using known addresses with labels
#   print(f"starting address: {start_address:x}")
    target:set = set()
    # go through the code and collect operands for instructions in the jmp_cmd set
    # use these to identify code block leaders where a jmp sends control
    # most likely where there were labels in the source code
    # looking up the address in the symbol table and string table yields the label name
    for i in range(len(instruction_list)):
        [address, mnemonic, operands] = instruction_list[i]
        if mnemonic.lower() in jmp_cmd:
            target.add(operands)
    #        print(f"added {operands} to target")
            None
        None
    # initialize the structure for storing the instructions in a code block
    # and the list that holds the collected blocks
    # address:int
    # mnemonic: str
    # operands: str
    # target address termination: bool
    basic_block:list[int,str,str,int,bool] = list()
    # jmp command termination: bool
    # basic_block list
    block_list:list[int,bool,list[int,str,str,int,bool]] = list()
    # set flags for controlling the collection of instructions
    is_leader = True
    is_target = False
    block_start_address = 0
    # look at all of the instructions
    for i in range(len(instruction_list)):
        # clear the target (result of jump instruction) flag
        is_target = False
        # get the fields for the instruction
        [address, mnemonic, operands] = instruction_list[i]
        # check the target list to see if this address is a target for a jump instruction
        if f"0x{address:x}" in target: # beginning of a block
            # save any block collected so far as this is the beginning of a code block
            # tag it as being terminated by the next instruction being a target
            if len(basic_block) > 0: # save the preceding block and start a new one
#                for [_address,_mnemonic,_operands,_,_] in basic_block:
#                   print(f" target terminated {_address} {_mnemonic} {_operands}")
#                    None
                block_list.append([block_start_address,False,basic_block]) #ended by a jump target
                None
            # current instruction is a code block leader
            is_leader = True
            # current instruction is a jmp target
            is_target = True
            None
        # as a leader, start with a fresh basic_block and clear the flag
        if is_leader:
            basic_block = list()
            block_start_address = address
            is_leader = False
            None
        # peek at the next instruction for the rip
        rip_address = 0
        if i < (len(instruction_list)-1): [rip_address, _, _] = instruction_list[i+1]
        # put the instruction into the basic block list
        basic_block.append([address,mnemonic,operands,rip_address,is_target])
        # if the mnemonic is in the set of jmp commands or call
        # then this is the end of the code block
        if mnemonic.lower() in jmp_cmd: # end of block
#            for [__address,__mnemonic,__operands,_,_] in basic_block:
#                print(f" jump terminated {__address} {__mnemonic} {__operands}")
#                None
            # add the code block to the block list -- set the jump flag to show that
            # the block was terminated with a jmp and needs the surrounding if / fi structure
            block_list.append([block_start_address,True,basic_block]) # block ended with jump
            # clear the current block for the next code block
            basic_block = list()
            # next instruction is a leader
            is_leader = True
            None
        # do we want to stop at the hlt for this?
#       if mnemonic == "hlt": break
        None
    # there may be a remaining code block that needs to be added to the block list
    if len(basic_block) > 0:
        block_list.append([block_start_address,False,basic_block]) # block didn't end with jump command
        None
    # return the blocked code
    return block_list

        
