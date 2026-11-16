# main for project 4
# csc6580 reverse engineering
# perlman group
# dennis jump
# oct 23, 2026

#
# magic words to get to libraries
# export PYTHONPATH="/usr/lib/python3/dist-packages"
#

# code_nesting - nest once used blocks inline
#
import os
import sys
from elftools.elf.elffile import ELFFile, ELFError
from elftools.elf.sections import SymbolTableSection
from elftools.elf.sections import Symbol
from capstone import *

from elf_utilities import *
from analyze_elf import *
from start_address import *
from typing import Any

def code_nesting(structured:list[list[Any]])->bool:
    # construct a dictionary of L values and a count of times used
    mentions = dict()
    is_inside = False
    if_depth = 0
    changed_structure = True
    for instruction in structured:
        # looking for use of L value
        # must be inside of if fi bracket
        # appears (for now) that "if" "then" "else" "fi" and ":=" are unique keywords
        # so I will determine inside of if fi by incrementing and decrementing
        # the depth and flipping is_inside when depth is zero - coming or going
        # this is only to build the map / dictionary before trying to count
        # the structured list contains a separate field for this notation
        # skip structures with empty notation field

        
        [notation,_,_,_] = instruction
        if not notation: continue
        if "if" in notation: 
            is_inside = True
            if_depth += 1
            None
        if "fi" in notation: 
            if_depth -= 1
            if if_depth <= 0:
                if_depth = 0
                is_inside = False
                None
            None
        if is_inside and "L :=" in notation:
            l_value = notation.partition("L :=")[2] # get the information behind the "L :="
            hex_value = int(l_value,16) # check its value - going to throw out some
            if (hex_value < 2): continue # skip opening "1" tag and zero tags
            if not l_value in mentions: mentions[l_value] = 0 # add first mention to dictionary
            mentions[l_value] += 1 # increment count on every occurance
#            print(f"added / incremented {l_value} to dictionary")
            None
        None
    # go through the mentions and do something about the single use
    for l_value,count in mentions.items(): 
#        print(f"l_value {l_value} gets mentioned {count} times")
        if count == 1: # do the nesting for single use blocks
            # find the l_value as the ADDRESS field in the instruction list
            # build a list of instructions until an "L :=" if found
            # include it in the list and stop building
            # now the tricky part ... substitute this new sub-list for the 
            # instruction entry for the annotation L := value
            # now delete the extracted lines from their original position
            # moving the block up?
            # moving the block down?
            changed_structure = block_and_move(l_value,structured)
            None
        None
    return changed_structure

def block_and_move(l_value:str,structured:list[list[Any]])->bool:
    target_address = int(l_value,16) # get the int value for comparing with code address field
    index_of_l_value_reference = 0
    index_of_block_start = 0
    index_of_terminating_l_value = 0
    inside_if = False
    if_depth = 0
    inside_block = False
    the_block:list[list[Any]] = list()
    
    # added notes after I got the "flat" version working.
    # at the moment, i don't know how to attack an if fi group to be
    # moved like a primitive block of code
    if_begins = list()
    if_begin = 0
    fi_ends = 0
    for index,instruction in enumerate(structured):
        [notation,address,_,_] = instruction
#        print(f"{index}: {notation} {address:x}")
        if "if" in notation: 
            inside_if = True
            if_begins.append(index) #push the if index into the stack
            if_depth += 1
            None
        if "fi" in notation:
            if_begin = if_begins.pop()
            fi_ends = index 
            inside_if = False
            None

        if inside_if:
            if l_value in notation: 
                index_of_l_value_reference = index
                None

        if target_address == address:
            index_of_block_start = index if not inside_if else if_begin
            inside_block = True
            None

        if inside_block:
            if "L :=" in notation: # annotation at the end of the block 
                # include this in the block as it shows where to transfer 
                # control after the block executes
                # HOWEVER - if the terminating "L :=" is 0x00
                # THEN don't use this block
                if int(notation.partition("L :=")[2],16) == 0:
                    inside_block = False
                    index_of_block_start = 0
                    index_of_terminating_l_value = 0
                    None
                else:
                    index_of_terminating_l_value = index if not inside_if else fi_ends
                    inside_block = False
                    None
                None
        None
        if (index_of_l_value_reference != 0) and (index_of_block_start != 0) and (index_of_terminating_l_value != 0): 
            break
    None
    # make sure that we actually caught something
    if index_of_l_value_reference == 0: return False
    if index_of_block_start == 0: return False
    if index_of_terminating_l_value == 0: return False
#    print(f"move block {index_of_block_start}:{index_of_terminating_l_value} to {l_value} reference at {index_of_l_value_reference}")
    # now we have the location of the notation line to be replaced
    # with block of code
    # the last line is notation of end of block
    the_block = structured[index_of_block_start:index_of_terminating_l_value+1]
    # can't just drop a block of code into the mixture
    # beware of changing indices when items are inserted or deleted

    # moving the block to the front
    # 
    if index_of_l_value_reference < index_of_block_start: 
        # going to do it this way to keep indices straight
        # remove the blocks from the list - will not affect the reference index
        del structured[index_of_block_start:index_of_terminating_l_value+1]
        # remove the reference notation
        del structured[index_of_l_value_reference:index_of_l_value_reference+1]
        # plug the extracted block in the location of the reference
        structured[index_of_l_value_reference:index_of_l_value_reference] = the_block
        None
    # moving the block towards the end of the list
    elif index_of_l_value_reference > index_of_terminating_l_value: 
        # remove the reference notation. The location stays the same for the moment
        del structured[index_of_l_value_reference:index_of_l_value_reference+1]
        # plug the extracted block in the location of the reference
        structured[index_of_l_value_reference:index_of_l_value_reference] = the_block
        # remove the extracted block from its location at the front
        del structured[index_of_block_start:index_of_terminating_l_value+1]
        None
    return True # all done

