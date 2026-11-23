# registers_dead_or_alive(program_structure)
# csc6580 reverse engineering
# perlman group
# dennis jump
# Nov 22, 2026
# Project 5

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
import re

# scan all of the blocks and create a class for each which records
# beginning address
# ending address
# set of registers in 64 bit nomenclature coming into the block
# set of registers written during the block
r8_names = (  "AL",  "CL",  "DL",  "BL", "SPL", "BPL", "SIL", "DIL", "R8B", "R9B", "R10B", "R11B", "R12B", "R13B", "R14B", "R15B" )
r16_names =(  "AX",  "CX",  "DX",  "BX",  "SP",  "BP",  "SI",  "DI", "R8W", "R9W", "R10W", "R11W", "R12W", "R13W", "R14W", "R15W" )
r32_names =( "EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI", "R8D", "R9D", "R10D", "R11D", "R12D", "R13D", "R14D", "R15D" )
r64_names =( "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",  "R8",  "R9",  "R10",  "R11",  "R12",  "R13",  "R14",  "R15" )
 
r80_names =  ( "ST0", "ST1", "ST2", "ST3", "ST4", "ST5", "ST6", "ST7" )
sreg_names = ( "ES", "CS", "SS", "DS", "FS", "GS" )
mmx_names =  ( "MM0", "MM1", "MM2", "MM3", "MM4", "MM5", "MM6", "MM7" )
xmm_names =  ( "XMM0", "XMM1", "XMM2", "XMM3", "XMM4", "XMM5", "XMM6", "XMM7", "XMM8", "XMM9", "XMM10", "XMM11", "XMM12", "XMM13", "XMM14", "XMM15" )
ymm_names =  ( "YMM0", "YMM1", "YMM2", "YMM3", "YMM4", "YMM5", "YMM6", "YMM7", "YMM8", "YMM9", "YMM10", "YMM11", "YMM12", "YMM13", "YMM14", "YMM15" )
zmm_names =  ( "ZMM0", "ZMM1", "ZMM2", "ZMM3", "ZMM4", "ZMM5", "ZMM6", "ZMM7", "ZMM8", "ZMM9", "ZMM10", "ZMM11", "ZMM12", "ZMM13", "ZMM14", "ZMM15", "ZMM16", "ZMM17", "ZMM18", "ZMM19", "ZMM20", "ZMM21", "ZMM22", "ZMM23", "ZMM24", "ZMM25", "ZMM26", "ZMM27", "ZMM28", "ZMM29", "ZMM30", "ZMM31" )
cr_names =   ( "CR0", "CR1", "CR2", "CR3", "CR4", "CR5", "CR6", "CR7" )
dr_names =   ( "DR0", "DR1", "DR2", "DR3", "DR4", "DR5", "DR6", "DR7" )

def isaregister(r:str) -> bool:
    rg = r.upper()
    if rg in r8_names: return True
    if rg in r16_names: return True 
    if rg in r32_names: return True 
    if rg in r64_names: return True 
    if rg in r80_names: return True 
    if rg in sreg_names: return True
    if rg in mmx_names: return True 
    if rg in xmm_names: return True 
    if rg in ymm_names: return True 
    if rg in zmm_names: return True 
    if rg in cr_names: return True
    if rg in dr_names: return True
    return False

def normalize_register(r) -> str:
    r = r.upper()
    if r in r8_names:
        where = r8_names.index(r)
        return r64_names[where]
    elif r.upper() in r16_names:
        where = r16_names.index(r)
        return r64_names[where]
    elif r in r32_names:
        where = r32_names.index(r)
        return r64_names[where]
    return r

def parameter_constituent_parts(p:str) -> list[str]:
    reg_list = list()
    parts = p.split("[]+*")
    for r in parts:
        if isaregister(r.strip()):
            reg = normalize_register(r.strip())
            reg_list.append(reg)
            None
    return reg_list

write_operand_instructions = ("INC", "DEC" ,"NEG" ,"NOT" ,"POP" ,"BSWAP","SET")
read_operand_instructions = ("PUSH","CALL","JMP","Jcc","MUL","IMUL","DIV","IDIV") 

def does_instruction_write_the_operand(inst:str)->bool:
    if inst.upper() in write_operand_instructions: return True
    if inst.startswith("SET"): return True     
    return False

def does_instruction_read_and_write_the_operand(inst:str)->bool:
    if inst.startswith("SET"): return False     
    if inst == "POP": return False
    if inst.upper() in write_operand_instructions: return True
    return False

# need to watch for blocks terminated with ret 
class block_scorecard:
    def __init__(self):
        self.starting_address = 0
        self.ending_address = 0
        self.live_on_entry = set()
        self.written_registers = set()
        pass
    def load_start_address(self, addr):
        self.starting_address = addr
        pass
    def load_end_address(self, addr):
        self.starting_address = addr
        pass
    def add_register_live_on_entry(self, reg:str):
        self.live_on_entry.add(reg)
        pass
    def add_register_written(self, reg:str):
        self.written_registers.add(reg)
        pass
    def get_sorted_live_registers(self) -> list:
        reg_list: list[str] = self.live_on_entry
        return sorted(reg_list)
    def get_report_line(self) -> list:
        reg_list = self.get_sorted_live_registers()
        return [self.starting_address,reg_list]
    def has_parameters(self) -> bool:
        return ((len(self.live_on_entry) + len(self.written_registers)) > 0)
    def has_live_parameters(self) -> bool:
        return (len(self.live_on_entry) > 0)
    def has_written_parameters(self) -> bool:
        return (len(self.written_registers) > 0)
    def has_register_been_written_to(self,r:str) -> bool:
        return r in self.written_registers
    pass


def registers_dead_or_alive(program_structures:list) -> list :
    #each item in program structure is a block
    program_scord_cards = list()
    instructions = list()
    for i in range(0,len(program_structures)):
        score_card = block_scorecard()
        # list is:
        #   block starting address, 
        #   boolean True if JUMP terminated, 
        #   list of instructions
        #       address (int),
        #       mnemonic (str),
        #       operands (str),
        #       rip_address (int),
        #       is_target (bool)
        [starting_address,_,instructions] = program_structures[i]
        # look for a comma in operands to tell us how many operands there are
        # presume / hope for ... only none, one or two. Three are rare in non-vector extended space but they exist
        # OK - release the Kracken
        # get the fields from the instruction
        # capture the starting address from the block
        # get last instruction so we can save the ending address
        last_instruction = len(instructions) - 1
        first_instruction = True
        for k in range(0,len(instructions)):
        # capture the ending address in the last block
            [address, inst, operands, _, _] = instructions[k]
            if first_instruction:
                first_instruction = False
                score_card.starting_address = address
                None
            if k == last_instruction:
                score_card.ending_address = address
                None
            # split the operands at the comma to get separate operands to extract registers
            parameter_list = operands.split(',')
            # no parameters, nothing to do
            if len(parameter_list) == 0: continue
            # could be call to address in register or register + offset
            if len(parameter_list) == 1: 
                # it is possible that this instruction MAY write the register (POP)
                # or read the register (PUSH)
                # when the register is read regardless of whether - since it is a pointer - it is push or pop
                # take care of that first
                regs = parameter_constituent_parts(parameter_list[0])
                if "[" in parameter_list[0]: 
                    for r in regs: score_card.add_register_live_on_entry(r)
                    regs = ()
                    None
                elif does_instruction_write_the_operand(inst):
                    if does_instruction_read_and_write_the_operand(inst):                  
                        for r in regs: score_card.add_register_live_on_entry(r)
                        None
                    for r in regs: score_card.add_register_written(r)
                    None
                else:
                    for r in regs: score_card.add_register_live_on_entry(r)
                    None
                continue  
            # should be a register in here someplace
            # filter the operands for indication of a register name 
            # get back the list of registers found in the operand
            # store the registers according to the position in the Intel instruction          
            if len(parameter_list) == 2: 
                # live registers
                written_regs = parameter_constituent_parts(parameter_list[0])
                if "[" in parameter_list[0]: # the register is read regardless of whether it is push or pop
                    for r in written_regs: score_card.add_register_live_on_entry(r)
                    written_regs = () # won't be used to add to written register
                    None
                live_regs = parameter_constituent_parts(parameter_list[1])
                for r in live_regs: 
                    if not score_card.has_register_been_written_to(r):
                        score_card.add_register_live_on_entry(r)
                # written registers
                for r in written_regs: score_card.add_register_written(r)
                continue
            # OMG, he tricked us with an IMUL or IDIV which take three operands
            if len(parameter_list) == 3:
                written_regs = parameter_constituent_parts(parameter_list[0])
                if "[" in parameter_list[0]: # the register is read regardless of whether it is push or pop
                    for r in written_regs: score_card.add_register_live_on_entry(r)
                    written_regs = () # won't be used to add to written register
                    None
                live_regs = parameter_constituent_parts(parameter_list[1])
                for r in live_regs: 
                    if not score_card.has_register_been_written_to(r):
                        score_card.add_register_live_on_entry(r)
                live_regs = parameter_constituent_parts(parameter_list[2])
                for r in live_regs: 
                    if not score_card.has_register_been_written_to(r):
                        score_card.add_register_live_on_entry(r)
                for r in written_regs: score_card.add_register_written(r)
                continue
            None # data gathering loop
            # save the score card for returning to the analyzer
        program_scord_cards.append(score_card) #going to show a block even without registers
#       if score_card.has_live_parameters() : program_scord_cards.append(score_card)
        score_card = ()
        None # end of program block loop
    return program_scord_cards
