# analyze_elf.py -- project 3, csc6580 reverse engineering
# perlman group: Dennis Jump, Aaron Werth, Joseph Cherry, Maraz Mia
import sys
from collections import deque

from capstone import (Cs, CS_ARCH_X86, CS_MODE_64,
                      CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET)
from capstone.x86_const import (X86_OP_IMM, X86_OP_MEM, X86_OP_REG,
                                X86_REG_RIP, X86_REG_RDI, X86_REG_EDI)
from elftools.elf.elffile import ELFFile

STOP_INSTRUCTIONS = {'hlt', 'ud2', 'int3'}


# Mia: P3 addition - normalize the instruction mnemonic.
def base_mnemonic(instruction):
    return instruction.mnemonic.split()[-1]


def load_regions(elf):
    regions = []
    for section in elf.iter_sections():
        if (section['sh_flags'] & 4 and section['sh_type'] != 'SHT_NOBITS'
                and int(section['sh_size']) > 0):
            regions.append((int(section['sh_addr']), section.data(), section.name))
    return regions


def region_at(regions, address):
    for base, data, name in regions:
        if base <= address < base + len(data):
            return base, data, name
    return None


def decode_one(decoder, regions, address):
    region = region_at(regions, address)
    if region is None:
        return None
    base, data, _ = region
    offset = address - base
    return next(decoder.disasm(data[offset:offset + 15], address, count=1), None)


def immediate_target(instruction):
    if instruction.operands and instruction.operands[0].type == X86_OP_IMM:
        return int(instruction.operands[0].imm)
    return None


def rip_memory_address(instruction):
    if not instruction.operands:
        return None
    operand = instruction.operands[0]
    if (operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP
            and operand.mem.index == 0):
        return instruction.address + instruction.size + operand.mem.disp
    return None


def libc_relocations(elf):
    slots = set()
    for section in elf.iter_sections():
        if section['sh_type'] not in ('SHT_REL', 'SHT_RELA'):
            continue
        symbols = elf.get_section(section['sh_link'])
        if symbols is None or not hasattr(symbols, 'get_symbol'):
            continue
        for relocation in section.iter_relocations():
            symbol = symbols.get_symbol(relocation['r_info_sym'])
            if symbol is not None and symbol.name.split('@')[0] == '__libc_start_main':
                slots.add(int(relocation['r_offset']))
    return slots


def call_reaches_libc(instruction, decoder, regions, slots):
    if rip_memory_address(instruction) in slots:
        return True
    target = immediate_target(instruction)
    if target is None:
        return False
    for _ in range(4):
        stub = decode_one(decoder, regions, target)
        if stub is None:
            return False
        if base_mnemonic(stub) == 'jmp':
            return rip_memory_address(stub) in slots
        if stub.mnemonic not in ('endbr64', 'nop'):
            return False
        target += stub.size
    return False


def candidate_main(instruction):
    operands = instruction.operands
    if len(operands) < 2 or operands[0].type != X86_OP_REG:
        return None
    if operands[0].reg not in (X86_REG_RDI, X86_REG_EDI):
        return None
    source = operands[1]
    if instruction.mnemonic == 'lea' and source.type == X86_OP_MEM:
        if source.mem.base == X86_REG_RIP and source.mem.index == 0:
            return instruction.address + instruction.size + source.mem.disp
    if instruction.mnemonic == 'mov' and source.type == X86_OP_IMM:
        mask = 0xffffffff if operands[0].reg == X86_REG_EDI else 0xffffffffffffffff
        return int(source.imm) & mask
    return None


def writes_first_argument(instruction):
    operands = instruction.operands
    return (bool(operands) and operands[0].type == X86_OP_REG
            and operands[0].reg in (X86_REG_RDI, X86_REG_EDI)
            and instruction.mnemonic not in ('cmp', 'test', 'push'))


def find_start(elf, decoder, regions):
    entry = int(elf.header['e_entry'])
    slots = libc_relocations(elf)
    address = entry
    main_address = None
    for _ in range(80):
        instruction = decode_one(decoder, regions, address)
        if instruction is None:
            break
        if writes_first_argument(instruction):
            main_address = candidate_main(instruction)
        if instruction.group(CS_GRP_CALL):
            if main_address is not None and region_at(regions, main_address):
                following = decode_one(decoder, regions, address + instruction.size)
                ends_in_hlt = following is not None and following.mnemonic == 'hlt'
                if call_reaches_libc(instruction, decoder, regions, slots) or ends_in_hlt:
                    return main_address
            main_address = None
        if (instruction.group(CS_GRP_JUMP) or instruction.group(CS_GRP_RET)
                or instruction.mnemonic in STOP_INSTRUCTIONS):
            break
        address += instruction.size
    return entry


def previous_instruction(decoded, address):
    return next((instruction for instruction in decoded.values()
                 if instruction.address + instruction.size == address), None)


# Mia: P3 addition - recognize the opaque JAE used by the block test.
def is_opaque_jae(instruction, decoded):
    if base_mnemonic(instruction) not in ('jae', 'jnb'):
        return False
    shift = previous_instruction(decoded, instruction.address)
    zero = previous_instruction(decoded, shift.address) if shift else None
    return (shift is not None and shift.mnemonic == 'shl'
            and len(shift.operands) == 2
            and shift.operands[1].type == X86_OP_IMM
            and int(shift.operands[1].imm) == 1
            and zero is not None and zero.mnemonic == 'xor'
            and len(zero.operands) == 2
            and zero.operands[0].type == X86_OP_REG
            and zero.operands[1].type == X86_OP_REG
            and zero.operands[0].reg == zero.operands[1].reg)


def successors(instruction, decoded=None):
    following = instruction.address + instruction.size
    if instruction.group(CS_GRP_JUMP):
        target = immediate_target(instruction)
        if target is None:
            return []
        if (decoded is not None and is_opaque_jae(instruction, decoded)
                and base_mnemonic(instruction) != 'jmp'):
            return [target]
        edges = [target]
        if base_mnemonic(instruction) != 'jmp':
            edges.append(following)
        return edges
    if instruction.group(CS_GRP_RET) or instruction.mnemonic in STOP_INSTRUCTIONS:
        return []
    return [following]


def is_terminator(instruction):
    return bool(instruction.group(CS_GRP_JUMP) or instruction.group(CS_GRP_RET)
                or instruction.mnemonic in STOP_INSTRUCTIONS)


def discover_blocks(decoder, regions, start):
    leaders = {start}
    pending = deque([start])
    decoded = {}
    while pending:
        address = pending.popleft()
        if region_at(regions, address) is None:
            continue
        while address not in decoded:
            instruction = decode_one(decoder, regions, address)
            if instruction is None:
                break
            decoded[address] = instruction
            if instruction.group(CS_GRP_CALL):
                target = immediate_target(instruction)
                if target is not None and region_at(regions, target) is not None:
                    leaders.add(target)
                    pending.append(target)
            if is_terminator(instruction):
                for target in successors(instruction, decoded):
                    if region_at(regions, target) is not None:
                        leaders.add(target)
                        pending.append(target)
                break
            address += instruction.size
            if region_at(regions, address) is None:
                break

    result = []
    for leader in sorted(leaders):
        if leader not in decoded:
            continue
        block = []
        address = leader
        while address in decoded:
            if address != leader and address in leaders:
                break
            instruction = decoded[address]
            block.append(instruction)
            if is_terminator(instruction):
                break
            address += instruction.size
        if block:
            result.append(block)
    return result


# Mia: P3 addition - classify conditional blocks as predicates.
def is_predicate(block):
    instruction = block[-1]
    return instruction.group(CS_GRP_JUMP) and base_mnemonic(instruction) != 'jmp'


def format_instruction(instruction):
    suffix = f' {instruction.op_str}' if instruction.op_str else ''
    return f'0x{instruction.address:x}: {instruction.mnemonic}{suffix}'


# Mia: P3 addition - compute the value assigned to L for a sequence prime.
def block_l(block):
    instruction = block[-1]
    target = immediate_target(instruction)
    if target is not None:
        return target
    if base_mnemonic(instruction) == 'jmp':
        target = rip_memory_address(instruction)
        if target is not None:
            return target
    return 0


# Mia: P3 addition - print a function/sequence prime.
def print_prime(block):
    for instruction in block:
        print(format_instruction(instruction))
    print(f'L := 0x{block_l(block):x}')


# Mia: P3 addition - print an if-then-else prime.
def print_predicate(block):
    last = block[-1]
    print('if')
    for instruction in block:
        print(f'    {format_instruction(instruction)}')
    print('then')
    target = immediate_target(last)
    print(f'    L := 0x{target:x}' if target is not None else '    L := 0x0')
    print('else')
    print(f'    L := 0x{last.address + last.size:x}')
    print('fi')


def analyze_elf(path: str):
    with open(path, 'rb') as file:
        elf = ELFFile(file)
        if elf.elfclass != 64 or elf['e_machine'] != 'EM_X86_64':
            raise ValueError('Expected a 64-bit AMD64 ELF file')
        if elf['e_type'] not in ('ET_EXEC', 'ET_DYN'):
            raise ValueError('Expected an ELF executable (ET_EXEC or ET_DYN)')

        regions = load_regions(elf)
        entry = int(elf.header['e_entry'])
        if region_at(regions, entry) is None:
            raise ValueError(f'Entry point 0x{entry:x} is not in an executable section')
        decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        decoder.detail = True
        start = find_start(elf, decoder, regions)
        blocks = discover_blocks(decoder, regions, start)

        # Mia: P3 addition - emit the discovered blocks as Structure-Theorem primes.
        for index, block in enumerate(blocks):
            if index:
                print()
            if is_predicate(block):
                print_predicate(block)
            else:
                print_prime(block)