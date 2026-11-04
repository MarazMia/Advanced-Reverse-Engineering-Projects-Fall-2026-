# main for project 2
# csc6580 reverse engineering
# perlman group
# dennis jump
# oct 23, 2026

#
# magic words to get to libraries
# export PYTHONPATH="/usr/lib/python3/dist-packages"
#


import os
import sys
from elftools.elf.elffile import ELFFile, ELFError
from capstone import *

from analyze_elf import *
from elf_utilities import *
    
# main is a simple starting point
# fetches the elf filename and sends to start the analysis
def main() -> int:

    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} [path to ELF file]")
        return 0
    filename = sys.argv[1]

#    filename = "/home/djump/csc6580/P1/reverse" # this is my test 
    try:
        # dj the object returned by ELFFile is a file and must be open
        # dj for the duration --  
        # dj moved it into the analyze_elf function because leaving
        # dj it in open elf seems to be more than OPEN and the file closes
        # dj as you leave the scope of the "with open" statement
        # dj changed it to analyze elf would make more sense
        # dj in that case, move all of this to analyze_elf(filename)
        # dj and work from there in another file
        analyze_elf(filename)
        return 0
    except FileNotFoundError:
        elf_error(f"File not found ({sys.argv[0]})")
    except IsADirectoryError:
        elf_error("Provided path is a directory")
    except PermissionError:
        elf_error("Cannot read file")
    except ELFError as err:
        elf_error(f"Invalid ELF file: {err}")    
    return -1
    None

if __name__ == "__main__":
    sys.exit(main())