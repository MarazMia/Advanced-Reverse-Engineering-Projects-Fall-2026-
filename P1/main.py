# main for project 1
# csc6580 reverse engineering
# perlman group
# dennis jump
# Maraz Mia
# Aaron Werth
# Joseph Cherry

import os
import sys
from elftools.elf.elffile import ELFFile, ELFError
from capstone import *
import analyze_elf
# dj I am adding my initials to comments to keep things straight
# dj A sanitized version gets turned in

# mia comments initials



#def open_elf(path: str):
#    """Open the given file as an ELF file and report some info."""
#    with open(path, "rb") as file:
#        elf = ELFFile(file)
#        None
#    return elf


def error(msg) -> None:
    """Print an error message."""
    print(f"ERROR: {msg}")
    None



def main() -> int:
    if len(sys.argv) != 2:
       print(f"usage: {sys.argv[0]} [path to ELF file]")
       return 0

    filename = sys.argv[1] # mia added the cmd file reading 
    
    try:
        analyze_elf.analyze_elf(filename)
        # dj the object returned by ELFFile is a file and must be open
        # dj for the duration -- so I moved it into main and 
        # dj then into the analyze_elf function because leaving
        # dj it in open elf seems to be more than OPEN and the file closes
        # dj as you leave the scope of the "with open" statement
        # dj changed it to analyze elf would make more sense
        # dj in that case, move all of this to analyze_elf(filename)
        # dj and work from there.
        return 0
    except FileNotFoundError:
        error(f"File not found ({filename})")
    except IsADirectoryError:
        error("Provided path is a directory")
    except PermissionError:
        error("Cannot read file")
    except ELFError as err:
        error(f"Invalid ELF file: {err}")    
    return -1
    None

if __name__ == "__main__":
    sys.exit(main())