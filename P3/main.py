# Mia: P3 update - main entry point for Project 3
# csc6580 reverse engineering
# perlman group
# Dennis Jump
# Aaron Werth
# Joseph Cherry
# Maraz Mia
import sys

from elftools.common.exceptions import ELFError

import analyze_elf


def error(msg) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: python3 {sys.argv[0]} <path to ELF file>", file=sys.stderr)
        return 1
    filename = sys.argv[1]
    try:
        analyze_elf.analyze_elf(filename)
        return 0
    except FileNotFoundError:
        error(f"File not found ({filename})")
    except IsADirectoryError:
        error("Provided path is a directory")
    except PermissionError:
        error("Cannot read file")
    except ELFError as err:
        error(f"Invalid ELF file: {err}")
    except ValueError as err:
        error(str(err))
    except Exception as err:
        error(f"Unexpected failure: {err}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
