# main for project 2
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
    """Print an error message (to stderr, so stdout holds only the blocks)."""
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
    except Exception as err:  # keep any unexpected failure from dumping a traceback
        error(f"Unexpected failure: {err}")
    return 1


if __name__ == "__main__":
    sys.exit(main())