# Reverse Engineering — Fall 2026 Projects

This repository contains the programming assignments for CSC 6580. Each assignment is organized in its own directory (`P1`, `P2`, `P3`, etc.).

## Requirements

- Python 3.14.4 or newer
- Git
- Assignment-specific dependencies listed in `requirements.txt`

## First-Time Setup

Run these commands from the repository root.

### 1. Create the virtual environment

```bash
python3.14 -m venv .venv
```

### 2. Activate the environment

```bash
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Verify the environment

```bash
python --version
python -m pip list
```

Ensure Python is version 3.14.4 or newer.

## Running the Projects

Run the relevant assignment from the repository root. For example, to run P1:

```bash
python P1/main.py ./P1/reverse
```

Refer to each assignment's README for its purpose, usage, and verification instructions.

## Subsequent Runs

Whenever you open a new terminal, navigate to the repository root and activate the existing environment:

```bash
cd ~/Desktop/Reverse_Engineering_Fall_2026_Projects
source .venv/bin/activate
```

You do **not** need to recreate the environment or reinstall dependencies every time.

If dependencies are added or changed, update `requirements.txt` and run:

```bash
python -m pip install -r requirements.txt
```

When finished, deactivate the environment if desired:

```bash
deactivate
```

## Repository Structure

```text
Reverse_Engineering_Fall_2026_Projects/
├── .gitignore
├── requirements.txt
├── README.md
├── .venv/                 # Local environment; not committed
├── P1/
│   ├── main.py
│   ├── analyze_elf.py
│   ├── P1.md
│   └── reverse            # Example ELF executable
├── P2/
└── ...
```

The `.venv/` directory and Python cache files are excluded from Git through `.gitignore`.