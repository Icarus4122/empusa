# Empusa Installation & Testing Guide

## Quick Start

### 1. Install in Development Mode (Recommended for testing)

```powershell
# Navigate to project directory
cd "c:\Users\aspar\Desktop\Personal Projects\empusa"

# Install in editable mode
pip install -e .
```

### 2. Verify Installation

```powershell
# Check version
empusa --version

# Show help
empusa --help

# Run the application
empusa
```

### 3. Test the Package

```powershell
# Test as module
python -m empusa

# Check if package is installed
pip show empusa
```

## Installation Methods Tested on Windows

### Method 1: pipx (Isolated, Recommended)

```powershell
# Install pipx if not already installed
pip install pipx
python -m pipx ensurepath

# Restart PowerShell, then install empusa
pipx install .

# Test
empusa --version
```

### Method 2: pip (System Install)

```powershell
# Install
pip install .

# Test
empusa --version

# Uninstall
pip uninstall empusa
```

### Method 3: Virtual Environment (Development)

```powershell
# Create virtual environment
python -m venv .venv

# Activate
.\.venv\Scripts\Activate.ps1

# Install in editable mode
pip install -e .

# Test
empusa --version

# Deactivate when done
deactivate
```

## Building Distribution Package

To create distributable packages:

```powershell
# Install build tools
pip install build

# Build the package
python -m build

# This creates:
# - dist/empusa-1.0.0-py3-none-any.whl
# - dist/empusa-1.0.0.tar.gz
```

## Installing from Distribution

```powershell
# Install from wheel
pip install dist/empusa-1.0.0-py3-none-any.whl

# Or from tarball
pip install dist/empusa-1.0.0.tar.gz
```

## Troubleshooting

### Issue: "empusa: command not found"

**Solution:**

```powershell
# Check if Scripts directory is in PATH
$env:Path -split ';' | Select-String -Pattern 'Scripts'

# Add Python Scripts to PATH temporarily
$env:Path += ";$env:LOCALAPPDATA\Programs\Python\Python39\Scripts"

# Or permanently add via System Properties > Environment Variables
```

### Issue: Import errors

**Solution:**

```powershell
# Reinstall with verbose output
pip install -e . -v

# Check installation
pip list | Select-String empusa
```

### Issue: "rich" module not found

**Solution:**

```powershell
# Rich should install automatically, but if not:
pip install rich>=13.0.0
```

## Verifying Features

After installation, test each feature:

1. **Check help**: `empusa --help`
2. **Check version**: `empusa --version`
3. **Run interactive menu**: `empusa`
4. **Test as module**: `python -m empusa`
5. **Check platform detection**: Should auto-detect Windows

## Publishing to PyPI (Optional)

To publish your package to PyPI:

```powershell
# Install twine
pip install twine

# Build the package
python -m build

# Upload to Test PyPI first
python -m twine upload --repository testpypi dist/*

# Then to real PyPI
python -m twine upload dist/*
```

After publishing, anyone can install with:

```powershell
pip install empusa
# or
pipx install empusa
```

## Development Workflow

```powershell
# 1. Make changes to code
# 2. Since installed with -e, changes are immediately available
# 3. Test
empusa

# 4. Commit changes
git add .
git commit -m "Your changes"
git push
```
