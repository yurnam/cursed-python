# dllfuz.py - Single DLL Fuzzer

A focused DLL fuzzing tool that targets a specific DLL file, based on wacc.py but modified for single-DLL fuzzing and PyInstaller packaging.

## Features

- **Hardcoded DLL Path**: Configure a specific DLL to fuzz by modifying `TARGET_DLL_PATH`
- **File Dialog Fallback**: If the hardcoded DLL isn't found, opens a file selection dialog
- **Parallel Execution**: Uses multiprocessing for concurrent function execution
- **Randomized Parameters**: Generates diverse input parameters for thorough testing
- **PyInstaller Ready**: Can be packaged into a standalone executable

## Configuration

Edit the following constants in `dllfuz.py`:

```python
# CHANGE THIS PATH TO YOUR TARGET DLL
TARGET_DLL_PATH = r"C:\Windows\System32\kernel32.dll"

WORKERS = 10                          # parallel child processes
TOTAL_DURATION_SEC = 3600             # 1 hour of runtime
MAX_ARGS_PER_CALL = 20               # max arguments per function call
MAX_RANDOM_BUF_BYTES = 1048576        # 1MB max buffer size
CHILD_TIMEOUT_SEC = 2                # timeout per child process
```

## Usage

### Direct Execution
```bash
python dllfuz.py
```

### Create Executable with PyInstaller
```bash
# Install PyInstaller if not already installed
pip install pyinstaller

# Build the executable
pyinstaller dllfuz.spec

# The executable will be in dist/dllfuz.exe
```

### Running the Executable
```bash
# Run the standalone executable
dist/dllfuz.exe
```

## How It Works

1. **DLL Detection**: First tries the hardcoded `TARGET_DLL_PATH`
2. **Fallback Dialog**: If DLL not found and tkinter is available, opens file dialog
3. **Function Enumeration**: Parses the target DLL to extract exported functions
4. **Parameter Generation**: Creates randomized input parameters using various strategies
5. **Parallel Execution**: Runs multiple function calls concurrently with timeouts
6. **Continuous Fuzzing**: Repeats the process for the specified duration

## File Dialog Behavior

- **DLL Found**: Uses the hardcoded path and starts fuzzing immediately
- **DLL Not Found + GUI Available**: Opens file selection dialog
- **DLL Not Found + No GUI**: Exits with error message

## Input Generation

The fuzzer generates diverse input types including:
- Small and large integers
- Float values
- Random buffers of various sizes
- Strings and Unicode data
- Structured binary data
- Memory addresses and pointers
- File content-based data

## Safety Notes

- **Windows Only**: Requires Windows and 64-bit Python
- **System DLLs**: Be careful when fuzzing critical system DLLs
- **Crash Handling**: Uses process isolation to contain crashes
- **Timeouts**: Implements timeouts to prevent hanging

## Example Output

```
[STARTUP] Single DLL Fuzzer
[CONFIG] Target DLL: C:\Windows\System32\kernel32.dll
[CONFIG] Workers: 10, Duration: 3600s
[+] Using hardcoded DLL path: C:\Windows\System32\kernel32.dll
[ENUMERATION] Found 1521 functions in target DLL
[ENUMERATION] Sample functions: [('C:\\Windows\\System32\\kernel32.dll', 'AcquireSRWLockExclusive'), ...]
[+] Found 234 files for random data generation
[READY] Starting DLL fuzzing loop for 3600 seconds...
[RANDOMIZE] Prepared 10 parameter sets
[EXEC] Batch complete: 8/10 functions executed successfully
[PROGRESS] Cycle 10, Elapsed: 15.2s/3600s
...
```

## Dependencies

- **Python 3.6+**: 64-bit Python required for x64 DLL fuzzing
- **Windows**: Windows-specific functionality
- **dolboyob**: Included chaos module for enhanced randomization
- **tkinter**: Optional, for file dialog (usually included with Python)

## Troubleshooting

- **"Windows-only" Error**: Run on Windows system
- **"Use 64-bit Python" Error**: Install 64-bit Python
- **"No valid target DLL"**: Check DLL path or select valid DLL file
- **GUI not available**: Install tkinter or manually specify valid DLL path