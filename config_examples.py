#!/usr/bin/env python3
# Example configuration file showing how to customize dllfuz.py for different DLLs

"""
To create a custom DLL fuzzer executable:

1. Copy dllfuz.py to a new file (e.g., myfuzzer.py)
2. Modify the TARGET_DLL_PATH constant
3. Optionally adjust other parameters
4. Build with PyInstaller

Example configurations:
"""

# Example 1: Fuzz kernel32.dll (Windows core API)
KERNEL32_CONFIG = {
    'TARGET_DLL_PATH': r"C:\Windows\System32\kernel32.dll",
    'WORKERS': 20,
    'TOTAL_DURATION_SEC': 7200,  # 2 hours
    'MAX_ARGS_PER_CALL': 15,
}

# Example 2: Fuzz user32.dll (Windows UI API)
USER32_CONFIG = {
    'TARGET_DLL_PATH': r"C:\Windows\System32\user32.dll",
    'WORKERS': 10,
    'TOTAL_DURATION_SEC': 3600,  # 1 hour
    'MAX_ARGS_PER_CALL': 10,
}

# Example 3: Fuzz a custom application DLL
CUSTOM_APP_CONFIG = {
    'TARGET_DLL_PATH': r"C:\Program Files\MyApp\myapp.dll",
    'WORKERS': 5,
    'TOTAL_DURATION_SEC': 1800,  # 30 minutes
    'MAX_ARGS_PER_CALL': 8,
}

# Example 4: High-intensity fuzzing configuration
HIGH_INTENSITY_CONFIG = {
    'TARGET_DLL_PATH': r"C:\Windows\System32\ntdll.dll",
    'WORKERS': 50,
    'TOTAL_DURATION_SEC': 86400,  # 24 hours
    'MAX_ARGS_PER_CALL': 30,
    'MAX_RANDOM_BUF_BYTES': 2097152,  # 2MB
}

"""
To apply a configuration:

1. Choose one of the configs above or create your own
2. Edit dllfuz.py and replace the constants at the top:

# Replace these lines in dllfuz.py:
TARGET_DLL_PATH = r"C:\Windows\System32\kernel32.dll"
WORKERS = 10
TOTAL_DURATION_SEC = 3600
MAX_ARGS_PER_CALL = 20

# With your chosen configuration, e.g.:
TARGET_DLL_PATH = r"C:\Windows\System32\user32.dll"
WORKERS = 10
TOTAL_DURATION_SEC = 3600
MAX_ARGS_PER_CALL = 10

3. Build the executable:
pyinstaller dllfuz.spec

4. The resulting executable will be hardcoded to fuzz your specific DLL.
"""

def create_custom_fuzzer(config, output_filename):
    """
    Helper function to create a customized fuzzer script.
    
    Args:
        config: Dictionary with configuration values
        output_filename: Name for the output file
    """
    
    # Read the original dllfuz.py
    with open('dllfuz.py', 'r') as f:
        content = f.read()
    
    # Replace configuration values
    for key, value in config.items():
        if isinstance(value, str):
            # String values need quotes
            old_line = f'{key} = r"'
            new_value = f'{key} = r"{value}"'
        else:
            # Numeric values don't need quotes
            old_line = f'{key} = '
            new_value = f'{key} = {value}'
        
        # Find and replace the line
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if line.strip().startswith(old_line):
                # Find the end of the current value
                if '=' in line:
                    lines[i] = new_value
                break
        content = '\n'.join(lines)
    
    # Write the customized file
    with open(output_filename, 'w') as f:
        f.write(content)
    
    print(f"Created customized fuzzer: {output_filename}")
    print(f"Configuration applied:")
    for key, value in config.items():
        print(f"  {key} = {value}")

if __name__ == "__main__":
    print("DLL Fuzzer Configuration Examples")
    print("=" * 40)
    
    configs = {
        "kernel32_fuzzer": KERNEL32_CONFIG,
        "user32_fuzzer": USER32_CONFIG,
        "custom_app_fuzzer": CUSTOM_APP_CONFIG,
        "high_intensity_fuzzer": HIGH_INTENSITY_CONFIG,
    }
    
    print("Available configurations:")
    for name, config in configs.items():
        print(f"\n{name}:")
        for key, value in config.items():
            print(f"  {key}: {value}")
    
    print("\nTo create a custom fuzzer:")
    print("1. Edit this file to modify the configurations")
    print("2. Run: python config_examples.py")
    print("3. Use the create_custom_fuzzer() function")
    print("\nExample:")
    print("create_custom_fuzzer(KERNEL32_CONFIG, 'kernel32_fuzzer.py')")