import pefile
import ctypes
import os
import random
import multiprocessing

# Define some ctypes types
ctypes_types = [ctypes.c_int, ctypes.c_float, ctypes.c_double, ctypes.c_char_p]


# Generate random ctypes type
def random_ctypes_type():
    return random.choice(ctypes_types)


# Generate a random parameter for a given ctypes type
def random_parameter(ctypes_type):
    if ctypes_type == ctypes.c_int:
        return random.randint(-9000, 9000)
    elif ctypes_type == ctypes.c_float or ctypes_type == ctypes.c_double:
        return random.uniform(-9000.0, 9000.0)
    elif ctypes_type == ctypes.c_char_p:
        return ctypes.create_string_buffer(bytes(''.join(random.choices('ABCDEFGHIJKLMNOP\\/!"`_-|><^°1234567890§$%&/()=?abcdefghijklmnopqrstuvwxyz', k=10)), 'utf-8'))
    else:
        return None


def list_exported_functions(dll_path):
    try:
        pe = pefile.PE(dll_path)
        functions = []
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            function_address = hex(pe.OPTIONAL_HEADER.ImageBase + exp.address)
            function_name = exp.name.decode('utf-8') if exp.name else None
            functions.append((function_address, function_name))
        return functions
    except Exception as e:
        print(f"Failed to list exported functions for {dll_path} with exception: {e}")
        return []


def dosomethingtodll(dll_path):
    try:
        dll = ctypes.CDLL(dll_path)
        functions = list_exported_functions(dll_path)

        for function_address, function_name in functions:
            if function_name:  # Ensure the function has a name
                try:
                    func = getattr(dll, function_name)

                    # Assign random argument types and create random arguments
                    argtypes = [random_ctypes_type() for _ in range(random.randint(1, 5))]
                    func.argtypes = argtypes
                    func.restype = random_ctypes_type()

                    # Generate random parameters for the function
                    parameters = [random_parameter(argtype) for argtype in argtypes]

                    try:
                        result = func(*parameters)
                        print(f"Function {function_name} called successfully with result: {result}")
                    except Exception as e:
                        print(f"Function {function_name} call failed with exception: {e}")

                except AttributeError as e:
                    print(f"Setting up function {function_name} failed with AttributeError: {e}")
                except Exception as e:
                    print(f"Setting up function {function_name} failed with exception: {e}")

    except Exception as e:
        print(f"Loading DLL {dll_path} failed with exception: {e}")


def process_dll_file(dll_path):
    try:
        dosomethingtodll(dll_path)
    except Exception as e:
        print(f"Processing {dll_path} failed with exception: {e}")


def main():
    pool = multiprocessing.Pool()
    for root, dirs, files in os.walk('c:\\'):
        for file in files:
            try:
                if file.lower().endswith('.dll'):
                    dll_path = os.path.join(root, file)
                    print(f"Processing {dll_path}")
                    pool.apply_async(process_dll_file, args=(dll_path,))
            except Exception as e:
                print(f"Failed to process {file} with exception: {e}")
    try:
        pool.close()
        pool.join()
    except Exception as e:
        print(f"Failed to close pool with exception: {e}")


if __name__ == "__main__":
        main()

