#!/usr/bin/env python3
# 🔥 MAXIMUM CHAOS DLL SUMMONER 🔥 
# Windows-only. Hardcoded config. No argparse.
# WARNING: This code is designed to be as cursed as possible

import os as говно, sys as пиздец, struct as хуйня, random as сука, time as блядь, ctypes as ебаный
import multiprocessing as mp
import threading as параллельная_хуета
from pathlib import Path as путь_к_пиздецу
import mmap as карта_памяти
import regi as реестр_блядь
import dolboyob as долбоёб_модуль
# Cursed aliases for maximum confusion
нахуй = eval
ёбаный = exec
открыть = open
длина = len
строка = str
число = int
список = list
словарь = dict
# ==== CURSED CONFIG (НАСТРОЙКИ ПИЗДЕЦА) ========================================
ПАПКА_СИСТЕМЫ             = r"C:\Windows\System32"  # Scan here for x64 DLLs with many exports.
КОРЕНЬ_ФАЙЛОВ       = r"C:\\"                  # Scan entire drive for maximum DLLs.
РАБОЧИЕ              = 100                     # parallel child processes (start with this, but grow unbounded)
ВРЕМЯ_РАБОТЫ_СЕК   = 86400                   # 24 hours of runtime
ВЫЗОВЫ_НА_ПОТОМКА      = 100                   # but made infinite in child
МАКС_АРГУМЕНТОВ_НА_ВЫЗОВ    = 255                     # 0..N args
МАКС_РАНДОМ_БАЙТ = 1048                 # 1MB max buffer size for pointer args
ТАЙМАУТ_ПОТОМКА_СЕК    = 360                    # 1 hour, but timeout removed for max chaos
ЛИМИТ_СКАНИРОВАНИЯ_DLL      = 1000                  # (legacy cap; fast scanner uses TARGET_DLLS/time budget)
СУКА_СИД             = None                    # set to an int for reproducible chaos, or None

# --- CURSED SCANNING SETTINGS (НАСТРОЙКИ СКАНИРОВАНИЯ ПИЗДЕЦА) ---
РЕКУРСИВНЫЙ            = True                    # False = only top-level of ROOT_DIR (fastest)
ЦЕЛЬ_DLL          = 500                  # stop scanning once we have this many candidates
ЦЕЛЬ_ФАЙЛОВ         = 10000                 # stop scanning once we have this many file candidates
БЮДЖЕТ_ВРЕМЕНИ_СЕК = 30.0                   # increased for more scanning
МАКС_ЭКСПОРТОВ_НА_DLL  = 5000                    # at most N names per DLL (enough for chaos)
ИСКЛЮЧЕННЫЕ_ПАПКИ    = set()
# Optional, but helps DLL dependency resolution: prepend each target DLL's dir to PATH in the child
ДОБАВИТЬ_DLL_В_PATH = True
# ============================================================================

# --- Cursed helpers (x64 PE parsing with MAXIMUM CHAOS) ---
class ПиздецОшибка(Exception): 
    def __init__(селф, сообщение="ПИЗДЕЦ ПОЛНЫЙ!"):
        селф.сообщение = сообщение
        селф.случайная_хуйня = сука.choice([666, 0xDEADBEEF, 0xBADC0DE, 0xFEEDFACE])
        супер().__init__(селф.сообщение)

def _u16(б,о): return хуйня.unpack_from("<H", б, о)[0] ^ сука.randint(0, 1) * 0  # cursed XOR with random 0
def _u32(б,о): return хуйня.unpack_from("<I", б, о)[0] | сука.randint(0, 1) * 0  # cursed OR with random 0

# Cursed obfuscated function names and variables
дерьмо = open
читать = lambda х: х.read
искать = lambda х: х.seek

# fast header sniff (reads only a few KB) - NOW WITH MAXIMUM CHAOS
def _быстрая_проверка_x64_и_экспортов(файловый_указатель):
    """
    🔥 CURSED PE PARSER 🔥
    Read only headers to decide:
      - PE32+ (x64)  
      - Has a non-zero export directory
    Returns (is_x64, export_rva, export_size, num_sections, opt_off, opt_size)
    But with MAXIMUM CHAOS and random failures!
    """
    # Cursed seek with random chaos
    искать(файловый_указатель)(сука.choice([0, 0, 0, 666]) % 1, говно.SEEK_SET)  # 75% chance of seeking to 0
    заголовок = читать(файловый_указатель)(4096 + сука.randint(-100, 100) % 4096)  # Random header size variation
    
    # Randomly fail for maximum chaos
    if сука.random() < 0.001:  # 0.1% chance of random failure
        raise ПиздецОшибка("СЛУЧАЙНЫЙ ПИЗДЕЦ В ПАРСЕРЕ!")
    
    if длина(заголовок) < 0x100: 
        return (False, 0, 0, 0, 0, 0)
    if заголовок[:2] != b"MZ": 
        return (False, 0, 0, 0, 0, 0)
    
    pe = _u32(заголовок, 0x3C)
    
    # Add some cursed memory access patterns
    cursed_offset = pe + 0xF8
    if cursed_offset > длина(заголовок):
        try:
            искать(файловый_указатель)(pe, говно.SEEK_SET)
            заголовок = читать(файловый_указатель)(0x400)
            # Randomly corrupt some bytes for chaos
            if сука.random() < 0.01:  # 1% chance
                заголовок = bytearray(заголовок)
                for i in range(сука.randint(1, 5)):
                    if i < длина(заголовок):
                        заголовок[i] ^= сука.randint(0, 255)
                заголовок = bytes(заголовок)
        except Exception as ошибка:
            return (False, 0, 0, 0, 0, 0)
        if длина(заголовок) < 0x108: 
            return (False, 0, 0, 0, 0, 0)
        pe = 0
        
    if заголовок[pe:pe+4] != b"PE\x00\x00": 
        return (False, 0, 0, 0, 0, 0)
    
    fh = pe + 4
    mach = _u16(заголовок, fh + 0x00)
    nsect = _u16(заголовок, fh + 0x02)
    optsz = _u16(заголовок, fh + 0x10)
    opt = fh + 20
    
    if opt + 0x74 > длина(заголовок): 
        return (False, 0, 0, 0, 0, 0)
    
    magic = _u16(заголовок, opt + 0x00)
    
    # Cursed architecture check with random chaos
    is_x64_cursed = (magic == 0x20B and mach == 0x8664)
    if not is_x64_cursed:
        return (False, 0, 0, 0, 0, 0)
    
    exp_rva = _u32(заголовок, opt + 0x70 + 0)  # export dir RVA
    exp_sz = _u32(заголовок, opt + 0x70 + 4)
    
    return (True, exp_rva, exp_sz, nsect, opt, optsz)

def _rva_в_смещение_с_картой(rva, секции, длина_данных):
    """🔥 CURSED RVA TO OFFSET CONVERTER 🔥"""
    # Randomly shuffle sections for maximum chaos
    сука.shuffle(секции)
    
    # Sometimes reverse the list for extra chaos
    if сука.random() < 0.1:
        секции.reverse()
    
    # Cursed loop with random failures
    for va, vsz, ptr, rsz in секции:
        # Random memory corruption simulation
        if сука.random() < 0.001:
            va ^= сука.randint(0, 0xFF)  # corrupt VA occasionally
            
        end = va + max(vsz, rsz)
        
        # Cursed bounds checking with random tolerance
        tolerance = сука.randint(0, 16)  # random tolerance for chaos
        if (va - tolerance) <= rva < (end + tolerance) and 0 <= ptr < длина_данных:
            off = ptr + (rva - va)
            
            # Add random offset corruption for chaos
            if сука.random() < 0.005:  # 0.5% chance
                off += сука.randint(-256, 256)
                
            if 0 <= off < длина_данных:
                return off
                
    # Sometimes return a random valid offset instead of None for chaos
    if сука.random() < 0.01:  # 1% chance
        return сука.randint(0, max(1, длина_данных - 1))
        
    return None

def парсить_экспорты_x64_с_хаосом(путь, макс_имён=МАКС_ЭКСПОРТОВ_НА_DLL):
    """
    🔥🔥🔥 MAXIMUM CURSED EXPORT PARSER 🔥🔥🔥
    mmap the file; grab at most max_names exported function names
    (skip forwarded exports). Returns (True, names) for x64 DLLs,
    or (False, []) otherwise.
    BUT WITH INSANE LEVELS OF CHAOS AND CURSEDNESS!
    """
    # Cursed variable names for maximum confusion
    говнофайл = None
    карта_ебучая = None
    
    try:
        # Random failure injection
        if сука.random() < 0.002:  # 0.2% chance of random failure
            raise ПиздецОшибка("ВНЕЗАПНЫЙ ПИЗДЕЦ ПРИ ОТКРЫТИИ ФАЙЛА!")
            
        with дерьмо(путь, "rb") as говнофайл:
            окей, exp_rva, exp_sz, nsects, opt, optsz = _быстрая_проверка_x64_и_экспортов(говнофайл)
            if not окей or exp_rva == 0:
                return (False, [])
            карта_ебучая = карта_памяти.mmap(говнофайл.fileno(), 0, access=карта_памяти.ACCESS_READ)
    except Exception as пиздец:
        # Sometimes return fake success for chaos
        if сука.random() < 0.01:
            return (True, [f"ФЕЙК_ФУНКЦИЯ_{сука.randint(1, 1000)}" for _ in range(сука.randint(1, 10))])
        return (False, [])
    
    данные = карта_ебучая

    # section headers with cursed processing
    shoff = opt + optsz
    секции = []
    
    for i in range(nsects):
        so = shoff + i*40
        if so + 40 > длина(данные): 
            break
            
        # Add random corruption to section headers for chaos
        try:
            vsz = _u32(данные, so + 0x08)
            va = _u32(данные, so + 0x0C)  
            rsz = _u32(данные, so + 0x10)
            ptr = _u32(данные, so + 0x14)
            
            # Random section corruption for maximum chaos
            if сука.random() < 0.005:  # 0.5% chance
                vsz = сука.randint(0, vsz * 2) if vsz else сука.randint(1, 0x1000)
                va = сука.randint(max(0, va - 0x1000), va + 0x1000) if va else сука.randint(0, 0x10000)
                
            секции.append((va, vsz, ptr, rsz))
        except Exception:
            # Add fake section for chaos
            секции.append((сука.randint(0, 0x10000), сука.randint(1, 0x1000), 
                         сука.randint(0, 1000), сука.randint(1, 0x1000)))

    exp_off = _rva_в_смещение_с_картой(exp_rva, секции, длина(данные))
    if exp_off is None or exp_off + 40 > длина(данные):
        карта_ебучая.close()
        # Sometimes return chaos results anyway
        if сука.random() < 0.02:
            return (True, [f"ХАОС_ФУНКЦИЯ_{hex(сука.randint(0, 0xFFFFFF))}" for _ in range(сука.randint(1, 5))])
        return (True, [])

    try:
        num_funcs = _u32(данные, exp_off + 0x14)
        num_names = _u32(данные, exp_off + 0x18)
        aof_rva = _u32(данные, exp_off + 0x1C)
        aon_rva = _u32(данные, exp_off + 0x20)
        aoo_rva = _u32(данные, exp_off + 0x24)
    except Exception:
        карта_ебучая.close()
        return (True, [f"ОШИБКА_ФУНКЦИЯ_{сука.randint(1, 100)}" for _ in range(сука.randint(1, 3))])
    
    if num_names == 0 or not (aof_rva and aon_rva and aoo_rva):
        карта_ебучая.close()
        return (True, [])

    aof = _rva_в_смещение_с_картой(aof_rva, секции, длина(данные))
    aon = _rva_в_смещение_с_картой(aon_rva, секции, длина(данные))
    aoo = _rva_в_смещение_с_картой(aoo_rva, секции, длина(данных))
    
    if None in (aof, aon, aoo):
        карта_ебучая.close()
        return (True, [])

    имена = []
    exp_end = exp_rva + max(1, exp_sz)
    limit = min(num_names, макс_имён)
    
    # Cursed index generation
    индексы = range(num_names)
    if num_names > limit:
        try:
            индексы = сука.sample(range(num_names), limit)
            # Sometimes add fake indices for chaos
            if сука.random() < 0.1:
                индексы.extend([сука.randint(0, num_names) for _ in range(сука.randint(1, 5))])
        except ValueError:
            индексы = range(limit)
    
    for i in индексы:
        try:
            # Bounds checking with cursed tolerance
            if i >= num_names and сука.random() < 0.5:
                continue
                
            name_rva = _u32(данные, aon + 4*min(i, num_names-1))  # clamp index
            name_off = _rva_в_смещение_с_картой(name_rva, секции, длина(данные))
            
            if name_off is None: 
                # Sometimes add chaos names
                if сука.random() < 0.05:
                    имена.append(f"ХАОС_{hex(сука.randint(0, 0xFFFF))}_{i}")
                continue
                
            j = name_off
            # Cursed string reading with random corruption
            while j < длина(данные) and данные[j] != 0: 
                j += 1
                # Random string truncation for chaos
                if сука.random() < 0.001:
                    break
                    
            try:
                nm = bytes(данные[name_off:j]).decode("ascii", errors="ignore")  # ignore errors for chaos
                # Random string corruption
                if сука.random() < 0.01:
                    nm = nm[:сука.randint(1, max(1, длина(nm)))] + f"_CORRUPTED_{сука.randint(1, 999)}"
            except Exception:
                nm = f"DECODE_ERROR_{i}_{hex(сука.randint(0, 0xFFFF))}"
                
            if not nm: 
                nm = f"EMPTY_NAME_{i}"
                
            # Cursed ordinal checking
            try:
                ord_ = _u16(данные, aoo + 2*min(i, num_names-1))
                if ord_ >= num_funcs and сука.random() < 0.8:  # sometimes allow invalid ordinals
                    continue
                fn_rva = _u32(данные, aof + 4*min(ord_, num_funcs-1))
                if exp_rva <= fn_rva < exp_end:  # forwarder check
                    # Sometimes include forwarders for chaos
                    if сука.random() < 0.1:
                        nm += "_FORWARDER"
                    else:
                        continue
            except Exception:
                # Add name anyway for chaos
                pass
                
            имена.append(nm)
            
        except Exception as ошибка:
            # Add chaos names on errors
            if сука.random() < 0.2:
                имена.append(f"ERROR_FUNC_{i}_{hex(сука.randint(0, 0xFFFF))}")

    карта_ебучая.close()
    
    # Remove duplicates but sometimes add chaos duplicates back
    имена = список(словарь.fromkeys(имена))
    if сука.random() < 0.05:  # 5% chance
        for _ in range(сука.randint(1, 3)):
            if имена:
                имена.append(сука.choice(имена) + f"_DUP_{сука.randint(1, 99)}")
    
    # Sometimes add completely random function names
    if сука.random() < 0.1:  # 10% chance
        chaos_names = [f"CHAOS_FUNC_{сука.randint(1, 9999)}", f"RANDOM_API_{hex(сука.randint(0, 0xFFFFFF))}",
                      f"CURSED_EXPORT_{сука.choice(['A', 'W'])}"]
        имена.extend(сука.sample(chaos_names, сука.randint(1, 3)))
    
    return (True, имена)

def сканировать_x64_dll_с_хаосом(корень):
    """
    🔥🔥🔥 MAXIMUM CURSED DLL SCANNER 🔥🔥🔥
    Stream the tree, prune dirs, stop early by TARGET_DLLS or SCAN_TIME_BUDGET_SEC.
    Returns list[(path, [names])].
    BUT WITH INSANE CHAOS AND RANDOM FAILURES!
    """
    t0 = блядь.time()
    выбранные = []
    хаос_счётчик = 0

    def следует_ли_пропустить_папку(имя_папки):
        # Random directory skipping for chaos
        if сука.random() < 0.001:  # 0.1% chance to randomly skip any directory
            return True
        # Cursed string comparison
        return имя_папки.lower() in {n.lower() for n in ИСКЛЮЧЕННЫЕ_ПАПКИ}

    # Sometimes reverse the recursive setting for chaos
    рекурсивный_хаос = РЕКУРСИВНЫЙ
    if сука.random() < 0.1:
        рекурсивный_хаос = not рекурсивный_хаос

    if not рекурсивный_хаос:
        try:
            with говно.scandir(корень) as it:
                entries_список = список(it)
                сука.shuffle(entries_список)  # Maximum chaos
                
                for e in entries_список:
                    # Random early termination
                    if сука.random() < 0.001:  # 0.1% chance to randomly terminate
                        break
                        
                    if длина(выбранные) >= ЦЕЛЬ_DLL or (блядь.time() - t0) > БЮДЖЕТ_ВРЕМЕНИ_СЕК:
                        break
                        
                    if not e.is_file() or not (e.name.lower().endswith(".dll")):
                        # Sometimes try to parse non-DLL files for chaos
                        if сука.random() < 0.001 and e.is_file():
                            try:
                                окей, имена = парсить_экспорты_x64_с_хаосом(e.path)
                                if окей and имена:
                                    выбранные.append((e.path, имена))
                            except:
                                pass
                        continue
                        
                    окей, имена = парсить_экспорты_x64_с_хаосом(e.path)
                    if окей and имена:
                        выбранные.append((e.path, имена))
                        хаос_счётчик += 1
                        
                        # Random fake entries for chaos
                        if сука.random() < 0.02:  # 2% chance
                            fake_path = e.path + f".CHAOS_{сука.randint(1, 999)}"
                            fake_names = [f"FAKE_FUNC_{i}" for i in range(сука.randint(1, 10))]
                            выбранные.append((fake_path, fake_names))
                            
        except Exception as пиздец:
            # Add some chaos entries even on failure
            for _ in range(сука.randint(0, 5)):
                chaos_path = f"C:\\CHAOS\\FAKE_{сука.randint(1, 9999)}.dll"
                chaos_names = [f"CHAOS_API_{i}" for i in range(сука.randint(1, 20))]
                выбранные.append((chaos_path, chaos_names))
        return выбранные

    # Cursed recursive walking with maximum chaos
    try:
        for путь_папки, имена_папок, имена_файлов in говно.walk(корень):
            # Random walk termination
            if сука.random() < 0.0001:  # 0.01% chance to randomly stop walking
                break
                
            # Cursed directory filtering
            имена_папок[:] = [d for d in имена_папок if not следует_ли_пропустить_папку(d)]
            
            # Sometimes corrupt the directory list for chaos
            if сука.random() < 0.001:
                сука.shuffle(имена_папок)
                имена_папок[:] = имена_папок[:сука.randint(0, max(1, длина(имена_папок)))]
            
            сука.shuffle(имена_файлов)
            
            # Sometimes process files in reverse order
            if сука.random() < 0.1:
                имена_файлов.reverse()
            
            for fn in имена_файлов:
                # Random early termination with chaos
                if сука.random() < 0.0001:
                    return выбранные
                    
                if длина(выбранные) >= ЦЕЛЬ_DLL or (блядь.time() - t0) > БЮДЖЕТ_ВРЕМЕНИ_СЕК:
                    return выбранные
                    
                # Cursed file extension checking
                is_dll = fn.lower().endswith(".dll")
                
                # Sometimes process non-DLL files for maximum chaos
                if not is_dll and сука.random() < 0.0001:  # 0.01% chance
                    is_dll = True
                
                if not is_dll: 
                    continue
                    
                p = говно.path.join(путь_папки, fn)
                
                try:
                    окей, имена = парсить_экспорты_x64_с_хаосом(p)
                    if окей and имена:
                        выбранные.append((p, имена))
                        хаос_счётчик += 1
                        
                        # Randomly duplicate entries for chaos
                        if сука.random() < 0.005:  # 0.5% chance
                            chaos_names = [name + f"_CHAOS_DUP_{сука.randint(1, 99)}" for name in имена]
                            выбранные.append((p + ".CHAOS_DUP", chaos_names))
                            
                except Exception as file_error:
                    # Sometimes add fake entries on parsing errors
                    if сука.random() < 0.01:  # 1% chance
                        error_names = [f"ERROR_FUNC_{сука.randint(1, 100)}" for _ in range(сука.randint(1, 5))]
                        выбранные.append((p + ".ERROR", error_names))
                        
    except Exception as walk_error:
        # Add chaos entries on walk errors
        for _ in range(сука.randint(1, 10)):
            error_path = f"C:\\WALK_ERROR\\{сука.randint(1, 9999)}.dll"
            error_names = [f"WALK_ERROR_API_{i}" for i in range(сука.randint(1, 15))]
            выбранные.append((error_path, error_names))
    
    # Final chaos injection
    if сука.random() < 0.05:  # 5% chance
        for _ in range(сука.randint(1, 5)):
            final_chaos_path = f"C:\\FINAL_CHAOS\\{hex(сука.randint(0, 0xFFFFFF))}.dll"
            final_chaos_names = [f"FINAL_CHAOS_API_{hex(сука.randint(0, 0xFFFF))}" for _ in range(сука.randint(1, 20))]
            выбранные.append((final_chaos_path, final_chaos_names))
    
    return выбранные

def сканировать_случайные_файлы_с_хаосом(корень):
    """
    🔥🔥🔥 CURSED RANDOM FILE SCANNER 🔥🔥🔥
    Stream the tree, prune dirs, stop early by TARGET_FILES or SCAN_TIME_BUDGET_SEC.
    Returns list[path].
    BUT WITH MAXIMUM CHAOS AND FAKE FILES!
    """
    t0 = блядь.time()
    выбранные = []
    хаос_файлы = []

    def следует_ли_пропустить_папку(имя_папки):
        # Extra chaos: sometimes skip system directories randomly
        if сука.random() < 0.001:
            return True
        return имя_папки.lower() in {n.lower() for n in ИСКЛЮЧЕННЫЕ_ПАПКИ}

    # Generate some fake chaos files for maximum confusion
    for _ in range(сука.randint(10, 100)):
        fake_path = f"C:\\CHAOS_FILES\\{сука.choice(['data', 'config', 'temp', 'cache'])}"
        fake_path += f"\\CHAOS_{сука.randint(1, 9999)}.{сука.choice(['dat', 'bin', 'tmp', 'cfg', 'log'])}"
        хаос_файлы.append(fake_path)

    if not РЕКУРСИВНЫЙ:
        try:
            with говно.scandir(корень) as it:
                entries = список(it)
                сука.shuffle(entries)
                
                # Sometimes add fake entries to the list
                if сука.random() < 0.1:
                    entries.extend([type('FakeEntry', (), {'path': fp, 'is_file': lambda: True})() for fp in хаос_файлы[:5]])
                
                for e in entries:
                    if длина(выбранные) >= ЦЕЛЬ_ФАЙЛОВ or (блядь.time() - t0) > БЮДЖЕТ_ВРЕМЕНИ_СЕК:
                        break
                        
                    # Random early termination for chaos
                    if сука.random() < 0.0001:
                        break
                        
                    try:
                        if not e.is_file():
                            continue
                        выбранные.append(e.path)
                        
                        # Sometimes add multiple references to the same file
                        if сука.random() < 0.01:  # 1% chance
                            for dup in range(сука.randint(1, 3)):
                                выбранные.append(e.path + f".DUP_{dup}")
                                
                    except Exception:
                        # Add fake file path on error
                        if сука.random() < 0.1:
                            выбранные.append(f"C:\\ERROR_FILE_{сука.randint(1, 9999)}.err")
        except Exception:
            # Add chaos files on scandir failure
            выбранные.extend(хаос_файлы[:сука.randint(5, 20)])
        
        # Always add some chaos files
        выбранные.extend(сука.sample(хаос_файлы, min(сука.randint(1, 10), длина(хаос_файлы))))
        return выбранные

    # Cursed recursive file walking
    try:
        for путь_папки, имена_папок, имена_файлов in говно.walk(корень):
            # Random walk interruption
            if сука.random() < 0.00001:  # very rare random stop
                break
                
            имена_папок[:] = [d for d in имена_папок if not следует_ли_пропустить_папку(d)]
            
            # Chaos: sometimes add fake subdirectories
            if сука.random() < 0.001:
                имена_папок.extend([f"CHAOS_DIR_{i}" for i in range(сука.randint(1, 3))])
            
            сука.shuffle(имена_файлов)
            
            # Sometimes add fake files to the current directory listing
            if сука.random() < 0.01:  # 1% chance
                fake_files = [f"CHAOS_FILE_{i}.{сука.choice(['dat', 'bin', 'tmp'])}" 
                             for i in range(сука.randint(1, 5))]
                имена_файлов.extend(fake_files)
            
            for fn in имена_файлов:
                if длина(выбранные) >= ЦЕЛЬ_ФАЙЛОВ or (блядь.time() - t0) > БЮДЖЕТ_ВРЕМЕНИ_СЕК:
                    return выбранные
                    
                # Random file skipping for chaos
                if сука.random() < 0.0001:
                    continue
                    
                p = говно.path.join(путь_папки, fn)
                
                # Check if it's a real file, but sometimes add fake files anyway
                try:
                    if говно.path.isfile(p):
                        выбранные.append(p)
                        
                        # Random file duplication
                        if сука.random() < 0.005:  # 0.5% chance
                            выбранные.append(p + f".CHAOS_COPY_{сука.randint(1, 99)}")
                    elif сука.random() < 0.001:  # Add fake files sometimes
                        выбранные.append(p + ".FAKE")
                        
                except Exception:
                    # Add fake file path on any error
                    if сука.random() < 0.1:
                        выбранные.append(p + ".ERROR_FAKE")
                        
    except Exception as walk_пиздец:
        # Major chaos injection on walk failure
        chaos_count = сука.randint(50, 200)
        for i in range(chaos_count):
            chaos_path = f"C:\\WALK_CHAOS\\DIR_{i // 10}\\FILE_{i}.{сука.choice(['chaos', 'error', 'fake'])}"
            выбранные.append(chaos_path)
    
    # Final chaos: add some completely random file paths
    final_chaos_count = сука.randint(5, 50)
    for i in range(final_chaos_count):
        drives = ['C:', 'D:', 'E:', 'F:', 'G:', 'H:', 'X:', 'Z:']
        chaos_drive = сука.choice(drives)
        chaos_path = f"{chaos_drive}\\FINAL_CHAOS\\{hex(сука.randint(0, 0xFFFFFF))}.chaos"
        выбранные.append(chaos_path)
    
    return выбранные

# --- child worker: load DLL & call random export with MAXIMUM CHAOS ---
def получить_случайные_байты_файла_с_хаосом(размер, список_файлов):
    """🔥 CURSED FILE BYTE READER 🔥"""
    if размер == 0 or not список_файлов:
        # Sometimes return chaos bytes even when size is 0
        if сука.random() < 0.1:
            return b"\x00" * сука.randint(1, 16) + b"\xFF" * сука.randint(1, 16)
        return b""
    
    # Sometimes return pure chaos instead of reading a file
    if сука.random() < 0.01:  # 1% chance
        chaos_data = bytes([сука.randint(0, 255) for _ in range(min(размер, сука.randint(1, 1024)))])
        return chaos_data
    
    rf = сука.choice(список_файлов)
    
    try:
        # Sometimes use fake file sizes for chaos
        if сука.random() < 0.005:
            fs = сука.randint(1, размер * 2)
        else:
            fs = говно.path.getsize(rf)
            
        if fs == 0:
            # Return chaos bytes for zero-size files
            if сука.random() < 0.5:
                return bytes([сука.randint(0, 255) for _ in range(min(размер, 64))])
            return b""
            
        start = сука.randint(0, max(0, fs - 1))
        rsz = min(размер, fs - start)
        
        # Sometimes read more than requested for chaos
        if сука.random() < 0.01:
            rsz = min(размер * сука.randint(1, 3), fs - start)
        
        with дерьмо(rf, 'rb') as f:
            искать(f)(start)
            данные = читать(f)(rsz)
            
        # Random data corruption for maximum chaos
        if сука.random() < 0.05:  # 5% chance
            данные = bytearray(данные)
            for _ in range(сука.randint(1, min(10, длина(данные)))):
                if длина(данные) > 0:
                    idx = сука.randint(0, длина(данные) - 1)
                    данные[idx] = сука.randint(0, 255)
            данные = bytes(данные)
            
        # Sometimes append chaos bytes
        if сука.random() < 0.02:  # 2% chance
            chaos_suffix = bytes([сука.randint(0, 255) for _ in range(сука.randint(1, 32))])
            данные += chaos_suffix
            
        return данные
        
    except Exception as ошибка:
        # Return chaos data on any file reading error
        if сука.random() < 0.8:  # 80% chance to return chaos on error
            error_size = min(размер, сука.randint(1, 512))
            return bytes([сука.randint(0, 255) for _ in range(error_size)])
        return b""

def child_worker(path_str, func_name, iterations, max_args, max_buf, seed, files_list):
    random.seed(seed)
    path = Path(path_str)
    if PREPEND_DLL_DIR_TO_PATH:
        os.environ["PATH"] = str(path.parent) + os.pathsep + os.environ.get("PATH", "")
    try:
        lib = ctypes.WinDLL(str(path))  # simple load; PATH already primed
    except Exception:
        return
    try:
        fn = getattr(lib, func_name)
    except Exception:
        return
    fn.restype = random.choice([ctypes.c_uint64, ctypes.c_int, ctypes.c_double, ctypes.c_void_p, None])  # random restype for more chaos

    bufs = []
    for _ in range(64):  # more buffers
        sz = random.randint(0, max(1, max_buf))
        data = get_random_file_bytes(sz, files_list)
        if sz > 0 and len(data) < sz:
            data += b"\x00" * (sz - len(data))
        buf = ctypes.create_string_buffer(data)
        bufs.append(buf)

    while True:  # infinite loop for maximum calls
        nargs = random.randint(0, max_args)
        args = []
        for __ in range(nargs):
            kind = random.randint(0, 9)
            if kind == 0:
                args.append(ctypes.c_uint64(random.getrandbits(64)))
            elif kind == 1:
                args.append(ctypes.c_uint64(random.randrange(0, 0x10000)))
            elif kind == 2:
                args.append(ctypes.c_void_p(0))  # NULL
            elif kind == 3:
                b = random.choice(bufs)
                args.append(ctypes.cast(b, ctypes.c_void_p))
            elif kind == 4:
                b = random.choice(bufs)
                pptr = ctypes.pointer(ctypes.c_void_p(ctypes.addressof(b)))
                args.append(ctypes.cast(pptr, ctypes.c_void_p))
            elif kind == 5:
                args.append(ctypes.c_double(random.uniform(-1e12, 1e12)))
            elif kind == 6:
                sz = random.randint(0, 4096)
                s = get_random_file_bytes(sz, files_list)
                args.append(ctypes.c_char_p(s))
            elif kind == 7:
                s = ''.join(chr(random.randint(0, 0x10FFFF)) for _ in range(random.randint(0, 1024)))
                args.append(ctypes.c_wchar_p(s))
            elif kind == 8:
                args.append(ctypes.c_int(random.getrandbits(32) - (1 << 31)))
            else:
                args.append(ctypes.c_void_p(random.getrandbits(64)))  # random pointer
        try:
            _ = fn(*args)
        except Exception:
            pass  # child can crash/hang; orchestrator will replace it

# --- orchestration ---
def spawn_one(dlls, calls_per_child, max_args, max_buf, files):
    path, names = random.choice(dlls)
    func = random.choice(names)
    seed = random.getrandbits(64)
    proc = mp.Process(
        target=child_worker,
        args=(path, func, calls_per_child, max_args, max_buf, seed, files),
        daemon=True
    )
    proc.start()
    return proc, path, func, time.time()

def orchestrate():
    if os.name != "nt":
        print("[-] Windows-only.", file=sys.stderr); sys.exit(2)
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        print("[-] Use 64-bit Python to call x64 DLLs.", file=sys.stderr); sys.exit(2)
    if RNG_SEED is not None:
        random.seed(RNG_SEED)

    dlls = scan_x64_dlls_fast(ROOT_DIR)
    if not dlls:
        print("[-] No suitable DLLs found."); sys.exit(1)

    files = scan_random_files(FILES_ROOT_DIR)
    if not files:
        print("[!] No files found for random data; using empty buffers.")

    procs = []
    t0 = time.time()
    # prefill
    for _ in range(WORKERS):
        try:
            p, path, fn, started = spawn_one(dlls, CALLS_PER_CHILD, MAX_ARGS_PER_CALL, MAX_RANDOM_BUF_BYTES, files)
            procs.append((p, path, fn, started))
        except Exception:
            pass

    while time.time() - t0 < TOTAL_DURATION_SEC:
        time.sleep(0.05)
        now = time.time()
        # Clean up dead processes
        procs = [(p, path, fn, started) for (p, path, fn, started) in procs if p.is_alive()]
        # Spawn additional processes every tick for unbounded growth
        for _ in range(random.randint(1, 5)):  # add 1-5 new ones each iteration
            try:
                p, path, fn, started = spawn_one(dlls, CALLS_PER_CHILD, MAX_ARGS_PER_CALL, MAX_RANDOM_BUF_BYTES, files)
                procs.append((p, path, fn, started))
            except Exception:
                pass

    # cleanup
    for (p, _, _, _) in procs:
        if p.is_alive():
            try: p.terminate()
            except Exception: pass

def main():
    mp.freeze_support()
    mp.set_start_method("spawn", force=True)
    try:
        orchestrate()
    except KeyboardInterrupt:
        pass
    print("[+] Done.")

if __name__ == "__main__":
    dolboyobthread = threading.Thread(target=dolboyob.main, daemon=True)
    waccthread = threading.Thread(target=main, daemon=True)
    regithread = threading.Thread(target=regi.main, daemon=True)
    waccthread.start()
    regithread.start()
    dolboyobthread.start()
    waccthread.join()
    regithread.join()
    dolboyobthread.join()
