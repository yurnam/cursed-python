#!/usr/bin/env python3
# Win32 UI Builder (user32.dll)
# - Creates a window + toolbar
# - Adds real Win32 controls (Button/Edit/ListBox/Static)
# - Exercise mode sends safe messages ONLY to controls you created
# - ALL logging goes to the console (no log window)

import ctypes
from ctypes import wintypes
import random
import sys

# ================== Portable Win32 types ==================
HANDLE    = ctypes.c_void_p
HWND      = HANDLE
HINSTANCE = HANDLE
HMENU     = HANDLE

LONG_PTR  = ctypes.c_ssize_t
ULONG_PTR = ctypes.c_size_t

LRESULT = LONG_PTR
WPARAM  = ULONG_PTR
LPARAM  = LONG_PTR
UINT_PTR = ctypes.c_size_t

WNDPROC = ctypes.WINFUNCTYPE(LRESULT, HWND, wintypes.UINT, WPARAM, LPARAM)

# ================== DLLs ==================
user32   = ctypes.WinDLL("user32",   use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# ================== Constants ==================
WS_OVERLAPPEDWINDOW = 0x00CF0000
WS_VISIBLE          = 0x10000000
WS_CHILD            = 0x40000000
WS_TABSTOP          = 0x00010000
WS_BORDER           = 0x00800000
WS_VSCROLL          = 0x00200000

ES_MULTILINE   = 0x0004
ES_AUTOVSCROLL = 0x0040
ES_AUTOHSCROLL = 0x0080

BS_PUSHBUTTON = 0x00000000
LBS_NOTIFY    = 0x0001

SW_SHOW = 5

SWP_NOZORDER   = 0x0004
SWP_NOACTIVATE = 0x0010

WM_CREATE  = 0x0001
WM_DESTROY = 0x0002
WM_SIZE    = 0x0005
WM_COMMAND = 0x0111
WM_TIMER   = 0x0113

BN_CLICKED = 0

BM_CLICK   = 0x00F5
WM_SETTEXT = 0x000C

LB_ADDSTRING = 0x0180
LB_GETCOUNT  = 0x018B
LB_SETCURSEL = 0x0186

EM_SETREADONLY = 0x00CF

# Toolbar IDs
ID_BTN_ADD_BUTTON  = 1001
ID_BTN_ADD_EDIT    = 1002
ID_BTN_ADD_LISTBOX = 1003
ID_BTN_ADD_STATIC  = 1004
ID_BTN_EXERCISE    = 1005

TIMER_ID = 42

# ================== Structs ==================
class WNDCLASSEXW(ctypes.Structure):
    _fields_ = [
        ("cbSize",        wintypes.UINT),
        ("style",         wintypes.UINT),
        ("lpfnWndProc",   WNDPROC),
        ("cbClsExtra",    ctypes.c_int),
        ("cbWndExtra",    ctypes.c_int),
        ("hInstance",     HINSTANCE),
        ("hIcon",         HANDLE),
        ("hCursor",       HANDLE),
        ("hbrBackground", HANDLE),
        ("lpszMenuName",  wintypes.LPCWSTR),
        ("lpszClassName", wintypes.LPCWSTR),
        ("hIconSm",       HANDLE),
    ]

class MSG(ctypes.Structure):
    _fields_ = [
        ("hwnd",    HWND),
        ("message", wintypes.UINT),
        ("wParam",  WPARAM),
        ("lParam",  LPARAM),
        ("time",    wintypes.DWORD),
        ("pt",      wintypes.POINT),
    ]

# ================== Prototypes ==================
user32.RegisterClassExW.argtypes = [ctypes.POINTER(WNDCLASSEXW)]
user32.RegisterClassExW.restype  = wintypes.ATOM

user32.CreateWindowExW.argtypes = [
    wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
    ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
    HWND, HMENU, HINSTANCE, wintypes.LPVOID
]
user32.CreateWindowExW.restype = HWND

user32.DefWindowProcW.argtypes = [HWND, wintypes.UINT, WPARAM, LPARAM]
user32.DefWindowProcW.restype  = LRESULT

user32.ShowWindow.argtypes = [HWND, ctypes.c_int]
user32.ShowWindow.restype  = wintypes.BOOL

user32.UpdateWindow.argtypes = [HWND]
user32.UpdateWindow.restype  = wintypes.BOOL

user32.GetMessageW.argtypes = [ctypes.POINTER(MSG), HWND, wintypes.UINT, wintypes.UINT]
user32.GetMessageW.restype  = ctypes.c_int

user32.TranslateMessage.argtypes = [ctypes.POINTER(MSG)]
user32.TranslateMessage.restype  = wintypes.BOOL

user32.DispatchMessageW.argtypes = [ctypes.POINTER(MSG)]
user32.DispatchMessageW.restype  = LRESULT

user32.PostQuitMessage.argtypes = [ctypes.c_int]
user32.PostQuitMessage.restype  = None

user32.SendMessageW.argtypes = [HWND, wintypes.UINT, WPARAM, LPARAM]
user32.SendMessageW.restype  = LRESULT

# allow NULL timerproc
user32.SetTimer.argtypes = [HWND, UINT_PTR, wintypes.UINT, ctypes.c_void_p]
user32.SetTimer.restype  = UINT_PTR

user32.KillTimer.argtypes = [HWND, UINT_PTR]
user32.KillTimer.restype  = wintypes.BOOL

kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
kernel32.GetModuleHandleW.restype  = HANDLE

# ================== Helpers ==================
def LOWORD(x): return x & 0xFFFF
def HIWORD(x): return (x >> 16) & 0xFFFF

def wbuf(s):
    return ctypes.create_unicode_buffer(s)

def lparam_from_buf(buf):
    return LPARAM(ctypes.cast(buf, ctypes.c_void_p).value)

# ================== UI Builder ==================
class UIBuilder:
    def __init__(self):
        self.hInstance = kernel32.GetModuleHandleW(None)
        self.class_name = "ChaosUIBuilder"
        self.hwnd = None

        self.controls = []  # (kind, hwnd, id)
        self.next_id = 2000
        self.keepalive = []

        self.exercise_enabled = False

    # ---------- logging ----------
    def log(self, msg):
        print(msg, flush=True)

    # ---------- controls ----------
    def add_control(self, kind):
        x = 20
        y = 60 + len(self.controls) * 50
        w = 220
        h = 24

        cid = self.next_id
        self.next_id += 1

        hwnd = None

        if kind == "button":
            hwnd = user32.CreateWindowExW(
                0, "BUTTON", f"Button {cid}",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                x, y, w, h,
                self.hwnd, ctypes.c_void_p(cid), self.hInstance, None
            )

        elif kind == "edit":
            hwnd = user32.CreateWindowExW(
                0, "EDIT", "",
                WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                x, y, w, h,
                self.hwnd, ctypes.c_void_p(cid), self.hInstance, None
            )

        elif kind == "listbox":
            hwnd = user32.CreateWindowExW(
                0, "LISTBOX", "",
                WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | LBS_NOTIFY,
                x, y, w, 80,
                self.hwnd, ctypes.c_void_p(cid), self.hInstance, None
            )
            for i in range(3):
                b = wbuf(f"item {i}")
                self.keepalive.append(b)
                user32.SendMessageW(hwnd, LB_ADDSTRING, 0, lparam_from_buf(b))

        elif kind == "static":
            hwnd = user32.CreateWindowExW(
                0, "STATIC", f"Static {cid}",
                WS_CHILD | WS_VISIBLE,
                x, y, w, h,
                self.hwnd, ctypes.c_void_p(cid), self.hInstance, None
            )

        self.controls.append((kind, hwnd, cid))
        self.log(f"[+] Added {kind} id={cid}")

    # ---------- exercise ----------
    def exercise_once(self):
        if not self.controls:
            return
        kind, hwnd, cid = random.choice(self.controls)

        if kind == "button":
            user32.SendMessageW(hwnd, BM_CLICK, 0, 0)
            self.log(f"[exercise] click button {cid}")

        elif kind == "edit":
            s = random.choice(["hello", "test", "data", "ÄÖÜ"])
            b = wbuf(s)
            self.keepalive.append(b)
            user32.SendMessageW(hwnd, WM_SETTEXT, 0, lparam_from_buf(b))
            self.log(f"[exercise] set edit {cid} -> {s}")

        elif kind == "listbox":
            cnt = user32.SendMessageW(hwnd, LB_GETCOUNT, 0, 0)
            if cnt:
                sel = random.randint(0, int(cnt) - 1)
                user32.SendMessageW(hwnd, LB_SETCURSEL, sel, 0)
                self.log(f"[exercise] select listbox {cid} -> {sel}")

        elif kind == "static":
            s = random.choice(["OK", "RUNNING", "✓"])
            b = wbuf(s)
            self.keepalive.append(b)
            user32.SendMessageW(hwnd, WM_SETTEXT, 0, lparam_from_buf(b))
            self.log(f"[exercise] set static {cid} -> {s}")

    # ---------- message handling ----------
    def on_command(self, wParam):
        cid = LOWORD(wParam)

        if cid == ID_BTN_ADD_BUTTON:
            self.add_control("button")
        elif cid == ID_BTN_ADD_EDIT:
            self.add_control("edit")
        elif cid == ID_BTN_ADD_LISTBOX:
            self.add_control("listbox")
        elif cid == ID_BTN_ADD_STATIC:
            self.add_control("static")
        elif cid == ID_BTN_EXERCISE:
            self.exercise_enabled = not self.exercise_enabled
            if self.exercise_enabled:
                user32.SetTimer(self.hwnd, TIMER_ID, 200, None)
                self.log("[+] Exercise ON")
            else:
                user32.KillTimer(self.hwnd, TIMER_ID)
                self.log("[+] Exercise OFF")

    # ---------- run ----------
    def run(self):
        @WNDPROC
        def WndProc(hwnd, msg, wParam, lParam):
            try:
                if msg == WM_CREATE:
                    self.hwnd = hwnd

                    x = 10
                    y = 10
                    w = 140
                    h = 26
                    gap = 8

                    def btn(text, cid):
                        nonlocal x
                        user32.CreateWindowExW(
                            0, "BUTTON", text,
                            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                            x, y, w, h,
                            hwnd, ctypes.c_void_p(cid), self.hInstance, None
                        )
                        x += w + gap

                    btn("Add Button", ID_BTN_ADD_BUTTON)
                    btn("Add Edit", ID_BTN_ADD_EDIT)
                    btn("Add ListBox", ID_BTN_ADD_LISTBOX)
                    btn("Add Static", ID_BTN_ADD_STATIC)
                    btn("Exercise", ID_BTN_EXERCISE)

                    self.log("[+] UI ready")
                    return 0

                if msg == WM_COMMAND:
                    self.on_command(int(wParam))
                    return 0

                if msg == WM_TIMER and self.exercise_enabled:
                    self.exercise_once()
                    return 0

                if msg == WM_DESTROY:
                    user32.PostQuitMessage(0)
                    return 0

                return user32.DefWindowProcW(hwnd, msg, wParam, lParam)

            except Exception as e:
                print(f"[WndProc error] {e}", file=sys.stderr)
                return user32.DefWindowProcW(hwnd, msg, wParam, lParam)

        wc = WNDCLASSEXW()
        wc.cbSize = ctypes.sizeof(WNDCLASSEXW)
        wc.lpfnWndProc = WndProc
        wc.hInstance = self.hInstance
        wc.hbrBackground = ctypes.c_void_p(6)
        wc.lpszClassName = self.class_name

        if not user32.RegisterClassExW(ctypes.byref(wc)):
            raise ctypes.WinError(ctypes.get_last_error())

        hwnd = user32.CreateWindowExW(
            0, self.class_name,
            "Win32 UI Builder (console log)",
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            100, 100, 900, 600,
            None, None, self.hInstance, None
        )

        user32.ShowWindow(hwnd, SW_SHOW)
        user32.UpdateWindow(hwnd)

        msg = MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0):
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))

# ================== main ==================
if __name__ == "__main__":
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        print("[-] Use 64-bit Python")
        sys.exit(1)

    UIBuilder().run()
