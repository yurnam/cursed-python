#!/usr/bin/env python3
# Win32 Todo + Notes (ctypes / user32)
# - Toolbar buttons + ListBox todo list + Multiline Notes
# - All logging goes to console
# - Only interacts with controls we create (safe harness)

import ctypes
from ctypes import wintypes
import random
import sys
import time

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
WS_HSCROLL          = 0x00100000

ES_MULTILINE   = 0x0004
ES_AUTOVSCROLL = 0x0040
ES_AUTOHSCROLL = 0x0080
ES_WANTRETURN  = 0x1000

BS_PUSHBUTTON = 0x00000000
LBS_NOTIFY    = 0x0001

SW_SHOW = 5

WM_CREATE  = 0x0001
WM_DESTROY = 0x0002
WM_SIZE    = 0x0005
WM_COMMAND = 0x0111
WM_TIMER   = 0x0113
WM_SETTEXT = 0x000C
WM_GETTEXT = 0x000D
WM_GETTEXTLENGTH = 0x000E

BN_CLICKED = 0

LB_ADDSTRING   = 0x0180
LB_GETCOUNT    = 0x018B
LB_GETCURSEL   = 0x0188
LB_SETCURSEL   = 0x0186
LB_DELETESTRING= 0x0182
LB_GETTEXTLEN  = 0x018A
LB_GETTEXT     = 0x0189
LB_RESETCONTENT= 0x0184

EM_SETREADONLY = 0x00CF

TIMER_ID = 42

# Toolbar IDs
ID_ADD        = 1001
ID_DONE       = 1002
ID_REMOVE     = 1003
ID_CLEAR      = 1004
ID_DEMO       = 1005

# Control IDs
ID_EDIT_INPUT = 2001
ID_LIST_TODO  = 2002
ID_EDIT_NOTES = 2003

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

class RECT(ctypes.Structure):
    _fields_ = [("left", ctypes.c_long), ("top", ctypes.c_long), ("right", ctypes.c_long), ("bottom", ctypes.c_long)]

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

user32.SetTimer.argtypes = [HWND, UINT_PTR, wintypes.UINT, ctypes.c_void_p]  # NULL ok
user32.SetTimer.restype  = UINT_PTR

user32.KillTimer.argtypes = [HWND, UINT_PTR]
user32.KillTimer.restype  = wintypes.BOOL

user32.GetClientRect.argtypes = [HWND, ctypes.POINTER(RECT)]
user32.GetClientRect.restype = wintypes.BOOL

kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
kernel32.GetModuleHandleW.restype  = HANDLE

# ================== Helpers ==================
def LOWORD(x): return x & 0xFFFF

def wbuf(s: str):
    return ctypes.create_unicode_buffer(s)

def lparam_from_buf(buf):
    return LPARAM(ctypes.cast(buf, ctypes.c_void_p).value)

def get_text(hwnd: HWND) -> str:
    n = user32.SendMessageW(hwnd, WM_GETTEXTLENGTH, 0, 0)
    if n <= 0:
        return ""
    buf = ctypes.create_unicode_buffer(int(n) + 1)
    user32.SendMessageW(hwnd, WM_GETTEXT, int(n) + 1, lparam_from_buf(buf))
    return buf.value

def set_text(hwnd: HWND, s: str):
    buf = wbuf(s)
    # keepalive not needed here because SendMessage completes synchronously,
    # but keeping it in a variable makes it explicit.
    user32.SendMessageW(hwnd, WM_SETTEXT, 0, lparam_from_buf(buf))

def listbox_get_item(hwnd: HWND, idx: int) -> str:
    n = user32.SendMessageW(hwnd, LB_GETTEXTLEN, idx, 0)
    if n <= 0:
        return ""
    buf = ctypes.create_unicode_buffer(int(n) + 1)
    user32.SendMessageW(hwnd, LB_GETTEXT, idx, lparam_from_buf(buf))
    return buf.value

# ================== App ==================
class TodoApp:
    def __init__(self):
        self.hInstance = kernel32.GetModuleHandleW(None)
        self.class_name = "TodoNotesWin32"
        self.hwnd = None

        self.hEditInput = None
        self.hListTodo   = None
        self.hNotes      = None

        self.demo = False

    def log(self, msg):
        print(msg, flush=True)

    def build_ui(self, hwnd: HWND):
        # toolbar buttons
        x = 10
        y = 10
        bw = 120
        bh = 26
        gap = 8

        def btn(text, cid):
            nonlocal x
            user32.CreateWindowExW(
                0, "BUTTON", text,
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                x, y, bw, bh,
                hwnd, ctypes.c_void_p(cid), self.hInstance, None
            )
            x += bw + gap

        btn("Add", ID_ADD)
        btn("Done", ID_DONE)
        btn("Remove", ID_REMOVE)
        btn("Clear", ID_CLEAR)
        btn("Demo", ID_DEMO)

        # input edit
        self.hEditInput = user32.CreateWindowExW(
            0, "EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | WS_TABSTOP,
            10, 45, 500, 26,
            hwnd, ctypes.c_void_p(ID_EDIT_INPUT), self.hInstance, None
        )

        # listbox
        self.hListTodo = user32.CreateWindowExW(
            0, "LISTBOX", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | LBS_NOTIFY,
            10, 80, 500, 400,
            hwnd, ctypes.c_void_p(ID_LIST_TODO), self.hInstance, None
        )

        # notes
        self.hNotes = user32.CreateWindowExW(
            0, "EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | WS_HSCROLL |
            ES_MULTILINE | ES_AUTOVSCROLL | ES_WANTRETURN,
            520, 45, 350, 435,
            hwnd, ctypes.c_void_p(ID_EDIT_NOTES), self.hInstance, None
        )

        self.log("[+] Todo + Notes ready")

    def on_size(self):
        # simple resize layout
        rc = RECT()
        if not user32.GetClientRect(self.hwnd, ctypes.byref(rc)):
            return
        width  = rc.right - rc.left
        height = rc.bottom - rc.top

        # keep a 10px margin
        margin = 10
        top = 45
        toolbar_h = 35

        left_w = max(260, int(width * 0.58))
        right_w = max(220, width - left_w - margin * 3)

        # input
        user32.SetWindowPos.argtypes = [HWND, HWND, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.UINT]
        user32.SetWindowPos.restype = wintypes.BOOL

        def move(h, x, y, w, hgt):
            user32.SetWindowPos(h, None, x, y, w, hgt, 0x0004 | 0x0010)

        move(self.hEditInput, margin, top, left_w, 26)

        list_top = top + 35
        list_h = max(120, height - list_top - margin)
        move(self.hListTodo, margin, list_top, left_w, list_h)

        move(self.hNotes, margin*2 + left_w, top, right_w, height - top - margin)

    def add_item(self, text: str):
        text = text.strip()
        if not text:
            return
        buf = wbuf(text)
        user32.SendMessageW(self.hListTodo, LB_ADDSTRING, 0, lparam_from_buf(buf))
        set_text(self.hEditInput, "")
        self.log(f"[+] Added: {text}")

    def mark_done_selected(self):
        idx = user32.SendMessageW(self.hListTodo, LB_GETCURSEL, 0, 0)
        if idx < 0:
            return
        cur = listbox_get_item(self.hListTodo, int(idx))
        if cur.startswith("✅ "):
            return
        new = "✅ " + cur
        # replace by delete+insert at same index
        user32.SendMessageW(self.hListTodo, LB_DELETESTRING, idx, 0)
        buf = wbuf(new)
        user32.SendMessageW(self.hListTodo, LB_ADDSTRING, 0, lparam_from_buf(buf))
        # move selection near end (simple)
        cnt = user32.SendMessageW(self.hListTodo, LB_GETCOUNT, 0, 0)
        if cnt > 0:
            user32.SendMessageW(self.hListTodo, LB_SETCURSEL, cnt - 1, 0)
        self.log(f"[~] Done: {cur}")

    def remove_selected(self):
        idx = user32.SendMessageW(self.hListTodo, LB_GETCURSEL, 0, 0)
        if idx < 0:
            return
        cur = listbox_get_item(self.hListTodo, int(idx))
        user32.SendMessageW(self.hListTodo, LB_DELETESTRING, idx, 0)
        self.log(f"[-] Removed: {cur}")

    def clear_all(self):
        user32.SendMessageW(self.hListTodo, LB_RESETCONTENT, 0, 0)
        self.log("[!] Cleared todo list")

    def toggle_demo(self):
        self.demo = not self.demo
        if self.demo:
            user32.SetTimer(self.hwnd, TIMER_ID, 250, None)
            self.log("[+] Demo ON")
        else:
            user32.KillTimer(self.hwnd, TIMER_ID)
            self.log("[+] Demo OFF")

    def demo_tick(self):
        # only touches our own controls
        actions = ["add", "done", "remove"]
        a = random.choice(actions)

        if a == "add":
            samples = [
                "check logs", "ship PCs", "order SSDs", "call supplier", "clean bench",
                "write report", "test drivers", "push build", "verify BIOS"
            ]
            self.add_item(random.choice(samples))
        elif a == "done":
            self.mark_done_selected()
        elif a == "remove":
            self.remove_selected()

    def on_command(self, wParam):
        cid = LOWORD(wParam)
        if cid == ID_ADD:
            self.add_item(get_text(self.hEditInput))
        elif cid == ID_DONE:
            self.mark_done_selected()
        elif cid == ID_REMOVE:
            self.remove_selected()
        elif cid == ID_CLEAR:
            self.clear_all()
        elif cid == ID_DEMO:
            self.toggle_demo()

    def run(self):
        @WNDPROC
        def WndProc(hwnd, msg, wParam, lParam):
            try:
                if msg == WM_CREATE:
                    self.hwnd = hwnd
                    self.build_ui(hwnd)
                    return 0
                if msg == WM_SIZE:
                    if self.hEditInput and self.hListTodo and self.hNotes:
                        self.on_size()
                    return 0
                if msg == WM_COMMAND:
                    self.on_command(int(wParam))
                    return 0
                if msg == WM_TIMER and self.demo:
                    self.demo_tick()
                    return 0
                if msg == WM_DESTROY:
                    try:
                        user32.KillTimer(hwnd, TIMER_ID)
                    except:
                        pass
                    user32.PostQuitMessage(0)
                    return 0
                return user32.DefWindowProcW(hwnd, msg, wParam, lParam)
            except Exception as e:
                print(f"[WndProc error] {e}", file=sys.stderr, flush=True)
                return user32.DefWindowProcW(hwnd, msg, wParam, lParam)

        wc = WNDCLASSEXW()
        wc.cbSize = ctypes.sizeof(WNDCLASSEXW)
        wc.lpfnWndProc = WndProc
        wc.hInstance = self.hInstance
        wc.hbrBackground = ctypes.c_void_p(6)  # COLOR_WINDOW+1 is 6 typically
        wc.lpszClassName = self.class_name

        if not user32.RegisterClassExW(ctypes.byref(wc)):
            raise ctypes.WinError(ctypes.get_last_error())

        hwnd = user32.CreateWindowExW(
            0, self.class_name, "Todo + Notes (Win32 ctypes)",
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            100, 100, 950, 620,
            None, None, self.hInstance, None
        )
        if not hwnd:
            raise ctypes.WinError(ctypes.get_last_error())

        user32.ShowWindow(hwnd, SW_SHOW)
        user32.UpdateWindow(hwnd)

        msg = MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0):
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))

# ================== main ==================
if __name__ == "__main__":
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        print("[-] Use 64-bit Python", flush=True)
        sys.exit(1)

    TodoApp().run()
