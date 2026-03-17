#!/usr/bin/env python3
# User32 DLL Safe Fuzzer - fuzzes user32.dll with only non-destructive functions
#
# Features:
# - Hardcoded to user32.dll
# - Uses provided function list, filters out potentially destructive functions (e.g., Set*, Destroy*, Close*, etc.)
# - Workers load DLL once and execute many safe functions
# - Parent respawns crashed workers
# - Uses safe, non-modifying fuzz inputs where possible

import os
import sys
import struct
import random
import time
import ctypes
import multiprocessing as mp
from pathlib import Path
import mmap

# ==== HARD-CODED CONFIG ========================================
DLL_PATH = r"C:\Windows\System32\user32.dll"  # Hardcoded user32.dll
WORKERS = 109  # parallel processes for function execution
TOTAL_DURATION_SEC = 36009  # 1 hour of runtime
MAX_ARGS_PER_CALL = 10  # 0..N args
MAX_RANDOM_BUF_BYTES = 148576  # 1MB max buffer size for pointer args
RNG_SEED = None  # set to an int for reproducible chaos, or None
WORKER_TIMEOUT_SEC = 5  # timeout to check and respawn workers

# --- TIMING CONTROLS ---
SHUFFLE_INTERVAL_SEC = 3  # shuffle function array every 12 seconds
RANDOMIZE_INTERVAL_SEC = 2  # re-randomize parameter data every 13 seconds
EXECUTION_BATCH_SIZE = 4  # preferred batch size (but not required)

# Optional, but helps DLL dependency resolution: prepend DLL's dir to PATH
PREPEND_DLL_DIR_TO_PATH = True

# Provided function list from user32.dll
ALL_FUNCTIONS = [
    "ActivateKeyboardLayout", "AddClipboardFormatListener", "AddVisualIdentifier", "AdjustWindowRect",
    "AdjustWindowRectEx", "AdjustWindowRectExForDpi", "AlignRects", "AllowForegroundActivation",
    "AllowSetForegroundWindow", "AnimateWindow", "AnyPopup", "AppendMenuA", "AppendMenuW",
    "AreDpiAwarenessContextsEqual", "ArrangeIconicWindows", "AttachThreadInput", "BeginDeferWindowPos",
    "BeginPaint", "BlockInput", "BringWindowToTop", "BroadcastSystemMessage", "BroadcastSystemMessageA",
    "BroadcastSystemMessageExA", "BroadcastSystemMessageExW", "BroadcastSystemMessageW", "BuildReasonArray",
    "CalcMenuBar", "CalculatePopupWindowPosition", "CallMsgFilter", "CallMsgFilterA", "CallMsgFilterW",
    "CallNextHookEx", "CallWindowProcA", "CallWindowProcW", "CancelShutdown", "CascadeChildWindows",
    "CascadeWindows", "ChangeClipboardChain", "ChangeDisplaySettingsA", "ChangeDisplaySettingsExA",
    "ChangeDisplaySettingsExW", "ChangeDisplaySettingsW", "ChangeMenuA", "ChangeMenuW",
    "ChangeWindowMessageFilter", "ChangeWindowMessageFilterEx", "CharLowerA", "CharLowerBuffA",
    "CharLowerBuffW", "CharLowerW", "CharNextA", "CharNextExA", "CharNextW", "CharPrevA", "CharPrevExA",
    "CharPrevW", "CharToOemA", "CharToOemBuffA", "CharToOemBuffW", "CharToOemW", "CharUpperA",
    "CharUpperBuffA", "CharUpperBuffW", "CharUpperW", "CheckBannedOneCoreTransformApi", "CheckDBCSEnabledExt",
    "CheckDlgButton", "CheckMenuItem", "CheckMenuRadioItem", "CheckProcessForClipboardAccess",
    "CheckProcessSession", "CheckRadioButton", "CheckWindowThreadDesktop", "ChildWindowFromPoint",
    "ChildWindowFromPointEx", "CliImmSetHotKey", "ClientThreadSetup", "ClientToScreen", "ClipCursor",
    "CloseClipboard", "CloseDesktop", "CloseGestureInfoHandle", "CloseTouchInputHandle", "CloseWindow",
    "CloseWindowStation", "ConsoleControl", "ControlMagnification", "CopyAcceleratorTableA",
    "CopyAcceleratorTableW", "CopyIcon", "CopyImage", "CopyRect", "CountClipboardFormats",
    "CreateAcceleratorTableA", "CreateAcceleratorTableW", "CreateCaret", "CreateCursor",
    "CreateDCompositionHwndTarget", "CreateDesktopA", "CreateDesktopExA", "CreateDesktopExW",
    "CreateDesktopW", "CreateDialogIndirectParamA", "CreateDialogIndirectParamAorW",
    "CreateDialogIndirectParamW", "CreateDialogParamA", "CreateDialogParamW", "CreateIcon",
    "CreateIconFromResource", "CreateIconFromResourceEx", "CreateIconIndirect", "CreateMDIWindowA",
    "CreateMDIWindowW", "CreateMenu", "CreatePopupMenu", "CreateSyntheticPointerDevice",
    "CreateSystemThreads", "CreateWindowExA", "CreateWindowExW", "CreateWindowInBand",
    "CreateWindowInBandEx", "CreateWindowIndirect", "CreateWindowStationA", "CreateWindowStationW",
    "CsrBroadcastSystemMessageExW", "CtxInitUser32", "DdeAbandonTransaction", "DdeAccessData",
    "DdeAddData", "DdeClientTransaction", "DdeCmpStringHandles", "DdeConnect", "DdeConnectList",
    "DdeCreateDataHandle", "DdeCreateStringHandleA", "DdeCreateStringHandleW", "DdeDisconnect",
    "DdeDisconnectList", "DdeEnableCallback", "DdeFreeDataHandle", "DdeFreeStringHandle",
    "DdeGetData", "DdeGetLastError", "DdeGetQualityOfService", "DdeImpersonateClient",
    "DdeInitializeA", "DdeInitializeW", "DdeKeepStringHandle", "DdeNameService", "DdePostAdvise",
    "DdeQueryConvInfo", "DdeQueryNextServer", "DdeQueryStringA", "DdeQueryStringW", "DdeReconnect",
    "DdeSetQualityOfService", "DdeSetUserHandle", "DdeUnaccessData", "DdeUninitialize",
    "DefDlgProcA", "DefDlgProcW", "DefFrameProcA", "DefFrameProcW", "DefMDIChildProcA",
    "DefMDIChildProcW", "DefRawInputProc", "DefWindowProcA", "DefWindowProcW", "DeferWindowPos",
    "DeferWindowPosAndBand", "DelegateInput", "DeleteMenu", "DeregisterShellHookWindow",
    "DestroyAcceleratorTable", "DestroyCaret", "DestroyCursor", "DestroyDCompositionHwndTarget",
    "DestroyIcon", "DestroyMenu", "DestroyReasons", "DestroySyntheticPointerDevice", "DestroyWindow",
    "DialogBoxIndirectParamA", "DialogBoxIndirectParamAorW", "DialogBoxIndirectParamW",
    "DialogBoxParamA", "DialogBoxParamW", "DisableProcessWindowsGhosting", "DispatchMessageA",
    "DispatchMessageW", "DisplayConfigGetDeviceInfo", "DisplayConfigSetDeviceInfo", "DisplayExitWindowsWarnings",
    "DlgDirListA", "DlgDirListComboBoxA", "DlgDirListComboBoxW", "DlgDirListW", "DlgDirSelectComboBoxExA",
    "DlgDirSelectComboBoxExW", "DlgDirSelectExA", "DlgDirSelectExW", "DoSoundConnect", "DoSoundDisconnect",
    "DragDetect", "DragObject", "DrawAnimatedRects", "DrawCaption", "DrawCaptionTempA", "DrawCaptionTempW",
    "DrawEdge", "DrawFocusRect", "DrawFrame", "DrawFrameControl", "DrawIcon", "DrawIconEx", "DrawMenuBar",
    "DrawMenuBarTemp", "DrawStateA", "DrawStateW", "DrawTextA", "DrawTextExA", "DrawTextExW", "DrawTextW",
    "DwmGetDxRgn", "DwmGetDxSharedSurface", "DwmGetRemoteSessionOcclusionEvent",
    "DwmGetRemoteSessionOcclusionState", "DwmKernelShutdown", "DwmKernelStartup", "DwmLockScreenUpdates",
    "DwmValidateWindow", "EditWndProc", "EmptyClipboard", "EnableMenuItem", "EnableMouseInPointer",
    "EnableNonClientDpiScaling", "EnableOneCoreTransformMode", "EnableScrollBar",
    "EnableSessionForMMCSS", "EnableWindow", "EndDeferWindowPos", "EndDeferWindowPosEx", "EndDialog",
    "EndMenu", "EndPaint", "EndTask", "EnterReaderModeHelper", "EnumChildWindows", "EnumClipboardFormats",
    "EnumDesktopWindows", "EnumDesktopsA", "EnumDesktopsW", "EnumDisplayDevicesA", "EnumDisplayDevicesW",
    "EnumDisplayMonitors", "EnumDisplaySettingsA", "EnumDisplaySettingsExA", "EnumDisplaySettingsExW",
    "EnumDisplaySettingsW", "EnumPropsA", "EnumPropsExA", "EnumPropsExW", "EnumPropsW", "EnumThreadWindows",
    "EnumWindowStationsA", "EnumWindowStationsW", "EnumWindows", "EqualRect", "EvaluateProximityToPolygon",
    "EvaluateProximityToRect", "ExcludeUpdateRgn", "ExitWindowsEx", "FillRect", "FindWindowA",
    "FindWindowExA", "FindWindowExW", "FindWindowW", "FlashWindow", "FlashWindowEx", "FrameRect",
    "FreeDDElParam", "FrostCrashedWindow", "GetActiveWindow", "GetAltTabInfo", "GetAltTabInfoA",
    "GetAltTabInfoW", "GetAncestor", "GetAppCompatFlags", "GetAppCompatFlags2", "GetAsyncKeyState",
    "GetAutoRotationState", "GetCIMSSM", "GetCapture", "GetCaretBlinkTime", "GetCaretPos", "GetClassInfoA",
    "GetClassInfoExA", "GetClassInfoExW", "GetClassInfoW", "GetClassLongA", "GetClassLongPtrA",
    "GetClassLongPtrW", "GetClassLongW", "GetClassNameA", "GetClassNameW", "GetClassWord", "GetClientRect",
    "GetClipCursor", "GetClipboardAccessToken", "GetClipboardData", "GetClipboardFormatNameA",
    "GetClipboardFormatNameW", "GetClipboardOwner", "GetClipboardSequenceNumber", "GetClipboardViewer",
    "GetComboBoxInfo", "GetCurrentInputMessageSource", "GetCursor", "GetCursorFrameInfo", "GetCursorInfo",
    "GetCursorPos", "GetDC", "GetDCEx", "GetDesktopID", "GetDesktopWindow", "GetDialogBaseUnits",
    "GetDialogControlDpiChangeBehavior", "GetDialogDpiChangeBehavior", "GetDisplayAutoRotationPreferences",
    "GetDisplayConfigBufferSizes", "GetDlgCtrlID", "GetDlgItem", "GetDlgItemInt", "GetDlgItemTextA",
    "GetDlgItemTextW", "GetDoubleClickTime", "GetDpiAwarenessContextForProcess", "GetDpiForMonitorInternal",
    "GetDpiForSystem", "GetDpiForWindow", "GetDpiFromDpiAwarenessContext", "GetExtendedPointerDeviceProperty",
    "GetFocus", "GetForegroundWindow", "GetGUIThreadInfo", "GetGestureConfig", "GetGestureExtraArgs",
    "GetGestureInfo", "GetGuiResources", "GetIconInfo", "GetIconInfoExA", "GetIconInfoExW",
    "GetInputDesktop", "GetInputLocaleInfo", "GetInputState", "GetInternalWindowPos", "GetKBCodePage",
    "GetKeyNameTextA", "GetKeyNameTextW", "GetKeyState", "GetKeyboardLayout", "GetKeyboardLayoutList",
    "GetKeyboardLayoutNameA", "GetKeyboardLayoutNameW", "GetKeyboardState", "GetKeyboardType",
    "GetLastActivePopup", "GetLastInputInfo", "GetLayeredWindowAttributes", "GetListBoxInfo",
    "GetMagnificationDesktopColorEffect", "GetMagnificationDesktopMagnification",
    "GetMagnificationDesktopSamplingMode", "GetMagnificationLensCtxInformation", "GetMenu",
    "GetMenuBarInfo", "GetMenuCheckMarkDimensions", "GetMenuContextHelpId", "GetMenuDefaultItem",
    "GetMenuInfo", "GetMenuItemCount", "GetMenuItemID", "GetMenuItemInfoA", "GetMenuItemInfoW",
    "GetMenuItemRect", "GetMenuState", "GetMenuStringA", "GetMenuStringW", "GetMessageA",
    "GetMessageExtraInfo", "GetMessagePos", "GetMessageTime", "GetMessageW", "GetMonitorInfoA",
    "GetMonitorInfoW", "GetMouseMovePointsEx", "GetNextDlgGroupItem", "GetNextDlgTabItem",
    "GetOpenClipboardWindow", "GetParent", "GetPhysicalCursorPos", "GetPointerCursorId",
    "GetPointerDevice", "GetPointerDeviceCursors", "GetPointerDeviceInputSpace",
    "GetPointerDeviceOrientation", "GetPointerDeviceProperties", "GetPointerDeviceRects",
    "GetPointerDevices", "GetPointerFrameArrivalTimes", "GetPointerFrameInfo",
    "GetPointerFrameInfoHistory", "GetPointerFramePenInfo", "GetPointerFramePenInfoHistory",
    "GetPointerFrameTimes", "GetPointerFrameTouchInfo", "GetPointerFrameTouchInfoHistory",
    "GetPointerInfo", "GetPointerInfoHistory", "GetPointerInputTransform", "GetPointerPenInfo",
    "GetPointerPenInfoHistory", "GetPointerTouchInfo", "GetPointerTouchInfoHistory", "GetPointerType",
    "GetPriorityClipboardFormat", "GetProcessDefaultLayout", "GetProcessDpiAwarenessInternal",
    "GetProcessUIContextInformation", "GetProcessWindowStation", "GetProgmanWindow", "GetPropA",
    "GetPropW", "GetQueueStatus", "GetRawInputBuffer", "GetRawInputData", "GetRawInputDeviceInfoA",
    "GetRawInputDeviceInfoW", "GetRawInputDeviceList", "GetRawPointerDeviceData",
    "GetRegisteredRawInputDevices", "GetScrollBarInfo", "GetScrollInfo", "GetScrollPos",
    "GetScrollRange", "GetSendMessageReceiver", "GetShellChangeNotifyWindow", "GetShellWindow",
    "GetSubMenu", "GetSysColor", "GetSysColorBrush", "GetSystemDpiForProcess", "GetSystemMenu",
    "GetSystemMetrics", "GetSystemMetricsForDpi", "GetTabbedTextExtentA", "GetTabbedTextExtentW",
    "GetTaskmanWindow", "GetThreadDesktop", "GetThreadDpiAwarenessContext",
    "GetThreadDpiHostingBehavior", "GetTitleBarInfo", "GetTopLevelWindow", "GetTopWindow",
    "GetTouchInputInfo", "GetUnpredictedMessagePos", "GetUpdateRect", "GetUpdateRgn",
    "GetUpdatedClipboardFormats", "GetUserObjectInformationA", "GetUserObjectInformationW",
    "GetWinStationInfo", "GetWindow", "GetWindowBand", "GetWindowCompositionAttribute",
    "GetWindowCompositionInfo", "GetWindowContextHelpId", "GetWindowDC", "GetWindowDisplayAffinity",
    "GetWindowDpiAwarenessContext", "GetWindowDpiHostingBehavior", "GetWindowFeedbackSetting",
    "GetWindowInfo", "GetWindowLongA", "GetWindowLongPtrA", "GetWindowLongPtrW", "GetWindowLongW",
    "GetWindowMinimizeRect", "GetWindowModuleFileName", "GetWindowModuleFileNameA",
    "GetWindowModuleFileNameW", "GetWindowPlacement", "GetWindowProcessHandle", "GetWindowRect",
    "GetWindowRgn", "GetWindowRgnBox", "GetWindowRgnEx", "GetWindowTextA", "GetWindowTextLengthA",
    "GetWindowTextLengthW", "GetWindowTextW", "GetWindowThreadProcessId", "GetWindowWord",
    "GrayStringA", "GrayStringW", "HandleDelegatedInput", "HideCaret", "HiliteMenuItem",
    "HungWindowFromGhostWindow", "IMPGetIMEA", "IMPGetIMEW", "IMPQueryIMEA", "IMPQueryIMEW",
    "IMPSetIMEA", "IMPSetIMEW", "ImpersonateDdeClientWindow", "InSendMessage", "InSendMessageEx",
    "InflateRect", "InheritWindowMonitor", "InitDManipHook", "InitializeGenericHidInjection",
    "InitializeInputDeviceInjection", "InitializeLpkHooks", "InitializePointerDeviceInjection",
    "InitializePointerDeviceInjectionEx", "InitializeTouchInjection", "InputSpaceRegionFromPoint",
    "InsertMenuA", "InsertMenuItemA", "InsertMenuItemW", "InsertMenuW", "InternalGetWindowIcon",
    "InternalGetWindowText", "IntersectRect", "InvalidateRect", "InvalidateRgn", "InvertRect",
    "IsCharAlphaA", "IsCharAlphaNumericA", "IsCharAlphaNumericW", "IsCharAlphaW", "IsCharLowerA",
    "IsCharLowerW", "IsCharUpperA", "IsCharUpperW", "IsChild", "IsClipboardFormatAvailable",
    "IsDialogMessage", "IsDialogMessageA", "IsDialogMessageW", "IsDlgButtonChecked", "IsGUIThread",
    "IsHungAppWindow", "IsIconic", "IsImmersiveProcess", "IsInDesktopWindowBand", "IsMenu",
    "IsMouseInPointerEnabled", "IsOneCoreTransformMode", "IsProcessDPIAware", "IsQueueAttached",
    "IsRectEmpty", "IsSETEnabled", "IsServerSideWindow", "IsThreadDesktopComposited",
    "IsThreadMessageQueueAttached", "IsThreadTSFEventAware", "IsTopLevelWindow", "IsTouchWindow",
    "IsValidDpiAwarenessContext", "IsWinEventHookInstalled", "IsWindow", "IsWindowArranged",
    "IsWindowEnabled", "IsWindowInDestroy", "IsWindowRedirectedForPrint", "IsWindowUnicode",
    "IsWindowVisible", "IsWow64Message", "IsZoomed", "keybd_event", "LoadAcceleratorsA",
    "LoadAcceleratorsW", "LoadBitmapA", "LoadBitmapW", "LoadCursorA", "LoadCursorFromFileA",
    "LoadCursorFromFileW", "LoadCursorW", "LoadIconA", "LoadIconW", "LoadImageA", "LoadImageW",
    "LoadKeyboardLayoutA", "LoadKeyboardLayoutEx", "LoadKeyboardLayoutW", "LoadLocalFonts",
    "LoadMenuA", "LoadMenuIndirectA", "LoadMenuIndirectW", "LoadMenuW", "LoadStringA", "LoadStringW",
    "LogicalToPhysicalPoint", "LogicalToPhysicalPointForPerMonitorDPI", "LookupIconIdFromDirectory",
    "LookupIconIdFromDirectoryEx", "MBToWCSEx", "MBToWCSExt", "MB_GetString", "MITGetCursorUpdateHandle",
    "MITSetForegroundRoutingInfo", "MITSetInputDelegationMode", "MITSetLastInputRecipient",
    "MITSynthesizeTouchInput", "MapDialogRect", "MapPointsByVisualIdentifier", "MapVirtualKeyA",
    "MapVirtualKeyExA", "MapVirtualKeyExW", "MapVirtualKeyW", "MapVisualRelativePoints",
    "MapWindowPoints", "MenuItemFromPoint", "MenuWindowProcA", "MenuWindowProcW", "MessageBeep",
    "MessageBoxA", "MessageBoxExA", "MessageBoxExW", "MessageBoxIndirectA", "MessageBoxIndirectW",
    "MessageBoxTimeoutA", "MessageBoxTimeoutW", "MessageBoxW", "ModifyMenuA", "ModifyMenuW",
    "MonitorFromPoint", "MonitorFromRect", "MonitorFromWindow", "MoveWindow", "MsgWaitForMultipleObjects",
    "MsgWaitForMultipleObjectsEx", "NotifyOverlayWindow", "NotifyWinEvent", "OemKeyScan", "OemToCharA",
    "OemToCharBuffA", "OemToCharBuffW", "OemToCharW", "OffsetRect", "OpenClipboard", "OpenDesktopA",
    "OpenDesktopW", "OpenIcon", "OpenInputDesktop", "OpenWindowStationA", "OpenWindowStationW",
    "PackDDElParam", "PackTouchHitTestingProximityEvaluation", "PaintDesktop", "PaintMenuBar",
    "PaintMonitor", "PeekMessageA", "PeekMessageW", "PhysicalToLogicalPoint",
    "PhysicalToLogicalPointForPerMonitorDPI", "PostMessageA", "PostMessageW", "PostQuitMessage",
    "PostThreadMessageA", "PostThreadMessageW", "PrintWindow", "PrivateExtractIconExA",
    "PrivateExtractIconExW", "PrivateExtractIconsA", "PrivateExtractIconsW", "PrivateRegisterICSProc",
    "PtInRect", "QueryBSDRWindow", "QueryDisplayConfig", "QuerySendMessage", "RIMAddInputObserver",
    "RIMAreSiblingDevices", "RIMDeviceIoControl", "RIMEnableMonitorMappingForDevice",
    "RIMFreeInputBuffer", "RIMGetDevicePreparsedData", "RIMGetDevicePreparsedDataLockfree",
    "RIMGetDeviceProperties", "RIMGetDevicePropertiesLockfree", "RIMGetPhysicalDeviceRect",
    "RIMGetSourceProcessId", "RIMObserveNextInput", "RIMOnPnpNotification", "RIMOnTimerNotification",
    "RIMQueryDevicePath", "RIMReadInput", "RIMRegisterForInput", "RIMRemoveInputObserver",
    "RIMSetExtendedDeviceProperty", "RIMSetTestModeStatus", "RIMUnregisterForInput",
    "RIMUpdateInputObserverRegistration", "RealChildWindowFromPoint", "RealGetWindowClass",
    "RealGetWindowClassA", "RealGetWindowClassW", "ReasonCodeNeedsBugID", "ReasonCodeNeedsComment",
    "RecordShutdownReason", "RedrawWindow", "RegisterBSDRWindow", "RegisterClassA", "RegisterClassExA",
    "RegisterClassExW", "RegisterClassW", "RegisterClipboardFormatA", "RegisterClipboardFormatW",
    "RegisterDManipHook", "RegisterDeviceNotificationA", "RegisterDeviceNotificationW",
    "RegisterErrorReportingDialog", "RegisterFrostWindow", "RegisterGhostWindow", "RegisterHotKey",
    "RegisterLogonProcess", "RegisterMessagePumpHook", "RegisterPointerDeviceNotifications",
    "RegisterPointerInputTarget", "RegisterPointerInputTargetEx", "RegisterPowerSettingNotification",
    "RegisterRawInputDevices", "RegisterServicesProcess", "RegisterSessionPort", "RegisterShellHookWindow",
    "RegisterSuspendResumeNotification", "RegisterSystemThread", "RegisterTasklist",
    "RegisterTouchHitTestingWindow", "RegisterTouchWindow", "RegisterUserApiHook",
    "RegisterWindowMessageA", "RegisterWindowMessageW", "ReleaseCapture", "ReleaseDC", "ReleaseDwmHitTestWaiters",
    "RemoveClipboardFormatListener", "RemoveInjectionDevice", "RemoveMenu", "RemovePropA", "RemovePropW",
    "RemoveThreadTSFEventAwareness", "RemoveVisualIdentifier", "ReplyMessage", "ReportInertia",
    "ResolveDesktopForWOW", "ReuseDDElParam", "ScreenToClient", "ScrollChildren", "ScrollDC",
    "ScrollWindow", "ScrollWindowEx", "SendDlgItemMessageA", "SendDlgItemMessageW", "SendIMEMessageExA",
    "SendIMEMessageExW", "SendInput", "SendMessageA", "SendMessageCallbackA", "SendMessageCallbackW",
    "SendMessageTimeoutA", "SendMessageTimeoutW", "SendMessageW", "SendNotifyMessageA",
    "SendNotifyMessageW", "SetActiveWindow", "SetCapture", "SetCaretBlinkTime", "SetCaretPos",
    "SetClassLongA", "SetClassLongPtrA", "SetClassLongPtrW", "SetClassLongW", "SetClassWord",
    "SetClipboardData", "SetClipboardViewer", "SetCoalescableTimer", "SetCoreWindow", "SetCursor",
    "SetCursorContents", "SetCursorPos", "SetDebugErrorLevel", "SetDeskWallpaper",
    "SetDesktopColorTransform", "SetDialogControlDpiChangeBehavior", "SetDialogDpiChangeBehavior",
    "SetDisplayAutoRotationPreferences", "SetDisplayConfig", "SetDlgItemInt", "SetDlgItemTextA",
    "SetDlgItemTextW", "SetDoubleClickTime", "SetFeatureReportResponse", "SetFocus",
    "SetForegroundWindow", "SetFullscreenMagnifierOffsetsDWMUpdated", "SetGestureConfig",
    "SetInternalWindowPos", "SetKeyboardState", "SetLastErrorEx", "SetLayeredWindowAttributes",
    "SetMagnificationDesktopColorEffect", "SetMagnificationDesktopMagnification",
    "SetMagnificationDesktopMagnifierOffsetsDWMUpdated", "SetMagnificationDesktopSamplingMode",
    "SetMagnificationLensCtxInformation", "SetMenu", "SetMenuContextHelpId", "SetMenuDefaultItem",
    "SetMenuInfo", "SetMenuItemBitmaps", "SetMenuItemInfoA", "SetMenuItemInfoW", "SetMessageExtraInfo",
    "SetMessageQueue", "SetMirrorRendering", "SetParent", "SetPhysicalCursorPos",
    "SetPointerDeviceInputSpace", "SetProcessDPIAware", "SetProcessDefaultLayout",
    "SetProcessDpiAwarenessContext", "SetProcessDpiAwarenessInternal", "SetProcessRestrictionExemption",
    "SetProcessWindowStation", "SetProgmanWindow", "SetPropA", "SetPropW", "SetRect", "SetRectEmpty",
    "SetScrollInfo", "SetScrollPos", "SetScrollRange", "SetShellChangeNotifyWindow", "SetShellWindow",
    "SetShellWindowEx", "SetSysColors", "SetSysColorsTemp", "SetSystemCursor", "SetSystemMenu",
    "SetTaskmanWindow", "SetThreadDesktop", "SetThreadDpiAwarenessContext", "SetThreadDpiHostingBehavior",
    "SetThreadInputBlocked", "SetTimer", "SetUserObjectInformationA", "SetUserObjectInformationW",
    "SetWinEventHook", "SetWindowBand", "SetWindowCompositionAttribute", "SetWindowCompositionTransition",
    "SetWindowContextHelpId", "SetWindowDisplayAffinity", "SetWindowFeedbackSetting",
    "SetWindowLongA", "SetWindowLongPtrA", "SetWindowLongPtrW", "SetWindowLongW", "SetWindowPlacement",
    "SetWindowPos", "SetWindowRgn", "SetWindowRgnEx", "SetWindowStationUser", "SetWindowTextA",
    "SetWindowTextW", "SetWindowWord", "SetWindowsHookA", "SetWindowsHookExA", "SetWindowsHookExAW",
    "SetWindowsHookExW", "SetWindowsHookW", "ShowCaret", "ShowCursor", "ShowOwnedPopups",
    "ShowScrollBar", "ShowStartGlass", "ShowSystemCursor", "ShowWindow", "ShowWindowAsync",
    "ShutdownBlockReasonCreate", "ShutdownBlockReasonDestroy", "ShutdownBlockReasonQuery",
    "SignalRedirectionStartComplete", "SkipPointerFrameMessages", "SoftModalMessageBox", "SoundSentry",
    "SubtractRect", "SwapMouseButton", "SwitchDesktop", "SwitchDesktopWithFade", "SwitchToThisWindow",
    "SystemParametersInfoA", "SystemParametersInfoForDpi", "SystemParametersInfoW", "TabbedTextOutA",
    "TabbedTextOutW", "TileChildWindows", "TileWindows", "ToAscii", "ToAsciiEx", "ToUnicode",
    "ToUnicodeEx", "TrackMouseEvent", "TrackPopupMenu", "TrackPopupMenuEx", "TranslateAccelerator",
    "TranslateAcceleratorA", "TranslateAcceleratorW", "TranslateMDISysAccel", "TranslateMessage",
    "TranslateMessageEx", "UndelegateInput", "UnhookWinEvent", "UnhookWindowsHook",
    "UnhookWindowsHookEx", "UnionRect", "UnloadKeyboardLayout", "UnlockWindowStation",
    "UnpackDDElParam", "UnregisterClassA", "UnregisterClassW", "UnregisterDeviceNotification",
    "UnregisterHotKey", "UnregisterMessagePumpHook", "UnregisterPointerInputTarget",
    "UnregisterPointerInputTargetEx", "UnregisterPowerSettingNotification", "UnregisterSessionPort",
    "UnregisterSuspendResumeNotification", "UnregisterTouchWindow", "UnregisterUserApiHook",
    "UpdateDefaultDesktopThumbnail", "UpdateLayeredWindow", "UpdateLayeredWindowIndirect",
    "UpdatePerUserSystemParameters", "UpdateWindow", "UpdateWindowInputSinkHints",
    "User32InitializeImmEntryTable", "UserClientDllInitialize", "UserHandleGrantAccess",
    "UserLpkPSMTextOut", "UserLpkTabbedTextOut", "UserRealizePalette", "UserRegisterWowHandlers",
    "VRipOutput", "VTagOutput", "ValidateRect", "ValidateRgn", "VkKeyScanA", "VkKeyScanExA",
    "VkKeyScanExW", "VkKeyScanW", "WCSToMBEx", "WINNLSEnableIME", "WINNLSGetEnableStatus",
    "WINNLSGetIMEHotkey", "WaitForInputIdle", "WaitForRedirectionStartComplete", "WaitMessage",
    "WinHelpA", "WinHelpW", "WindowFromDC", "WindowFromPhysicalPoint", "WindowFromPoint",
    "_UserTestTokenForInteractive", "gSharedInfo", "gapfnScSendMessage", "keybd_event",
    "mouse_event", "wsprintfA", "wsprintfW", "wvsprintfA", "wvsprintfW"
]

import re

DESTRUCTIVE_KEYWORDS = ["shutdown", "lock", "exit", "mouse"]
pattern = re.compile("|".join(DESTRUCTIVE_KEYWORDS), re.IGNORECASE)

SAFE_FUNCTIONS = [
    func for func in ALL_FUNCTIONS
    if not pattern.search(func)
]


# ============================================================================

def get_random_file_bytes(sz, files_list):
    if not files_list:
        return os.urandom(sz)

    try:
        file_path = random.choice(files_list)
        if os.path.isfile(file_path):
            file_size = os.path.getsize(file_path)
            if file_size > 0:
                with open(file_path, 'rb') as f:
                    offset = random.randint(0, max(0, file_size - sz))
                    f.seek(offset)
                    data = f.read(sz)
                    if len(data) == sz:
                        return data
    except:
        pass

    return os.urandom(sz)


def generate_randomized_input(files_list=None):
    input_type = random.randint(1, 25)

    if input_type == 1:
        return random.randint(0, 0xFFFF)

    elif input_type == 2:
        return random.randint(0, 0xFFFFFFFFFFFFFFFF)

    elif input_type == 3:
        return random.randint(-2 ** 31, 2 ** 31 - 1)

    elif input_type == 4:
        return 0

    elif input_type == 5:
        size = random.randint(1, 256)
        return get_random_file_bytes(size, files_list)

    elif input_type == 6:
        size = random.randint(256, 4096)
        return get_random_file_bytes(size, files_list)

    elif input_type == 7:
        max_size = MAX_RANDOM_BUF_BYTES if MAX_RANDOM_BUF_BYTES > 0 else 1048576
        size = random.randint(4096, max_size)
        return get_random_file_bytes(size, files_list)

    elif input_type == 8:
        return random.uniform(-1e10, 1e10)

    elif input_type == 9:
        length = random.randint(1, 1024)
        return get_random_file_bytes(length, files_list).decode('utf-8', errors='ignore')

    elif input_type == 10:
        patterns = [b'\x00' * 32, b'\xFF' * 32, b'\xAA' * 32, b'\x55' * 32]
        return random.choice(patterns)

    elif input_type == 11:
        format_strings = ["%s%s%s%s", "%x%x%x%x", "%n%n%n%n", "%.1000000s"]
        return random.choice(format_strings)

    elif input_type == 12:
        bases = [0x7FFE0000, 0x400000, 0x10000000, 0x70000000]
        base = random.choice(bases)
        offset = random.randint(0, 0xFFFF)
        return base + offset

    elif input_type == 13:
        special_values = [0xFFFFFFFF, 0xFFFFFFFE, 0x12345678, 0xDEADBEEF]
        return random.choice(special_values)

    elif input_type == 14:
        unicode_chars = []
        for _ in range(random.randint(5, 50)):
            unicode_chars.append(chr(random.randint(0x20, 0x7E)))
        return ''.join(unicode_chars)

    elif input_type == 15:
        struct_data = struct.pack('<IIQQ',
                                  random.randint(0, 0xFFFFFFFF),
                                  random.randint(0, 0xFFFFFFFF),
                                  random.randint(0, 0xFFFFFFFFFFFFFFFF),
                                  random.randint(0, 0xFFFFFFFFFFFFFFFF))
        return struct_data

    elif input_type == 16:
        return random.randint(0x400000, 0x7FFFFFFF) & ~0xF

    elif input_type == 17:
        reg_strings = [
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows",
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows",
            "\\Registry\\Machine\\SOFTWARE\\Classes"
        ]
        return random.choice(reg_strings)

    elif input_type == 18:
        paths = [
            "C:\\Windows\\System32\\kernel32.dll",
            "C:\\Program Files\\Common Files\\",
            "\\\\?\\C:\\Windows\\System32\\",
            "..\\..\\..\\Windows\\System32\\cmd.exe"
        ]
        return random.choice(paths)

    elif input_type == 19:
        return random.randint(0, 2 ** 63 - 1)

    elif input_type == 20:
        try:
            if files_list:
                file_path = random.choice(files_list)
                chunk_size = random.randint(64, 8192)

                offsets = []
                file_size = os.path.getsize(file_path)
                for _ in range(3):
                    offsets.append(random.randint(0, max(0, file_size - chunk_size)))

                offset = random.choice(offsets)

                if offset < file_size:
                    actual_size = min(chunk_size, file_size - offset)
                    with open(file_path, 'rb') as f:
                        f.seek(offset)
                        data = f.read(actual_size)
                    return data
        except:
            pass

        data = os.urandom(random.randint(32, 1024))
        return data

    elif input_type == 21:
        values = [0, 1, True, False]
        value = random.choice(values)
        return value

    elif input_type == 22:
        element_count = random.randint(1, 16)
        elements = [random.randint(0, 0xFFFF) for _ in range(element_count)]
        array_data = struct.pack(f'<{element_count}H', *elements)
        return array_data

    elif input_type == 23:
        strings = [
            "tlasjfdlksjfokjaswoefjslfjape4p",
            "randomstringdata123456789",
            "abcdefghijklmnopqrstuvwxyz",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "1234567890!@#$%^&*()",
            "testdataforDLLexecution",
            "chaos_dll_random_string",
        ]
        string = random.choice(strings)
        return string

    elif input_type == 24:
        size = random.choice([1, 2, 4, 8, 16, 32])
        data = os.urandom(size)
        return data

    else:  # input_type == 25
        parts = []
        for _ in range(random.randint(2, 5)):
            part_size = random.randint(4, 32)
            parts.append(os.urandom(part_size))
        data = b''.join(parts)
        return data


def convert_to_ctypes(input_data):
    if isinstance(input_data, bytes):
        if len(input_data) > 0:
            return ctypes.create_string_buffer(input_data)
        else:
            return ctypes.c_void_p(0)
    elif isinstance(input_data, str):
        try:
            return ctypes.c_char_p(input_data.encode('utf-8', errors='ignore'))
        except:
            return ctypes.c_void_p(0)
    elif isinstance(input_data, int):
        if -2 ** 31 <= input_data <= 2 ** 31 - 1:
            return ctypes.c_int(input_data)
        elif 0 <= input_data <= 2 ** 32 - 1:
            return ctypes.c_uint32(input_data)
        elif 0 <= input_data <= 2 ** 64 - 1:
            return ctypes.c_uint64(input_data)
        else:
            return ctypes.c_void_p(input_data & 0xFFFFFFFFFFFFFFFF)
    elif isinstance(input_data, float):
        return ctypes.c_double(input_data)
    elif isinstance(input_data, bool):
        return ctypes.c_bool(input_data)
    else:
        return ctypes.c_void_p(random.randint(0, 0xFFFFFFFF))


def scan_random_files(root_dir):
    files = []
    try:
        for root, dirs, filenames in os.walk(root_dir):
            level = root.replace(root_dir, '').count(os.sep)
            if level >= 3:
                dirs[:] = []
                continue

            for filename in filenames:
                if len(files) >= 1000:
                    return files

                filepath = os.path.join(root, filename)
                try:
                    if os.path.isfile(filepath) and os.path.getsize(filepath) > 0:
                        files.append(filepath)
                except:
                    continue

    except Exception:
        pass

    return files


def load_dll(target_dll_path):
    path = Path(target_dll_path)
    if PREPEND_DLL_DIR_TO_PATH:
        os.environ["PATH"] = str(path.parent) + os.pathsep + os.environ.get("PATH", "")

    try:
        dll = ctypes.WinDLL(target_dll_path)
        print(f"[+] Successfully loaded DLL: {target_dll_path}")
        return dll
    except Exception as e:
        print(f"[-] Failed to load DLL: {e}")
        return None


def worker_process(target_dll_path, dll_function_array, files_list):
    # Load DLL once in this process
    lib = load_dll(target_dll_path)
    if not lib:
        return

    # Local result pool for this worker
    result_pool = []

    while True:
        # Shuffle locally
        random.shuffle(dll_function_array)

        # Prepare parameter sets
        current_parameter_sets = []
        num_functions = len(dll_function_array)
        num_sets = max(num_functions, EXECUTION_BATCH_SIZE)

        for i in range(num_sets):
            num_args = random.randint(0, MAX_ARGS_PER_CALL)
            param_set = []

            for j in range(num_args):
                try:
                    if random.random() < 0.5 and result_pool:
                        param_data = random.choice(result_pool)
                    else:
                        param_data = generate_randomized_input(files_list)
                    param_set.append(param_data)
                except Exception:
                    param_set.append(random.randint(0, 0xFFFFFFFF))

            current_parameter_sets.append(param_set)

        # Execute many functions
        num_exec = min(EXECUTION_BATCH_SIZE, num_functions, len(current_parameter_sets))

        if num_functions > num_exec:
            selected_indices = random.sample(range(num_functions), num_exec)
            functions_to_execute = [dll_function_array[i] for i in selected_indices]
        else:
            functions_to_execute = dll_function_array[:num_exec]

        param_sets_to_use = []
        for i in range(len(functions_to_execute)):
            param_index = i % len(current_parameter_sets)
            param_sets_to_use.append(current_parameter_sets[param_index])

        for func_name, param_set in zip(functions_to_execute, param_sets_to_use):
            if "LockWorks" in func_name:
                continue
            try:
                random.seed(random.getrandbits(32))

                fn = getattr(lib, func_name)
                fn.restype = random.choice([ctypes.c_uint64, ctypes.c_int, ctypes.c_double, ctypes.c_void_p, None])

                args = []
                for param_data in param_set:
                    try:
                        converted_arg = convert_to_ctypes(param_data)
                        args.append(converted_arg)
                    except Exception:
                        args.append(ctypes.c_void_p(0))

                result = fn(*args)

                if result is not None:
                    result_pool.append(result)

            except Exception as e:
                print(f"[WORKER ERROR] Error executing {func_name}: {e}")

        time.sleep(0.01)


def orchestrate():
    if os.name != "nt":
        print("[-] Windows-only.", file=sys.stderr)
        sys.exit(2)
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        print("[-] Use 64-bit Python to call x64 DLLs.", file=sys.stderr)
        sys.exit(2)
    if RNG_SEED is not None:
        random.seed(RNG_SEED)

    print("[STARTUP] User32 Safe Fuzzer")

    # Use filtered safe functions
    dll_function_array = SAFE_FUNCTIONS
    if not dll_function_array:
        print("[-] No safe functions available. Exiting.")
        sys.exit(1)
    print(f"[+] Using {len(dll_function_array)} safe functions")

    dll_dir = os.path.dirname(DLL_PATH)
    files = scan_random_files(dll_dir)
    if not files:
        files = scan_random_files(r"C:\Windows\System32")
    if not files:
        print("[!] No files found for random data; using fallback methods.")
    else:
        print(f"[+] Found {len(files)} files for random data generation")

    print(f"[READY] Starting DLL fuzzing loop for {TOTAL_DURATION_SEC} seconds...")

    processes = []
    start_time = time.time()

    # Start initial workers
    for i in range(WORKERS):
        p = mp.Process(target=worker_process, args=(DLL_PATH, dll_function_array, files), daemon=True)
        p.start()
        processes.append(p)

    while time.time() - start_time < TOTAL_DURATION_SEC:
        time.sleep(WORKER_TIMEOUT_SEC)

        # Check and respawn dead workers
        new_processes = []
        for p in processes:
            if p.is_alive():
                new_processes.append(p)
            else:
                print(f"[ORCHESTRATOR] Worker died, respawning...")
                np = mp.Process(target=worker_process, args=(DLL_PATH, dll_function_array, files), daemon=True)
                np.start()
                new_processes.append(np)

        # If fewer than WORKERS, spawn more
        while len(new_processes) < WORKERS:
            p = mp.Process(target=worker_process, args=(DLL_PATH, dll_function_array, files), daemon=True)
            p.start()
            new_processes.append(p)

        processes = new_processes

    # Cleanup
    for p in processes:
        if p.is_alive():
            p.terminate()

    print("[+] Time limit reached. Exiting.")


def main():
    mp.freeze_support()
    mp.set_start_method("spawn", force=True)
    try:
        orchestrate()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
    except Exception as e:
        print(f"[ERROR] {e}")
    print("[+] Done.")


if __name__ == "__main__":
    main()