// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if os(Linux)

public enum KeyboardCode: UInt8 {
  case KeyBack        = 0x08
  case KeyTab         = 0x09
  case KeyBacktab     = 0x0A
  case KeyClear       = 0x0C
  case KeyReturn      = 0x0D
  case KeyShift       = 0x10
  case KeyControl     = 0x11
  case KeyMenu        = 0x12
  case KeyPause       = 0x13
  case KeyCapital     = 0x14
  case KeyKana        = 0x15
  //case KeyHangul = 0x15
  //case KeyHangul      = -1
  case KeyJunja       = 0x17
  case KeyFinal       = 0x18
  case KeyHanja       = 0x19
  // swift doesnt let us repeat.. what to do?
  //case KeyKanji       = -2// was 0x19
  case KeyEscape      = 0x1B
  case KeyConvert     = 0x1C
  case KeyNonConvert  = 0x1D
  case KeyAccept      = 0x1E
  case KeyModeChange  = 0x1F
  case KeySpace       = 0x20
  case KeyPrior       = 0x21
  case KeyNext        = 0x22
  case KeyEnd         = 0x23
  case KeyHome        = 0x24
  case KeyLeft        = 0x25
  case KeyUp          = 0x26
  case KeyRight       = 0x27
  case KeyDown        = 0x28
  case KeySelect      = 0x29
  case KeyPrint       = 0x2A
  case KeyExecute     = 0x2B
  case KeySnapshot    = 0x2C
  case KeyInsert      = 0x2D
  case KeyDelete      = 0x2E
  case KeyHelp        = 0x2F
  case Key0           = 0x30
  case Key1           = 0x31
  case Key2           = 0x32
  case Key3           = 0x33
  case Key4           = 0x34
  case Key5           = 0x35
  case Key6           = 0x36
  case Key7           = 0x37
  case Key8           = 0x38
  case Key9           = 0x39
  case KeyA           = 0x41
  case KeyB           = 0x42
  case KeyC           = 0x43
  case KeyD           = 0x44
  case KeyE           = 0x45
  case KeyF           = 0x46
  case KeyG           = 0x47
  case KeyH           = 0x48
  case KeyI           = 0x49
  case KeyJ           = 0x4A
  case KeyK           = 0x4B
  case KeyL           = 0x4C
  case KeyM           = 0x4D
  case KeyN           = 0x4E
  case KeyO           = 0x4F
  case KeyP           = 0x50
  case KeyQ           = 0x51
  case KeyR           = 0x52
  case KeyS           = 0x53
  case KeyT           = 0x54
  case KeyU           = 0x55
  case KeyV           = 0x56
  case KeyW           = 0x57
  case KeyX           = 0x58
  case KeyY           = 0x59
  case KeyZ           = 0x5A
  case KeyLWin        = 0x5B
  //case KeyCommand = 0x5B
  //case KeyCommand = -3
  case KeyRWin        = 0x5C
  case KeyApps        = 0x5D
  case KeySleep       = 0x5F
  case KeyNumpad0     = 0x60
  case KeyNumpad1     = 0x61
  case KeyNumpad2     = 0x62
  case KeyNumpad3     = 0x63
  case KeyNumpad4     = 0x64
  case KeyNumpad5     = 0x65
  case KeyNumpad6     = 0x66
  case KeyNumpad7     = 0x67
  case KeyNumpad8     = 0x68
  case KeyNumpad9     = 0x69
  case KeyMultiply    = 0x6A
  case KeyAdd         = 0x6B
  case KeySeparator   = 0x6C
  case KeySubtract    = 0x6D
  case KeyDecimal     = 0x6E
  case KeyDivide      = 0x6F
  case KeyF1          = 0x70
  case KeyF2          = 0x71
  case KeyF3          = 0x72
  case KeyF4          = 0x73
  case KeyF5          = 0x74
  case KeyF6          = 0x75
  case KeyF7          = 0x76
  case KeyF8          = 0x77
  case KeyF9          = 0x78
  case KeyF10         = 0x79
  case KeyF11         = 0x7A
  case KeyF12         = 0x7B
  case KeyF13         = 0x7C
  case KeyF14         = 0x7D
  case KeyF15         = 0x7E
  case KeyF16         = 0x7F
  case KeyF17         = 0x80
  case KeyF18         = 0x81
  case KeyF19         = 0x82
  case KeyF20         = 0x83
  case KeyF21         = 0x84
  case KeyF22         = 0x85
  case KeyF23         = 0x86
  case KeyF24         = 0x87
  case KeyNumlock     = 0x90
  case KeyScroll      = 0x91
  case KeyLShift      = 0xA0
  case KeyRShift      = 0xA1
  case KeyLControl    = 0xA2
  case KeyRControl    = 0xA3
  case KeyLMenu       = 0xA4
  case KeyRMenu       = 0xA5
  case KeyBrowserBack    = 0xA6
  case KeyBrowserForward = 0xA7
  case KeyBrowserRefresh = 0xA8
  case KeyBrowserStop    = 0xA9
  case KeyBrowserSearch  = 0xAA
  case KeyBrowserFavorites = 0xAB
  case KeyBrowserHome      = 0xAC
  case KeyVolumeMute       = 0xAD
  case KeyVolumeDown       = 0xAE
  case KeyVolumeUP         = 0xAF
  case KeyMediaNextTrack   = 0xB0
  case KeyMediaPrevTrack   = 0xB1
  case KeyMediaStop        = 0xB2
  case KeyMediaPlayPause   = 0xB3
  case KeyMediaLaunchMail  = 0xB4
  case KeyMediaLaunchMediaSelect = 0xB5
  case KeyMediaLaunchApp1     = 0xB6
  case KeyMediaLaunchApp2     = 0xB7
  case KeyOEM1                = 0xBA
  case KeyOEMPlus             = 0xBB
  case KeyOEMComma            = 0xBC
  case KeyOEMMinus            = 0xBD
  case KeyOEMPeriod           = 0xBE
  case KeyOEM2                = 0xBF
  case KeyOEM3                = 0xC0
  case KeyOEM4                = 0xDB
  case KeyOEM5                = 0xDC
  case KeyOEM6                = 0xDD
  case KeyOEM7                = 0xDE
  case KeyOEM8                = 0xDF
  case KeyOEM102              = 0xE2
  case KeyOEM103              = 0xE3  // GTV KeyCODE_MEDIA_REWIND
  case KeyOEM104              = 0xE4  // GTV KeyCODE_MEDIA_FAST_FORWARD
  case KeyProcessKey          = 0xE5
  case KeyPacket              = 0xE7
  case KeyDbesbcschar         = 0xF3
  case KeyDbedbcschar         = 0xF4
  case KeyAttn                = 0xF6
  case KeyCrsel               = 0xF7
  case KeyExsel               = 0xF8
  case KeyEreof               = 0xF9
  case KeyPlay                = 0xFA
  case KeyZoom                = 0xFB
  case KeyNoname              = 0xFC
  case KeyPa1                 = 0xFD
  case KeyOEMClear            = 0xFE
  case KeyUnknown             = 0
  case KeyWlan                = 0x97
  case KeyPower               = 0x98
  case KeyBrightnessDown      = 0xD8
  case KeyBrightnessUp        = 0xD9
  case KeyKbdBrightnessDown   = 0xDA
  case KeyKbdBrightnessUp     = 0xE8
  case KeyAltGr               = 0xE1
  case KeyCompose             = 0xE6
}
#endif
