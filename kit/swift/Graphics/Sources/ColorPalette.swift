// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public let placeholderColor: Color = Color.Red

// The number refers to the shade of darkness. Each color in the MD
// palette ranges from 100-900.
public let googleBlue300: Color = Color.fromRGB(0x8A, 0xB4, 0xF8)
public let googleBlue500: Color = Color.fromRGB(0x42, 0x85, 0xF4)
public let googleBlue600: Color = Color.fromRGB(0x1A, 0x73, 0xE8)
public let googleBlue700: Color = Color.fromRGB(0x19, 0x67, 0xD2)
public let googleBlue900: Color = Color.fromRGB(0x17, 0x4E, 0xA6)
public let googleBlueDark600: Color = Color.fromRGB(0x25, 0x81, 0xDF)
public let googleRed300: Color = Color.fromRGB(0xF2, 0x8B, 0xB2)
public let googleRed600: Color = Color.fromRGB(0xD9, 0x30, 0x25)
public let googleRed700: Color = Color.fromRGB(0xC5, 0x22, 0x1F)
public let googleRed800: Color = Color.fromRGB(0xB3, 0x14, 0x12)
public let googleRedDark600: Color = Color.fromRGB(0xD3, 0x3B, 0x30)
public let googleRedDark800: Color = Color.fromRGB(0xB4, 0x1B, 0x1A)
public let googleGreen300: Color = Color.fromRGB(0x81, 0xC9, 0x95)
public let googleGreen600: Color = Color.fromRGB(0x1E, 0x8E, 0x3E)
public let googleGreen700: Color = Color.fromRGB(0x18, 0x80, 0x38)
public let googleGreenDark600: Color = Color.fromRGB(0x28, 0x99, 0x4F)
public let googleYellow300: Color = Color.fromRGB(0xFD, 0xD6, 0x63)
public let googleYellow700: Color = Color.fromRGB(0xF2, 0x99, 0x00)
public let googleYellow900: Color = Color.fromRGB(0xE3, 0x74, 0x00)
public let googleGrey100: Color = Color.fromRGB(0xF1, 0xF3, 0xF4)
public let googleGrey200: Color = Color.fromRGB(0xE8, 0xEA, 0xED)
public let googleGrey400: Color = Color.fromRGB(0xBD, 0xC1, 0xC6)
public let googleGrey700: Color = Color.fromRGB(0x5F, 0x63, 0x68)
public let googleGrey800: Color = Color.fromRGB(0x3C, 0x40, 0x43)
public let googleGrey900: Color = Color.fromRGB(0x20, 0x21, 0x24)

// kChromeIconGrey is subject to change in the future, kGoogleGrey700 is set in
// stone. If you're semantically looking for "the icon color Chrome uses" then
// use kChromeIconGrey, if you're looking for GG700 grey specifically, use the
// Google-grey constant directly.
public let chromeIconGrey: Color = googleGrey700

// An alpha value for designating a control's disabled state. In specs this is
// sometimes listed as 0.38a.
public let disabledControlAlpha: UInt8 = 0x61
