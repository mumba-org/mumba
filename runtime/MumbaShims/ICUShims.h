// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_ICU_SHIMS_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_ICU_SHIMS_H_

#include "Globals.h"
// export ICU symbols

typedef void* UBiDiRef;
//typedef int UBlockCode;
//typedef int UScriptCode;
//typedef int UErrorCode;

EXPORT unsigned short _ICUU16Next(const unsigned short* string, int offset, int lenght);
EXPORT void _ICUU16SetCPStart(const unsigned short* text, int start, int offset);
EXPORT int _ICUCBU16IsTrail(unsigned short c);
EXPORT int _ICUCBU16IsLead(unsigned short c);

#if defined(OS_LINUX)
EXPORT UBiDiRef _ICUBiDiOpen(const unsigned short* text, int textlen, int direction);
#elif defined(OS_WIN)
EXPORT UBiDiRef _ICUBiDiOpen(const wchar_t* text, int textlen, int direction);
#endif
EXPORT int _ICUBiDiCountRuns(UBiDiRef handle);
EXPORT int _ICUBiDiGetVisualRun(UBiDiRef handle, int index, int* start, int* len);
EXPORT void _ICUBiDiGetLogicalRun(UBiDiRef handle, int start, int* end, unsigned char* level);

EXPORT void _ICUBiDiReorderVisual(const unsigned char* levels, int length, int *indexMap);
EXPORT void _ICUBiDiReorderLogical(const unsigned char* levels, int length, int *indexMap);

EXPORT int _ICUUBlockGetCode(unsigned short c);
EXPORT int _ICUIsWhiteSpace(unsigned short c);
EXPORT int _ICUGetScript(unsigned short c, int *pErrorCode);
EXPORT int _ICUGetScriptExtensions(unsigned short c,
                                    int *scripts, 
                                    int capacity,
                                    int *pErrorCode);

#endif