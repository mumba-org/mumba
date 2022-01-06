// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_HARFBUZZ_SHIMS_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_HARFBUZZ_SHIMS_H_

#include "Globals.h"

typedef void* HarfBuzzFontRef;
typedef void* HarfBuzzBufferRef;
typedef int HarfBuzzScriptEnum;
typedef void* TypefaceRef;

EXPORT HarfBuzzFontRef _HarfBuzzFontCreate(TypefaceRef typeface,
                                            int text_size,
                                            int antialiasing,
                                            int subpixel_positioning,
                                            int autohinter,
                                            int subpixel_rendering,
                                            int subpixel_rendering_suppressed,
                                            int hinting);

EXPORT void _HarfBuzzFontDestroy(HarfBuzzFontRef handle);
EXPORT void _HarfBuzzFontShape(HarfBuzzFontRef handle, HarfBuzzBufferRef buffer);

EXPORT HarfBuzzBufferRef _HarfBuzzBufferCreate();
EXPORT void _HarfBuzzBufferDestroy(HarfBuzzBufferRef handle);
EXPORT void _HarfBuzzBufferAddUTF16(
  HarfBuzzBufferRef handle, 
  const uint16_t* text,
  int textLength,
  unsigned int itemOffset,
  int itemLength);

EXPORT void _HarfBuzzBufferGetGlyphInfos(
  HarfBuzzBufferRef handle, 
  uint32_t* codepoints, 
  uint32_t* masks, 
  uint32_t* clusters, 
  uint32_t* len);

EXPORT void _HarfBuzzBufferGetGlyphPositions(
  HarfBuzzBufferRef handle, 
  int* xadvances, 
  int* yadvances, 
  int* xoffset, 
  int* yoffset, 
  uint32_t* len);

EXPORT void _HarfBuzzBufferSetScript(HarfBuzzBufferRef handle, int script);
EXPORT void _HarfBuzzBufferSetDirection(HarfBuzzBufferRef handle, int dir);
EXPORT void _HarfBuzzBufferSetLanguage(HarfBuzzBufferRef handle, const char* lang, int len);
EXPORT void _HarfBuzzBufferSetDefaultLanguage(HarfBuzzBufferRef handle);

EXPORT HarfBuzzScriptEnum _HarfBuzzScriptCreateString(const char* string, int len);
EXPORT HarfBuzzScriptEnum _HarfBuzzScriptCreateICU(int script);

#endif