// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ICUShims.h"

#include <vector>

#include "base/logging.h"
#include <third_party/icu/source/common/unicode/ubidi.h>
#include <third_party/icu/source/common/unicode/utf16.h>
#include <third_party/icu/source/common/unicode/uchar.h>
#include <third_party/icu/source/common/unicode/uscript.h>
#include "base/third_party/icu/icu_utf.h"

namespace {

UBiDiLevel getParagraphLevelForDirection(int direction) {
    switch (direction) {
      case 0:
        return UBIDI_DEFAULT_LTR;
        break;
      case 1:
        return 1;  // Highest RTL level.
        break;
      case 2:
        return 0;  // Highest LTR level.
        break;
      default:
        NOTREACHED();
        return 0;
    }
}

}

unsigned short _ICUU16Next(const unsigned short* string, int offset, int lenght){
  unsigned short c;
  U16_NEXT(string, offset, lenght, c);
  return c;
}

void _ICUU16SetCPStart(const unsigned short* text, int start, int offset) {
  U16_SET_CP_START(text, start, offset);
}

int _ICUCBU16IsTrail(uint16_t c) {
  return CBU16_IS_TRAIL(c);
}

int _ICUCBU16IsLead(uint16_t c) {
 return CBU16_IS_LEAD(c);
}

#if defined(OS_LINUX)
UBiDiRef _ICUBiDiOpen(const unsigned short* text, int textlen, int direction) {
#elif defined(OS_WIN)
UBiDiRef _ICUBiDiOpen(const wchar_t* text, int textlen, int direction) {
#endif
  UErrorCode error = U_ZERO_ERROR;
  UBiDi* bidi = ubidi_openSized(textlen, 0, &error);
  if (U_FAILURE(error))
    return nullptr;
  ubidi_setPara(bidi, text, textlen, getParagraphLevelForDirection(direction), NULL, &error);
  if (U_SUCCESS(error) == TRUE) {
    return bidi;
  }
  return nullptr;
}

int _ICUBiDiCountRuns(UBiDiRef handle) {
  UErrorCode error = U_ZERO_ERROR;
  const int runs = ubidi_countRuns(reinterpret_cast<UBiDi *>(handle), &error);
  return U_SUCCESS(error) ? runs : 0;
}

int _ICUBiDiGetVisualRun(UBiDiRef handle, int index, int* start, int* len) {
  int istart = 0;
  int ilen = 0;

  int result = ubidi_getVisualRun(reinterpret_cast<UBiDi *>(handle), index, &istart, &ilen);
  
  *start = istart;
  *len = ilen;

  return result;
}

void _ICUBiDiGetLogicalRun(UBiDiRef handle, int start, int* end, unsigned char* level) {
  int iend = 0;
  uint8_t ilevel = 0;
  
  ubidi_getLogicalRun(reinterpret_cast<UBiDi *>(handle), start, &iend, &ilevel);
  
  *end = iend;
  *level = ilevel;
}

void _ICUBiDiReorderVisual(const unsigned char* levels, int length, int *indexMap) {
  // unfortunatelly passing the ptr directly doesnt seem to work
  std::vector<int32_t> index;
  index.resize(length);

  ubidi_reorderVisual(levels, length, &index[0]);

  for (int i = 0; i < length; i++) {
    indexMap[i] = index[i];
  }
}

void _ICUBiDiReorderLogical(const unsigned char* levels, int length, int *indexMap) {
  std::vector<int32_t> index;
  index.resize(length);
  
  ubidi_reorderLogical(levels, length, &index[0]);

  for (int i = 0; i < length; i++) {
    indexMap[i] = index[i];
  }
}

int _ICUUBlockGetCode(unsigned short c) {
  return ublock_getCode(c);
}

int _ICUIsWhiteSpace(unsigned short c) {
  return u_isUWhiteSpace(c);
}

int _ICUGetScript(unsigned short c, int *pErrorCode) {
  return uscript_getScript(c, reinterpret_cast<UErrorCode *>(pErrorCode));
}

int _ICUGetScriptExtensions(unsigned short c,
                             int *scripts, 
                             int capacity,
                             int *pErrorCode) {
  std::vector<UScriptCode> arr;
  arr.resize(capacity);

  int size = uscript_getScriptExtensions(c, &arr[0], capacity, reinterpret_cast<UErrorCode *>(pErrorCode));
  
  for (int i = 0; i < size; i++) {
    scripts[i] = static_cast<int>(arr[i]); 
  }

  return size;
}