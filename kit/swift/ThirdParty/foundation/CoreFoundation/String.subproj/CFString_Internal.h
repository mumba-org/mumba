/*	CFString_Internal.h
	Copyright (c) 1998-2018, Apple Inc. and the Swift project authors
 
	Portions Copyright (c) 2014-2018, Apple Inc. and the Swift project authors
	Licensed under Apache License v2.0 with Runtime Library Exception
	See http://swift.org/LICENSE.txt for license information
	See http://swift.org/CONTRIBUTORS.txt for the list of Swift project authors
*/

#include <CoreFoundation/CFBase.h>
#include <CoreFoundation/CFString.h>
#include <CoreFoundation/CFStringEncodingConverterExt.h>

CF_ASSUME_NONNULL_BEGIN

CF_PRIVATE void __CFSetCharToUniCharFunc(CFStringEncodingCheapEightBitToUnicodeProc _Nullable func);
CF_PRIVATE UniChar __CFCharToUniCharTable[256];
CF_PRIVATE CFIndex CFUniCharCompatibilityDecompose(UTF32Char *convertedChars, CFIndex length, CFIndex maxBufferLength);


CF_ASSUME_NONNULL_END

