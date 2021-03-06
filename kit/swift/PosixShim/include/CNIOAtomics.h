//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2018 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#include <stdbool.h>
//#include <stdint.h>

#include "cpp_magic.h"

#if __clang_major__ == 3 && __clang_minor__ <= 6
/* clang 3.6 doesn't seem to know about _Nonnull yet */
#define _Nonnull __attribute__((nonnull))
#endif

struct catmc_atomic__Bool;
struct catmc_atomic__Bool * _Nonnull catmc_atomic__Bool_create(bool value);
void catmc_atomic__Bool_destroy(struct catmc_atomic__Bool * _Nonnull atomic);
bool catmc_atomic__Bool_compare_and_exchange(struct catmc_atomic__Bool * _Nonnull atomic, bool expected, bool desired);
bool catmc_atomic__Bool_add(struct catmc_atomic__Bool * _Nonnull atomic, bool value);
bool catmc_atomic__Bool_sub(struct catmc_atomic__Bool * _Nonnull atomic, bool value);
bool catmc_atomic__Bool_exchange(struct catmc_atomic__Bool * _Nonnull atomic, bool value);
bool catmc_atomic__Bool_load(struct catmc_atomic__Bool * _Nonnull atomic);
void catmc_atomic__Bool_store(struct catmc_atomic__Bool * _Nonnull atomic, bool value);
struct catmc_atomic_char;
struct catmc_atomic_char * _Nonnull catmc_atomic_char_create(char value);
void catmc_atomic_char_destroy(struct catmc_atomic_char * _Nonnull atomic);
bool catmc_atomic_char_compare_and_exchange(struct catmc_atomic_char * _Nonnull atomic, char expected, char desired);
char catmc_atomic_char_add(struct catmc_atomic_char * _Nonnull atomic, char value);
char catmc_atomic_char_sub(struct catmc_atomic_char * _Nonnull atomic, char value);
char catmc_atomic_char_exchange(struct catmc_atomic_char * _Nonnull atomic, char value);
char catmc_atomic_char_load(struct catmc_atomic_char * _Nonnull atomic);
void catmc_atomic_char_store(struct catmc_atomic_char * _Nonnull atomic, char value);
struct catmc_atomic_short;
struct catmc_atomic_short * _Nonnull catmc_atomic_short_create(short value);
void catmc_atomic_short_destroy(struct catmc_atomic_short * _Nonnull atomic);
bool catmc_atomic_short_compare_and_exchange(struct catmc_atomic_short * _Nonnull atomic, short expected, short desired);
short catmc_atomic_short_add(struct catmc_atomic_short * _Nonnull atomic, short value);
short catmc_atomic_short_sub(struct catmc_atomic_short * _Nonnull atomic, short value);
short catmc_atomic_short_exchange(struct catmc_atomic_short * _Nonnull atomic, short value);
short catmc_atomic_short_load(struct catmc_atomic_short * _Nonnull atomic);
void catmc_atomic_short_store(struct catmc_atomic_short * _Nonnull atomic, short value);
struct catmc_atomic_int;
struct catmc_atomic_int * _Nonnull catmc_atomic_int_create(int value);
void catmc_atomic_int_destroy(struct catmc_atomic_int * _Nonnull atomic);
bool catmc_atomic_int_compare_and_exchange(struct catmc_atomic_int * _Nonnull atomic, int expected, int desired);
int catmc_atomic_int_add(struct catmc_atomic_int * _Nonnull atomic, int value);
int catmc_atomic_int_sub(struct catmc_atomic_int * _Nonnull atomic, int value);
int catmc_atomic_int_exchange(struct catmc_atomic_int * _Nonnull atomic, int value);
int catmc_atomic_int_load(struct catmc_atomic_int * _Nonnull atomic);
void catmc_atomic_int_store(struct catmc_atomic_int * _Nonnull atomic, int value);
struct catmc_atomic_long;
struct catmc_atomic_long * _Nonnull catmc_atomic_long_create(long value);
void catmc_atomic_long_destroy(struct catmc_atomic_long * _Nonnull atomic);
bool catmc_atomic_long_compare_and_exchange(struct catmc_atomic_long * _Nonnull atomic, long expected, long desired);
long catmc_atomic_long_add(struct catmc_atomic_long * _Nonnull atomic, long value);
long catmc_atomic_long_sub(struct catmc_atomic_long * _Nonnull atomic, long value);
long catmc_atomic_long_exchange(struct catmc_atomic_long * _Nonnull atomic, long value);
long catmc_atomic_long_load(struct catmc_atomic_long * _Nonnull atomic);
void catmc_atomic_long_store(struct catmc_atomic_long * _Nonnull atomic, long value);
struct catmc_atomic_long_long;
struct catmc_atomic_long_long * _Nonnull catmc_atomic_long_long_create(long long value);
void catmc_atomic_long_long_destroy(struct catmc_atomic_long_long * _Nonnull atomic);
bool catmc_atomic_long_long_compare_and_exchange(struct catmc_atomic_long_long * _Nonnull atomic, long long expected, long long desired);
long long catmc_atomic_long_long_add(struct catmc_atomic_long_long * _Nonnull atomic, long long value);
long long catmc_atomic_long_long_sub(struct catmc_atomic_long_long * _Nonnull atomic, long long value);
long long catmc_atomic_long_long_exchange(struct catmc_atomic_long_long * _Nonnull atomic, long long value);
long long catmc_atomic_long_long_load(struct catmc_atomic_long_long * _Nonnull atomic);
void catmc_atomic_long_long_store(struct catmc_atomic_long_long * _Nonnull atomic, long long value);
struct catmc_atomic_signed_char;
struct catmc_atomic_signed_char * _Nonnull catmc_atomic_signed_char_create(signed char value);
void catmc_atomic_signed_char_destroy(struct catmc_atomic_signed_char * _Nonnull atomic);
bool catmc_atomic_signed_char_compare_and_exchange(struct catmc_atomic_signed_char * _Nonnull atomic, signed char expected, signed char desired);
signed char catmc_atomic_signed_char_add(struct catmc_atomic_signed_char * _Nonnull atomic, signed char value);
signed char catmc_atomic_signed_char_sub(struct catmc_atomic_signed_char * _Nonnull atomic, signed char value);
signed char catmc_atomic_signed_char_exchange(struct catmc_atomic_signed_char * _Nonnull atomic, signed char value);
signed char catmc_atomic_signed_char_load(struct catmc_atomic_signed_char * _Nonnull atomic);
void catmc_atomic_signed_char_store(struct catmc_atomic_signed_char * _Nonnull atomic, signed char value);
struct catmc_atomic_signed_short;
struct catmc_atomic_signed_short * _Nonnull catmc_atomic_signed_short_create(signed short value);
void catmc_atomic_signed_short_destroy(struct catmc_atomic_signed_short * _Nonnull atomic);
bool catmc_atomic_signed_short_compare_and_exchange(struct catmc_atomic_signed_short * _Nonnull atomic, signed short expected, signed short desired);
signed short catmc_atomic_signed_short_add(struct catmc_atomic_signed_short * _Nonnull atomic, signed short value);
signed short catmc_atomic_signed_short_sub(struct catmc_atomic_signed_short * _Nonnull atomic, signed short value);
signed short catmc_atomic_signed_short_exchange(struct catmc_atomic_signed_short * _Nonnull atomic, signed short value);
signed short catmc_atomic_signed_short_load(struct catmc_atomic_signed_short * _Nonnull atomic);
void catmc_atomic_signed_short_store(struct catmc_atomic_signed_short * _Nonnull atomic, signed short value);
struct catmc_atomic_signed_int;
struct catmc_atomic_signed_int * _Nonnull catmc_atomic_signed_int_create(signed int value);
void catmc_atomic_signed_int_destroy(struct catmc_atomic_signed_int * _Nonnull atomic);
bool catmc_atomic_signed_int_compare_and_exchange(struct catmc_atomic_signed_int * _Nonnull atomic, signed int expected, signed int desired);
signed int catmc_atomic_signed_int_add(struct catmc_atomic_signed_int * _Nonnull atomic, signed int value);
signed int catmc_atomic_signed_int_sub(struct catmc_atomic_signed_int * _Nonnull atomic, signed int value);
signed int catmc_atomic_signed_int_exchange(struct catmc_atomic_signed_int * _Nonnull atomic, signed int value);
signed int catmc_atomic_signed_int_load(struct catmc_atomic_signed_int * _Nonnull atomic);
void catmc_atomic_signed_int_store(struct catmc_atomic_signed_int * _Nonnull atomic, signed int value);
struct catmc_atomic_signed_long;
struct catmc_atomic_signed_long * _Nonnull catmc_atomic_signed_long_create(signed long value);
void catmc_atomic_signed_long_destroy(struct catmc_atomic_signed_long * _Nonnull atomic);
bool catmc_atomic_signed_long_compare_and_exchange(struct catmc_atomic_signed_long * _Nonnull atomic, signed long expected, signed long desired);
signed long catmc_atomic_signed_long_add(struct catmc_atomic_signed_long * _Nonnull atomic, signed long value);
signed long catmc_atomic_signed_long_sub(struct catmc_atomic_signed_long * _Nonnull atomic, signed long value);
signed long catmc_atomic_signed_long_exchange(struct catmc_atomic_signed_long * _Nonnull atomic, signed long value);
signed long catmc_atomic_signed_long_load(struct catmc_atomic_signed_long * _Nonnull atomic);
void catmc_atomic_signed_long_store(struct catmc_atomic_signed_long * _Nonnull atomic, signed long value);
struct catmc_atomic_signed_long_long;
struct catmc_atomic_signed_long_long * _Nonnull catmc_atomic_signed_long_long_create(signed long long value);
void catmc_atomic_signed_long_long_destroy(struct catmc_atomic_signed_long_long * _Nonnull atomic);
bool catmc_atomic_signed_long_long_compare_and_exchange(struct catmc_atomic_signed_long_long * _Nonnull atomic, signed long long expected, signed long long desired);
signed long long catmc_atomic_signed_long_long_add(struct catmc_atomic_signed_long_long * _Nonnull atomic, signed long long value);
signed long long catmc_atomic_signed_long_long_sub(struct catmc_atomic_signed_long_long * _Nonnull atomic, signed long long value);
signed long long catmc_atomic_signed_long_long_exchange(struct catmc_atomic_signed_long_long * _Nonnull atomic, signed long long value);
signed long long catmc_atomic_signed_long_long_load(struct catmc_atomic_signed_long_long * _Nonnull atomic);
void catmc_atomic_signed_long_long_store(struct catmc_atomic_signed_long_long * _Nonnull atomic, signed long long value);
struct catmc_atomic_unsigned_char;
struct catmc_atomic_unsigned_char * _Nonnull catmc_atomic_unsigned_char_create(unsigned char value);
void catmc_atomic_unsigned_char_destroy(struct catmc_atomic_unsigned_char * _Nonnull atomic);
bool catmc_atomic_unsigned_char_compare_and_exchange(struct catmc_atomic_unsigned_char * _Nonnull atomic, unsigned char expected, unsigned char desired);
unsigned char catmc_atomic_unsigned_char_add(struct catmc_atomic_unsigned_char * _Nonnull atomic, unsigned char value);
unsigned char catmc_atomic_unsigned_char_sub(struct catmc_atomic_unsigned_char * _Nonnull atomic, unsigned char value);
unsigned char catmc_atomic_unsigned_char_exchange(struct catmc_atomic_unsigned_char * _Nonnull atomic, unsigned char value);
unsigned char catmc_atomic_unsigned_char_load(struct catmc_atomic_unsigned_char * _Nonnull atomic);
void catmc_atomic_unsigned_char_store(struct catmc_atomic_unsigned_char * _Nonnull atomic, unsigned char value);
struct catmc_atomic_unsigned_short;
struct catmc_atomic_unsigned_short * _Nonnull catmc_atomic_unsigned_short_create(unsigned short value);
void catmc_atomic_unsigned_short_destroy(struct catmc_atomic_unsigned_short * _Nonnull atomic);
bool catmc_atomic_unsigned_short_compare_and_exchange(struct catmc_atomic_unsigned_short * _Nonnull atomic, unsigned short expected, unsigned short desired);
unsigned short catmc_atomic_unsigned_short_add(struct catmc_atomic_unsigned_short * _Nonnull atomic, unsigned short value);
unsigned short catmc_atomic_unsigned_short_sub(struct catmc_atomic_unsigned_short * _Nonnull atomic, unsigned short value);
unsigned short catmc_atomic_unsigned_short_exchange(struct catmc_atomic_unsigned_short * _Nonnull atomic, unsigned short value);
unsigned short catmc_atomic_unsigned_short_load(struct catmc_atomic_unsigned_short * _Nonnull atomic);
void catmc_atomic_unsigned_short_store(struct catmc_atomic_unsigned_short * _Nonnull atomic, unsigned short value);
struct catmc_atomic_unsigned_int;
struct catmc_atomic_unsigned_int * _Nonnull catmc_atomic_unsigned_int_create(unsigned int value);
void catmc_atomic_unsigned_int_destroy(struct catmc_atomic_unsigned_int * _Nonnull atomic);
bool catmc_atomic_unsigned_int_compare_and_exchange(struct catmc_atomic_unsigned_int * _Nonnull atomic, unsigned int expected, unsigned int desired);
unsigned int catmc_atomic_unsigned_int_add(struct catmc_atomic_unsigned_int * _Nonnull atomic, unsigned int value);
unsigned int catmc_atomic_unsigned_int_sub(struct catmc_atomic_unsigned_int * _Nonnull atomic, unsigned int value);
unsigned int catmc_atomic_unsigned_int_exchange(struct catmc_atomic_unsigned_int * _Nonnull atomic, unsigned int value);
unsigned int catmc_atomic_unsigned_int_load(struct catmc_atomic_unsigned_int * _Nonnull atomic);
void catmc_atomic_unsigned_int_store(struct catmc_atomic_unsigned_int * _Nonnull atomic, unsigned int value);
struct catmc_atomic_unsigned_long;
struct catmc_atomic_unsigned_long * _Nonnull catmc_atomic_unsigned_long_create(unsigned long value);
void catmc_atomic_unsigned_long_destroy(struct catmc_atomic_unsigned_long * _Nonnull atomic);
bool catmc_atomic_unsigned_long_compare_and_exchange(struct catmc_atomic_unsigned_long * _Nonnull atomic, unsigned long expected, unsigned long desired);
unsigned long catmc_atomic_unsigned_long_add(struct catmc_atomic_unsigned_long * _Nonnull atomic, unsigned long value);
unsigned long catmc_atomic_unsigned_long_sub(struct catmc_atomic_unsigned_long * _Nonnull atomic, unsigned long value);
unsigned long catmc_atomic_unsigned_long_exchange(struct catmc_atomic_unsigned_long * _Nonnull atomic, unsigned long value);
unsigned long catmc_atomic_unsigned_long_load(struct catmc_atomic_unsigned_long * _Nonnull atomic);
void catmc_atomic_unsigned_long_store(struct catmc_atomic_unsigned_long * _Nonnull atomic, unsigned long value);
struct catmc_atomic_unsigned_long_long;
struct catmc_atomic_unsigned_long_long * _Nonnull catmc_atomic_unsigned_long_long_create(unsigned long long value);
void catmc_atomic_unsigned_long_long_destroy(struct catmc_atomic_unsigned_long_long * _Nonnull atomic);
bool catmc_atomic_unsigned_long_long_compare_and_exchange(struct catmc_atomic_unsigned_long_long * _Nonnull atomic, unsigned long long expected, unsigned long long desired);
unsigned long long catmc_atomic_unsigned_long_long_add(struct catmc_atomic_unsigned_long_long * _Nonnull atomic, unsigned long long value);
unsigned long long catmc_atomic_unsigned_long_long_sub(struct catmc_atomic_unsigned_long_long * _Nonnull atomic, unsigned long long value);
unsigned long long catmc_atomic_unsigned_long_long_exchange(struct catmc_atomic_unsigned_long_long * _Nonnull atomic, unsigned long long value);
unsigned long long catmc_atomic_unsigned_long_long_load(struct catmc_atomic_unsigned_long_long * _Nonnull atomic);
void catmc_atomic_unsigned_long_long_store(struct catmc_atomic_unsigned_long_long * _Nonnull atomic, unsigned long long value);
struct catmc_atomic_int_least8_t;
struct catmc_atomic_int_least8_t * _Nonnull catmc_atomic_int_least8_t_create(int_least8_t value);
void catmc_atomic_int_least8_t_destroy(struct catmc_atomic_int_least8_t * _Nonnull atomic);
bool catmc_atomic_int_least8_t_compare_and_exchange(struct catmc_atomic_int_least8_t * _Nonnull atomic, int_least8_t expected, int_least8_t desired);
int_least8_t catmc_atomic_int_least8_t_add(struct catmc_atomic_int_least8_t * _Nonnull atomic, int_least8_t value);
int_least8_t catmc_atomic_int_least8_t_sub(struct catmc_atomic_int_least8_t * _Nonnull atomic, int_least8_t value);
int_least8_t catmc_atomic_int_least8_t_exchange(struct catmc_atomic_int_least8_t * _Nonnull atomic, int_least8_t value);
int_least8_t catmc_atomic_int_least8_t_load(struct catmc_atomic_int_least8_t * _Nonnull atomic);
void catmc_atomic_int_least8_t_store(struct catmc_atomic_int_least8_t * _Nonnull atomic, int_least8_t value);
struct catmc_atomic_uint_least8_t;
struct catmc_atomic_uint_least8_t * _Nonnull catmc_atomic_uint_least8_t_create(uint_least8_t value);
void catmc_atomic_uint_least8_t_destroy(struct catmc_atomic_uint_least8_t * _Nonnull atomic);
bool catmc_atomic_uint_least8_t_compare_and_exchange(struct catmc_atomic_uint_least8_t * _Nonnull atomic, uint_least8_t expected, uint_least8_t desired);
uint_least8_t catmc_atomic_uint_least8_t_add(struct catmc_atomic_uint_least8_t * _Nonnull atomic, uint_least8_t value);
uint_least8_t catmc_atomic_uint_least8_t_sub(struct catmc_atomic_uint_least8_t * _Nonnull atomic, uint_least8_t value);
uint_least8_t catmc_atomic_uint_least8_t_exchange(struct catmc_atomic_uint_least8_t * _Nonnull atomic, uint_least8_t value);
uint_least8_t catmc_atomic_uint_least8_t_load(struct catmc_atomic_uint_least8_t * _Nonnull atomic);
void catmc_atomic_uint_least8_t_store(struct catmc_atomic_uint_least8_t * _Nonnull atomic, uint_least8_t value);
struct catmc_atomic_int_least16_t;
struct catmc_atomic_int_least16_t * _Nonnull catmc_atomic_int_least16_t_create(int_least16_t value);
void catmc_atomic_int_least16_t_destroy(struct catmc_atomic_int_least16_t * _Nonnull atomic);
bool catmc_atomic_int_least16_t_compare_and_exchange(struct catmc_atomic_int_least16_t * _Nonnull atomic, int_least16_t expected, int_least16_t desired);
int_least16_t catmc_atomic_int_least16_t_add(struct catmc_atomic_int_least16_t * _Nonnull atomic, int_least16_t value);
int_least16_t catmc_atomic_int_least16_t_sub(struct catmc_atomic_int_least16_t * _Nonnull atomic, int_least16_t value);
int_least16_t catmc_atomic_int_least16_t_exchange(struct catmc_atomic_int_least16_t * _Nonnull atomic, int_least16_t value);
int_least16_t catmc_atomic_int_least16_t_load(struct catmc_atomic_int_least16_t * _Nonnull atomic);
void catmc_atomic_int_least16_t_store(struct catmc_atomic_int_least16_t * _Nonnull atomic, int_least16_t value);
struct catmc_atomic_uint_least16_t;
struct catmc_atomic_uint_least16_t * _Nonnull catmc_atomic_uint_least16_t_create(uint_least16_t value);
void catmc_atomic_uint_least16_t_destroy(struct catmc_atomic_uint_least16_t * _Nonnull atomic);
bool catmc_atomic_uint_least16_t_compare_and_exchange(struct catmc_atomic_uint_least16_t * _Nonnull atomic, uint_least16_t expected, uint_least16_t desired);
uint_least16_t catmc_atomic_uint_least16_t_add(struct catmc_atomic_uint_least16_t * _Nonnull atomic, uint_least16_t value);
uint_least16_t catmc_atomic_uint_least16_t_sub(struct catmc_atomic_uint_least16_t * _Nonnull atomic, uint_least16_t value);
uint_least16_t catmc_atomic_uint_least16_t_exchange(struct catmc_atomic_uint_least16_t * _Nonnull atomic, uint_least16_t value);
uint_least16_t catmc_atomic_uint_least16_t_load(struct catmc_atomic_uint_least16_t * _Nonnull atomic);
void catmc_atomic_uint_least16_t_store(struct catmc_atomic_uint_least16_t * _Nonnull atomic, uint_least16_t value);
struct catmc_atomic_int_least32_t;
struct catmc_atomic_int_least32_t * _Nonnull catmc_atomic_int_least32_t_create(int_least32_t value);
void catmc_atomic_int_least32_t_destroy(struct catmc_atomic_int_least32_t * _Nonnull atomic);
bool catmc_atomic_int_least32_t_compare_and_exchange(struct catmc_atomic_int_least32_t * _Nonnull atomic, int_least32_t expected, int_least32_t desired);
int_least32_t catmc_atomic_int_least32_t_add(struct catmc_atomic_int_least32_t * _Nonnull atomic, int_least32_t value);
int_least32_t catmc_atomic_int_least32_t_sub(struct catmc_atomic_int_least32_t * _Nonnull atomic, int_least32_t value);
int_least32_t catmc_atomic_int_least32_t_exchange(struct catmc_atomic_int_least32_t * _Nonnull atomic, int_least32_t value);
int_least32_t catmc_atomic_int_least32_t_load(struct catmc_atomic_int_least32_t * _Nonnull atomic);
void catmc_atomic_int_least32_t_store(struct catmc_atomic_int_least32_t * _Nonnull atomic, int_least32_t value);
struct catmc_atomic_uint_least32_t;
struct catmc_atomic_uint_least32_t * _Nonnull catmc_atomic_uint_least32_t_create(uint_least32_t value);
void catmc_atomic_uint_least32_t_destroy(struct catmc_atomic_uint_least32_t * _Nonnull atomic);
bool catmc_atomic_uint_least32_t_compare_and_exchange(struct catmc_atomic_uint_least32_t * _Nonnull atomic, uint_least32_t expected, uint_least32_t desired);
uint_least32_t catmc_atomic_uint_least32_t_add(struct catmc_atomic_uint_least32_t * _Nonnull atomic, uint_least32_t value);
uint_least32_t catmc_atomic_uint_least32_t_sub(struct catmc_atomic_uint_least32_t * _Nonnull atomic, uint_least32_t value);
uint_least32_t catmc_atomic_uint_least32_t_exchange(struct catmc_atomic_uint_least32_t * _Nonnull atomic, uint_least32_t value);
uint_least32_t catmc_atomic_uint_least32_t_load(struct catmc_atomic_uint_least32_t * _Nonnull atomic);
void catmc_atomic_uint_least32_t_store(struct catmc_atomic_uint_least32_t * _Nonnull atomic, uint_least32_t value);
struct catmc_atomic_int_least64_t;
struct catmc_atomic_int_least64_t * _Nonnull catmc_atomic_int_least64_t_create(int_least64_t value);
void catmc_atomic_int_least64_t_destroy(struct catmc_atomic_int_least64_t * _Nonnull atomic);
bool catmc_atomic_int_least64_t_compare_and_exchange(struct catmc_atomic_int_least64_t * _Nonnull atomic, int_least64_t expected, int_least64_t desired);
int_least64_t catmc_atomic_int_least64_t_add(struct catmc_atomic_int_least64_t * _Nonnull atomic, int_least64_t value);
int_least64_t catmc_atomic_int_least64_t_sub(struct catmc_atomic_int_least64_t * _Nonnull atomic, int_least64_t value);
int_least64_t catmc_atomic_int_least64_t_exchange(struct catmc_atomic_int_least64_t * _Nonnull atomic, int_least64_t value);
int_least64_t catmc_atomic_int_least64_t_load(struct catmc_atomic_int_least64_t * _Nonnull atomic);
void catmc_atomic_int_least64_t_store(struct catmc_atomic_int_least64_t * _Nonnull atomic, int_least64_t value);
struct catmc_atomic_uint_least64_t;
struct catmc_atomic_uint_least64_t * _Nonnull catmc_atomic_uint_least64_t_create(uint_least64_t value);
void catmc_atomic_uint_least64_t_destroy(struct catmc_atomic_uint_least64_t * _Nonnull atomic);
bool catmc_atomic_uint_least64_t_compare_and_exchange(struct catmc_atomic_uint_least64_t * _Nonnull atomic, uint_least64_t expected, uint_least64_t desired);
uint_least64_t catmc_atomic_uint_least64_t_add(struct catmc_atomic_uint_least64_t * _Nonnull atomic, uint_least64_t value);
uint_least64_t catmc_atomic_uint_least64_t_sub(struct catmc_atomic_uint_least64_t * _Nonnull atomic, uint_least64_t value);
uint_least64_t catmc_atomic_uint_least64_t_exchange(struct catmc_atomic_uint_least64_t * _Nonnull atomic, uint_least64_t value);
uint_least64_t catmc_atomic_uint_least64_t_load(struct catmc_atomic_uint_least64_t * _Nonnull atomic);
void catmc_atomic_uint_least64_t_store(struct catmc_atomic_uint_least64_t * _Nonnull atomic, uint_least64_t value);
