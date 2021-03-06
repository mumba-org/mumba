/*
 *
 * Copyright 2015 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef GRPC_CORE_LIB_SUPPORT_STRING_H
#define GRPC_CORE_LIB_SUPPORT_STRING_H

#include <stdbool.h>
#include <stddef.h>

#include <rpc/support/port_platform.h>

#ifdef __cplusplus
extern "C" {
#endif

/* String utility functions */

/* Flags for gpr_dump function. */
#define GPR_DUMP_HEX 0x00000001
#define GPR_DUMP_ASCII 0x00000002

/* Converts array buf, of length len, into a C string  according to the flags.
   Result should be freed with gpr_free() */
GPRAPI char* gpr_dump(const char* buf, size_t len, uint32_t flags);

/* Parses an array of bytes into an integer (base 10). Returns 1 on success,
   0 on failure. */
GPRAPI int gpr_parse_bytes_to_uint32(const char* data, size_t length,
                              uint32_t* result);

/* Minimum buffer size for calling ltoa */
#define GPR_LTOA_MIN_BUFSIZE (3 * sizeof(long))

/* Convert a long to a string in base 10; returns the length of the
   output string (or 0 on failure).
   output must be at least GPR_LTOA_MIN_BUFSIZE bytes long. */
GPRAPI int gpr_ltoa(long value, char* output);

/* Minimum buffer size for calling int64toa */
#define GPR_INT64TOA_MIN_BUFSIZE (3 * sizeof(int64_t))

/* Convert  an int64 to a string in base 10; returns the length of the
output string (or 0 on failure).
output must be at least GPR_INT64TOA_MIN_BUFSIZE bytes long.
NOTE: This function ensures sufficient bit width even on Win x64,
where long is 32bit is size.*/
GPRAPI int int64_ttoa(int64_t value, char* output);

// Parses a non-negative number from a value string.  Returns -1 on error.
GPRAPI int gpr_parse_nonnegative_int(const char* value);

/* Reverse a run of bytes */
GPRAPI void gpr_reverse_bytes(char* str, int len);

/* Pad a string with flag characters. The given length specifies the minimum
   field width. The input string is never truncated. */
GPRAPI char* gpr_leftpad(const char* str, char flag, size_t length);

/* Join a set of strings, returning the resulting string.
   Total combined length (excluding null terminator) is returned in total_length
   if it is non-null. */
GPRAPI char* gpr_strjoin(const char** strs, size_t nstrs, size_t* total_length);

/* Join a set of strings using a separator, returning the resulting string.
   Total combined length (excluding null terminator) is returned in total_length
   if it is non-null. */
GPRAPI char* gpr_strjoin_sep(const char** strs, size_t nstrs, const char* sep,
                      size_t* total_length);

GPRAPI void gpr_string_split(const char* input, const char* sep, char*** strs,
                       size_t* nstrs);

/* A vector of strings... for building up a final string one piece at a time */
typedef struct {
  char** strs;
  size_t count;
  size_t capacity;
} gpr_strvec;

/* Initialize/destroy */
GPRAPI void gpr_strvec_init(gpr_strvec* strs);
GPRAPI void gpr_strvec_destroy(gpr_strvec* strs);
/* Add a string to a strvec, takes ownership of the string */
GPRAPI void gpr_strvec_add(gpr_strvec* strs, char* add);
/* Return a joined string with all added substrings, optionally setting
   total_length as per gpr_strjoin */
GPRAPI char* gpr_strvec_flatten(gpr_strvec* strs, size_t* total_length);

/** Case insensitive string comparison... return <0 if lower(a)<lower(b), ==0 if
    lower(a)==lower(b), >0 if lower(a)>lower(b) */
GPRAPI int gpr_stricmp(const char* a, const char* b);

GPRAPI void* gpr_memrchr(const void* s, int c, size_t n);

/** Return true if lower(s) equals "true", "yes" or "1", otherwise false. */
GPRAPI bool gpr_is_true(const char* s);

#ifdef __cplusplus
}
#endif

#endif /* GRPC_CORE_LIB_SUPPORT_STRING_H */
