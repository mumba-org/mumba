/*	CFSortFunctions.c
	Copyright (c) 1999-2017, Apple Inc. and the Swift project authors
 
	Portions Copyright (c) 2014-2017, Apple Inc. and the Swift project authors
	Licensed under Apache License v2.0 with Runtime Library Exception
	See http://swift.org/LICENSE.txt for license information
	See http://swift.org/CONTRIBUTORS.txt for the list of Swift project authors
	Responsibility: Christopher Kane
*/

#include <CoreFoundation/CFBase.h>
#include "CFInternal.h"
#if __HAS_DISPATCH__
#include <dispatch/dispatch.h>
#if (DEPLOYMENT_TARGET_MACOSX || DEPLOYMENT_TARGET_EMBEDDED) && __has_include(<dispatch/private.h>)
#include <dispatch/private.h>
#else
#define DISPATCH_APPLY_CURRENT_ROOT_QUEUE ((dispatch_queue_t _Nonnull)0)
#endif
#endif
#include "CFLogUtilities.h"
#include "CFInternal.h"

#if __has_include(<checkint.h>)
#include <checkint.h>
#else
enum {
    CHECKINT_NO_ERROR = 0,
    CHECKINT_OVERFLOW_ERROR = (1 << 0),
    CHECKINT_TYPE_ERROR = (1 << 1)
};

#define __check_int32_add(x, y, err)            (x + y)
#define __check_uint32_add(x, y, err)           (x + y)
#define __check_int64_add(x, y, err)            (x + y)
#define __check_uint64_add(x, y, err)           (x + y)

#define __check_int32_sub(x, y, err)            (x - y)
#define __check_uint32_sub(x, y, err)           (x - y)
#define __check_int64_sub(x, y, err)            (x - y)
#define __check_uint64_sub(x, y, err)           (x - y)

#define __check_int32_mul(x, y, err)            (x * y)
#define __check_uint32_mul(x, y, err)           (x * y)
#define __check_int64_mul(x, y, err)            (x * y)
#define __check_uint64_mul(x, y, err)           (x * y)

#define __check_int32_div(x, y, err)            (x / y)
#define __check_uint32_div(x, y, err)           (x / y)
#define __check_int64_div(x, y, err)            (x / y)
#define __check_uint64_div(x, y, err)           (x / y)

#define __checkint_int64_mul(x, y, err)         (x * y)
#define __checkint_uint64_add(x, y, err)        (x + y)
#define __checkint_int32_mul(x,y,err)           (x * y)
#define __checkint_uint32_add(x,y,err)          (x + y)

#endif

enum {
    kCFSortConcurrent = (1 << 0),
    kCFSortStable = (1 << 4),
};

typedef CFIndex VALUE_TYPE;
typedef CFIndex INDEX_TYPE;
typedef CFComparisonResult CMP_RESULT_TYPE;
typedef CMP_RESULT_TYPE (^COMPARATOR_BLOCK)(VALUE_TYPE, VALUE_TYPE);

/*
Number of elements in a list and expected number of compares,
when the initial short-circuiting compare is not done.
1	0
2	1
3	2.667
4	4.667
5	7.167
6	9.833
7	12.733
8	15.733
9	19.167
10	22.667
11	26.2857
12	29.9524
*/

static void __CFSimpleMerge(VALUE_TYPE listp[], INDEX_TYPE cnt1, INDEX_TYPE cnt2, VALUE_TYPE tmp[], COMPARATOR_BLOCK cmp) {
    if (cnt1 <= 0 || cnt2 <= 0) return;
    // if the last element of listp1 <= the first of listp2, lists are already ordered
    if (16 < cnt1 + cnt2 && cmp(listp[cnt1 - 1], listp[cnt1]) <= 0) return;

    INDEX_TYPE idx = 0, idx1 = 0, idx2 = cnt1;
    for (;;) {
        if (cnt1 <= idx1) {
            while (idx--) {
                listp[idx] = tmp[idx];
            }
            return;
        }
        if (cnt1 + cnt2 <= idx2) {
            for (INDEX_TYPE t = cnt1 + cnt2 - 1; idx <= t; t--) {
                listp[t] = listp[t - cnt2];
            }
            while (idx--) {
                listp[idx] = tmp[idx];
            }
            return;
        }
        VALUE_TYPE v1 = listp[idx1], v2 = listp[idx2];
        if (cmp(v1, v2) <= 0) {
            tmp[idx] = v1;
            idx1++;
        } else {
            tmp[idx] = v2;
            idx2++;
        }
        idx++;
    }
}

static void __CFSimpleMergeSort(VALUE_TYPE listp[], INDEX_TYPE cnt, VALUE_TYPE tmp[], COMPARATOR_BLOCK cmp) {
    if (cnt < 2) {
        /* do nothing */
    } else if (2 == cnt) {
        VALUE_TYPE v0 = listp[0], v1 = listp[1];
        if (0 < cmp(v0, v1)) {
            listp[0] = v1;
            listp[1] = v0;
        }
    } else if (3 == cnt) {
        VALUE_TYPE v0 = listp[0], v1 = listp[1], v2 = listp[2], vt;
        if (0 < cmp(v0, v1)) {
            vt = v0;
            v0 = v1;
            v1 = vt;
        }
        if (0 < cmp(v1, v2)) {
            vt = v1;
            v1 = v2;
            v2 = vt;
            if (0 < cmp(v0, v1)) {
                vt = v0;
                v0 = v1;
                v1 = vt;
            }
        }
        listp[0] = v0;
        listp[1] = v1;
        listp[2] = v2;
    } else {
        INDEX_TYPE half_cnt = cnt / 2;
        __CFSimpleMergeSort(listp, half_cnt, tmp, cmp);
        __CFSimpleMergeSort(listp + half_cnt, cnt - half_cnt, tmp, cmp);
        __CFSimpleMerge(listp, half_cnt, cnt - half_cnt, tmp, cmp);
    }
}

#if __HAS_DISPATCH__

// if !right, put the cnt1 smallest values in tmp, else put the cnt2 largest values in tmp
static void __CFSortIndexesNMerge(VALUE_TYPE listp1[], INDEX_TYPE cnt1, VALUE_TYPE listp2[], INDEX_TYPE cnt2, VALUE_TYPE tmp[], size_t right, COMPARATOR_BLOCK cmp) {
    // if the last element of listp1 <= the first of listp2, lists are already ordered
    if (16 < cnt1 + cnt2 && cmp(listp1[cnt1 - 1], listp2[0]) <= 0) {
        memmove(tmp, (right ? listp2 : listp1), (right ? cnt2 : cnt1) * sizeof(VALUE_TYPE));
        return;
    }

    if (right) {
        VALUE_TYPE *listp1_end = listp1;
        VALUE_TYPE *listp2_end = listp2;
        VALUE_TYPE *tmp_end = tmp;
        listp1 += cnt1 - 1;
        listp2 += cnt2 - 1;
        tmp += cnt2;
        while (tmp_end < tmp) {
            tmp--;
            if (listp2 < listp2_end) {
                listp1--;
                *tmp = *listp1;
            } else if (listp1 < listp1_end) {
                listp2--;
                *tmp = *listp2;
            } else {
                VALUE_TYPE v1 = *listp1, v2 = *listp2;
                CMP_RESULT_TYPE res = cmp(v1, v2);
                if (res <= 0) {
                    *tmp = v2;
                    listp2--;
                } else {
                    *tmp = v1;
                    listp1--;
                }
            }
        }
    } else {
        VALUE_TYPE *listp1_end = listp1 + cnt1;
        VALUE_TYPE *listp2_end = listp2 + cnt2;
        VALUE_TYPE *tmp_end = tmp + cnt1;
        while (tmp < tmp_end) {
            if (listp2_end <= listp2) {
                *tmp = *listp1;
                listp1++;
            } else if (listp1_end <= listp1) {
                *tmp = *listp2;
                listp2++;
            } else {
                VALUE_TYPE v1 = *listp1, v2 = *listp2;
                CMP_RESULT_TYPE res = cmp(v1, v2);
                if (res <= 0) {
                    *tmp = v1;
                    listp1++;
                } else {
                    *tmp = v2;
                    listp2++;
                }
            }
            tmp++;
        }
    }
}

/* Merging algorithm based on
    "A New Parallel Sorting Algorithm based on Odd-Even Mergesort", Ezequiel Herruzo, et al
*/
static void __CFSortIndexesN(VALUE_TYPE listp[], INDEX_TYPE count, int32_t ncores, CMP_RESULT_TYPE (^cmp)(INDEX_TYPE, INDEX_TYPE)) {
    /* Divide the array up into up to ncores, multiple-of-16-sized, chunks */
    INDEX_TYPE sz = ((((count + ncores - 1) / ncores) + 15) / 16) * 16;
    INDEX_TYPE num_sect = (count + sz - 1) / sz;
    INDEX_TYPE last_sect_len = count + sz - sz * num_sect;

    STACK_BUFFER_DECL(VALUE_TYPE *, stack_tmps, num_sect);
    for (INDEX_TYPE idx = 0; idx < num_sect; idx++) {
        stack_tmps[idx] = (VALUE_TYPE *)malloc(sz * sizeof(VALUE_TYPE));
    }
    VALUE_TYPE **tmps = stack_tmps;

    dispatch_apply(num_sect, DISPATCH_APPLY_CURRENT_ROOT_QUEUE, ^(size_t sect) {
            INDEX_TYPE sect_len = (sect < num_sect - 1) ? sz : last_sect_len;
            __CFSimpleMergeSort(listp + sect * sz, sect_len, tmps[sect], cmp); // naturally stable
        });

    INDEX_TYPE even_phase_cnt = ((num_sect / 2) * 2);
    INDEX_TYPE odd_phase_cnt = (((num_sect - 1) / 2) * 2);
    for (INDEX_TYPE idx = 0; idx < (num_sect + 1) / 2; idx++) {
        dispatch_apply(even_phase_cnt, DISPATCH_APPLY_CURRENT_ROOT_QUEUE, ^(size_t sect) { // merge even
                size_t right = sect & (size_t)0x1;
                VALUE_TYPE *left_base = listp + sect * sz - (right ? sz : 0);
                VALUE_TYPE *right_base = listp + sect * sz + (right ? 0 : sz);
                INDEX_TYPE sect2_len = (sect + 1 + (right ? 0 : 1) == num_sect) ? last_sect_len : sz;
                __CFSortIndexesNMerge(left_base, sz, right_base, sect2_len, tmps[sect], right, cmp);
            });
        if (num_sect & 0x1) {
            memmove(tmps[num_sect - 1], listp + (num_sect - 1) * sz, last_sect_len * sizeof(VALUE_TYPE));
        }
        dispatch_apply(odd_phase_cnt, DISPATCH_APPLY_CURRENT_ROOT_QUEUE, ^(size_t sect) { // merge odd
                size_t right = sect & (size_t)0x1;
                VALUE_TYPE *left_base = tmps[sect + (right ? 0 : 1)];
                VALUE_TYPE *right_base = tmps[sect + (right ? 1 : 2)];
                INDEX_TYPE sect2_len = (sect + 1 + (right ? 1 : 2) == num_sect) ? last_sect_len : sz;
                __CFSortIndexesNMerge(left_base, sz, right_base, sect2_len, listp + sect * sz + sz, right, cmp);
            });
        memmove(listp + 0 * sz, tmps[0], sz * sizeof(VALUE_TYPE));
        if (!(num_sect & 0x1)) {
            memmove(listp + (num_sect - 1) * sz, tmps[num_sect - 1], last_sect_len * sizeof(VALUE_TYPE));
        }
    }

    for (INDEX_TYPE idx = 0; idx < num_sect; idx++) {
        free(stack_tmps[idx]);
    }
}
#endif

// fills an array of indexes (of length count) giving the indexes 0 - count-1, as sorted by the comparator block
void CFSortIndexes(CFIndex *indexBuffer, CFIndex count, CFOptionFlags opts, CFComparisonResult (^cmp)(CFIndex, CFIndex)) {
    if (count < 1) return;
    if (INTPTR_MAX / sizeof(CFIndex) < count) return;
    int32_t ncores = 0;
    if (opts & kCFSortConcurrent) {
        ncores = __CFActiveProcessorCount();
        if (count < 160 || ncores < 2) {
            opts = (opts & ~kCFSortConcurrent);
        } else if (count < 640 && 2 < ncores) {
            ncores = 2;
        } else if (count < 3200 && 4 < ncores) {
            ncores = 4;
        } else if (count < 16000 && 8 < ncores) {
            ncores = 8;
        }
        if (16 < ncores) {
            ncores = 16;
        }
    }
#if __HAS_DISPATCH__
    if (count <= 65536) {
        for (CFIndex idx = 0; idx < count; idx++) indexBuffer[idx] = idx;
    } else {
        /* Specifically hard-coded to 8; the count has to be very large before more chunks and/or cores is worthwhile. */
        dispatch_queue_t q = dispatch_queue_create(__CF_QUEUE_NAME("NSSortIndexes"), DISPATCH_QUEUE_CONCURRENT);
        CFIndex sz = ((((size_t)count + 15) / 16) * 16) / 8;
        dispatch_apply(8, DISPATCH_APPLY_CURRENT_ROOT_QUEUE, ^(size_t n) {
                CFIndex idx = n * sz, lim = __CFMin(idx + sz, count);
                for (; idx < lim; idx++) indexBuffer[idx] = idx;
            });
        dispatch_release(q);
    }
#else
    for (CFIndex idx = 0; idx < count; idx++) indexBuffer[idx] = idx;
#endif
#if __HAS_DISPATCH__
    if (opts & kCFSortConcurrent) {
        __CFSortIndexesN(indexBuffer, count, ncores, cmp); // naturally stable
        return;
    }
#endif
    STACK_BUFFER_DECL(VALUE_TYPE, local, count <= 4096 ? count : 1);
    VALUE_TYPE *tmp = (count <= 4096) ? local : (VALUE_TYPE *)malloc(count * sizeof(VALUE_TYPE));
    __CFSimpleMergeSort(indexBuffer, count, tmp, cmp); // naturally stable
    if (local != tmp) free(tmp);
}

typedef CF_ENUM(uint8_t, _CFOverflowResult) {
    _CFOverflowResultOK = 0,
    _CFOverflowResultNegativeParameters,
    _CFOverflowResultOverflows,
};

// Overflow utilities for positive integers
CF_INLINE _CFOverflowResult _CFIntegerProductWouldOverflow(CFIndex si_a, CFIndex si_b) {
    _CFOverflowResult result = _CFOverflowResultOK;
    if (si_a < 0 || si_b < 0) {
        // we explicitly only implement a subset of the overflow checking, so report failure if out of domain
        result = _CFOverflowResultNegativeParameters;
    } else {
        int32_t err = CHECKINT_NO_ERROR;
#if __LP64__
        __checkint_int64_mul(si_a, si_b, &err);
#else
        __checkint_int32_mul(si_a, si_b, &err);
#endif
        if (err != CHECKINT_NO_ERROR) {
            result = _CFOverflowResultOverflows;
        }
    }
    return result;
}
CF_INLINE _CFOverflowResult _CFPointerSumWouldOverflow(void *p, size_t n) {
    _CFOverflowResult result = _CFOverflowResultOK;
    int32_t err = CHECKINT_NO_ERROR;
#if __LP64__
    __checkint_uint64_add((uint64_t)p, (uint64_t)n, &err);
#else
    __checkint_uint32_add((uint32_t)p, (uint32_t)n, &err);
#endif
    if (err != CHECKINT_NO_ERROR) {
        result = _CFOverflowResultOverflows;
    }
    return result;
}

/* Comparator is passed the address of the values. */
void CFQSortArray(void *list, CFIndex count, CFIndex elementSize, CFComparatorFunction comparator, void *context) {
    if (count < 2 || elementSize < 1) return;
    _CFOverflowResult overflowResult = _CFIntegerProductWouldOverflow(count, elementSize);
    if (overflowResult != _CFOverflowResultOK) {
        CFLog(kCFLogLevelError, CFSTR("Unable to qsort array - count: %ld elementSize: %ld product overflows"), (long)count, (long)elementSize);
        CRSetCrashLogMessage("qsort - count/elementSize overflow");
        HALT;
    }
    overflowResult = _CFPointerSumWouldOverflow(list, count * elementSize);
    if (overflowResult != _CFOverflowResultOK) {
        CFLog(kCFLogLevelError, CFSTR("Unable to qsort array - list: %lu count: %ld elementSize: %ld - array access overflows"), (unsigned long)list, (long)count, (long)elementSize);
        CRSetCrashLogMessage("qsort - array access overflow");
        HALT;
    }
    STACK_BUFFER_DECL(CFIndex, locali, count <= 4096 ? count : 1);
    CFIndex *indexes = (count <= 4096) ? locali : (CFIndex *)malloc(count * sizeof(CFIndex));
    if (indexes == NULL) {
        CFLog(kCFLogLevelError, CFSTR("unable to qsort array - malloc failed"));
        CRSetCrashLogMessage("qsort - malloc failed");
        HALT;
    }
    CFSortIndexes(indexes, count, 0, ^(CFIndex a, CFIndex b) { return comparator((char *)list + a * elementSize, (char *)list + b * elementSize, context); });
    STACK_BUFFER_DECL(uint8_t, locals, count <= (16 * 1024 / elementSize) ? count * elementSize : 1);
    void *store = (count <= (16 * 1024 / elementSize)) ? locals : malloc(count * elementSize);
    overflowResult = _CFPointerSumWouldOverflow(store, count * elementSize);
    if (overflowResult != _CFOverflowResultOK) {
        CFLog(kCFLogLevelError, CFSTR("Unable to qsort array - list: %lu count: %ld elementSize: %ld array - store overflows"), (unsigned long)list, (long)count, (long)elementSize);
        CRSetCrashLogMessage("qsort - array storage overflow");
        HALT;
    }
    for (CFIndex idx = 0; idx < count; idx++) {
        if (sizeof(uintptr_t) == elementSize) {
            uintptr_t *a = (uintptr_t *)list + indexes[idx];
            uintptr_t *b = (uintptr_t *)store + idx;
            *b = *a;
        } else {
            memmove((char *)store + idx * elementSize, (char *)list + indexes[idx] * elementSize, elementSize);
        }
    }
    // no swapping or modification of the original list has occurred until this point
    memmove(list, store, count * elementSize);
    if (locals != store) free(store);
    if (locali != indexes) free(indexes);
}

/* Comparator is passed the address of the values. */
void CFMergeSortArray(void *list, CFIndex count, CFIndex elementSize, CFComparatorFunction comparator, void *context) {
    if (count < 2 || elementSize < 1) return;
    _CFOverflowResult overflowResult = _CFIntegerProductWouldOverflow(count, elementSize);
    if (overflowResult != _CFOverflowResultOK) {
        CFLog(kCFLogLevelError, CFSTR("Unable to mergesort array - count: %ld elementSize: %ld overflows"), (long)count, (long)elementSize);
        CRSetCrashLogMessage("merge sort - count/elementSize overflow");
        HALT;
    }
    overflowResult = _CFPointerSumWouldOverflow(list, count * elementSize);
    if (overflowResult != _CFOverflowResultOK) {
        CFLog(kCFLogLevelError, CFSTR("Unable to mergesort array - list: %lu count: %ld elementSize: %ld - array access overflows"), (unsigned long)list, (long)count, (long)elementSize);
        CRSetCrashLogMessage("merge sort - array access overflow");
        HALT;
    }
    STACK_BUFFER_DECL(CFIndex, locali, count <= 4096 ? count : 1);
    CFIndex *indexes = (count <= 4096) ? locali : (CFIndex *)malloc(count * sizeof(CFIndex));
    if (indexes == NULL) {
        CFLog(kCFLogLevelError, CFSTR("unable to mergesort array - malloc failed"));
        CRSetCrashLogMessage("merge sort - malloc failure");
        HALT;
    }
    CFSortIndexes(indexes, count, kCFSortStable, ^(CFIndex a, CFIndex b) { return comparator((char *)list + a * elementSize, (char *)list + b * elementSize, context); });
    STACK_BUFFER_DECL(uint8_t, locals, count <= (16 * 1024 / elementSize) ? count * elementSize : 1);
    void *store = (count <= (16 * 1024 / elementSize)) ? locals : malloc(count * elementSize);
    overflowResult = _CFPointerSumWouldOverflow(store, count * elementSize);
    if (overflowResult != _CFOverflowResultOK) {
        CFLog(kCFLogLevelError, CFSTR("Unable to mergesort array - list: %lu count: %ld elementSize: %ld - array store overflows"), (unsigned long)list, (long)count, (long)elementSize);
        CRSetCrashLogMessage("merge sort - overflow array storage");
        HALT;
    }
    for (CFIndex idx = 0; idx < count; idx++) {
        if (sizeof(uintptr_t) == elementSize) {
            uintptr_t *a = (uintptr_t *)list + indexes[idx];
            uintptr_t *b = (uintptr_t *)store + idx;
            *b = *a;
        } else {
            memmove((char *)store + idx * elementSize, (char *)list + indexes[idx] * elementSize, elementSize);
        }
    }
    // no swapping or modification of the original list has occurred until this point
    memmove(list, store, count * elementSize);
    if (locals != store) free(store);
    if (locali != indexes) free(indexes);
}


