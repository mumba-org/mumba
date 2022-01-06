/*	CFSet.c
	Copyright (c) 1998-2017, Apple Inc. and the Swift project authors
 
    Portions Copyright (c) 2014-2017, Apple Inc. and the Swift project authors
    Licensed under Apache License v2.0 with Runtime Library Exception
    See http://swift.org/LICENSE.txt for license information
    See http://swift.org/CONTRIBUTORS.txt for the list of Swift project authors
	Responsibility: Michael LeHew
	Machine generated from Notes/HashingCode.template
*/





#include <CoreFoundation/CFSet.h>
#include "CFInternal.h"
#include "CFBasicHash.h"
#include <CoreFoundation/CFString.h>


#define CFDictionary 0
#define CFSet 0
#define CFBag 0
#undef CFSet
#define CFSet 1

#if CFDictionary


const CFSetKeyCallBacks kCFTypeSetKeyCallBacks = {0, __CFTypeCollectionRetain, __CFTypeCollectionRelease, CFCopyDescription, CFEqual, CFHash};
const CFSetKeyCallBacks kCFCopyStringSetKeyCallBacks = {0, __CFStringCollectionCopy, __CFTypeCollectionRelease, CFCopyDescription, CFEqual, CFHash};
const CFSetValueCallBacks kCFTypeSetValueCallBacks = {0, __CFTypeCollectionRetain, __CFTypeCollectionRelease, CFCopyDescription, CFEqual};

#define CFHashRef CFDictionaryRef
#define CFMutableHashRef CFMutableDictionaryRef
#define CFHashKeyCallBacks CFSetKeyCallBacks
#define CFHashValueCallBacks CFSetValueCallBacks
#endif

#if CFSet
const CFSetCallBacks kCFTypeSetCallBacks = {0, __CFTypeCollectionRetain, __CFTypeCollectionRelease, CFCopyDescription, CFEqual, CFHash};
const CFSetCallBacks kCFCopyStringSetCallBacks = {0, __CFStringCollectionCopy, __CFTypeCollectionRelease, CFCopyDescription, CFEqual, CFHash};

#define CFSetKeyCallBacks CFSetCallBacks
#define CFSetValueCallBacks CFSetCallBacks
#define kCFTypeSetKeyCallBacks kCFTypeSetCallBacks
#define kCFTypeSetValueCallBacks kCFTypeSetCallBacks

#define CFHashRef CFSetRef
#define CFMutableHashRef CFMutableSetRef
#define CFHashKeyCallBacks CFSetCallBacks
#define CFHashValueCallBacks CFSetCallBacks
#endif

#if CFBag
const CFSetCallBacks kCFTypeSetCallBacks = {0, __CFTypeCollectionRetain, __CFTypeCollectionRelease, CFCopyDescription, CFEqual, CFHash};
const CFSetCallBacks kCFCopyStringSetCallBacks = {0, __CFStringCollectionCopy, __CFTypeCollectionRelease, CFCopyDescription, CFEqual, CFHash};

#define CFSetKeyCallBacks CFSetCallBacks
#define CFSetValueCallBacks CFSetCallBacks
#define kCFTypeSetKeyCallBacks kCFTypeSetCallBacks
#define kCFTypeSetValueCallBacks kCFTypeSetCallBacks

#define CFHashRef CFBagRef
#define CFMutableHashRef CFMutableBagRef
#define CFHashKeyCallBacks CFSetCallBacks
#define CFHashValueCallBacks CFSetCallBacks
#endif


typedef uintptr_t any_t;
typedef const void * const_any_pointer_t;
typedef void * any_pointer_t;

static Boolean __CFSetEqual(CFTypeRef cf1, CFTypeRef cf2) {
    return __CFBasicHashEqual((CFBasicHashRef)cf1, (CFBasicHashRef)cf2);
}

static CFHashCode __CFSetHash(CFTypeRef cf) {
    return __CFBasicHashHash((CFBasicHashRef)cf);
}

static CFStringRef __CFSetCopyDescription(CFTypeRef cf) {
    return __CFBasicHashCopyDescription((CFBasicHashRef)cf);
}

static void __CFSetDeallocate(CFTypeRef cf) {
    __CFBasicHashDeallocate((CFBasicHashRef)cf);
}

static CFTypeID __kCFSetTypeID = _kCFRuntimeNotATypeID;

static const CFRuntimeClass __CFSetClass = {
    _kCFRuntimeScannedObject,
    "CFSet",
    NULL,        // init
    NULL,        // copy
    __CFSetDeallocate,
    __CFSetEqual,
    __CFSetHash,
    NULL,        //
    __CFSetCopyDescription
};

CFTypeID CFSetGetTypeID(void) {
    static dispatch_once_t initOnce;
    dispatch_once(&initOnce, ^{
        __kCFSetTypeID = _CFRuntimeRegisterClass(&__CFSetClass);
    });
    return __kCFSetTypeID;
}


static CFBasicHashRef __CFSetCreateGeneric(CFAllocatorRef allocator, const CFHashKeyCallBacks *keyCallBacks, const CFHashValueCallBacks *valueCallBacks, Boolean useValueCB) {
    CFOptionFlags flags = kCFBasicHashLinearHashing; // kCFBasicHashExponentialHashing
    flags |= (CFDictionary ? kCFBasicHashHasKeys : 0) | (CFBag ? kCFBasicHashHasCounts : 0);


    CFBasicHashCallbacks callbacks;
    callbacks.retainKey = keyCallBacks ? (uintptr_t (*)(CFAllocatorRef, uintptr_t))keyCallBacks->retain : NULL;
    callbacks.releaseKey = keyCallBacks ? (void (*)(CFAllocatorRef, uintptr_t))keyCallBacks->release : NULL;
    callbacks.equateKeys = keyCallBacks ? (Boolean (*)(uintptr_t, uintptr_t))keyCallBacks->equal : NULL;
    callbacks.hashKey = keyCallBacks ? (CFHashCode (*)(uintptr_t))keyCallBacks->hash : NULL;
    callbacks.getIndirectKey = NULL;
    callbacks.copyKeyDescription = keyCallBacks ? (CFStringRef (*)(uintptr_t))keyCallBacks->copyDescription : NULL;
    callbacks.retainValue = useValueCB ? (valueCallBacks ? (uintptr_t (*)(CFAllocatorRef, uintptr_t))valueCallBacks->retain : NULL) : (callbacks.retainKey);
    callbacks.releaseValue = useValueCB ? (valueCallBacks ? (void (*)(CFAllocatorRef, uintptr_t))valueCallBacks->release : NULL) : (callbacks.releaseKey);
    callbacks.equateValues = useValueCB ? (valueCallBacks ? (Boolean (*)(uintptr_t, uintptr_t))valueCallBacks->equal : NULL) : (callbacks.equateKeys);
    callbacks.copyValueDescription = useValueCB ? (valueCallBacks ? (CFStringRef (*)(uintptr_t))valueCallBacks->copyDescription : NULL) : (callbacks.copyKeyDescription);

    CFBasicHashRef ht = CFBasicHashCreate(allocator, flags, &callbacks);
    return ht;
}

#if CFDictionary
CF_PRIVATE CFHashRef __CFSetCreateTransfer(CFAllocatorRef allocator, const_any_pointer_t *klist, const_any_pointer_t *vlist, CFIndex numValues) {
#endif
#if CFSet || CFBag
CF_PRIVATE CFHashRef __CFSetCreateTransfer(CFAllocatorRef allocator, const_any_pointer_t *klist, CFIndex numValues) {
    const_any_pointer_t *vlist = klist;
#endif
    CFTypeID typeID = CFSetGetTypeID();
    CFAssert2(0 <= numValues, __kCFLogAssertion, "%s(): numValues (%ld) cannot be less than zero", __PRETTY_FUNCTION__, numValues);
    CFOptionFlags flags = kCFBasicHashLinearHashing; // kCFBasicHashExponentialHashing
    flags |= (CFDictionary ? kCFBasicHashHasKeys : 0) | (CFBag ? kCFBasicHashHasCounts : 0);

    CFBasicHashCallbacks callbacks;
    callbacks.retainKey = (uintptr_t (*)(CFAllocatorRef, uintptr_t))kCFTypeSetKeyCallBacks.retain;
    callbacks.releaseKey = (void (*)(CFAllocatorRef, uintptr_t))kCFTypeSetKeyCallBacks.release;
    callbacks.equateKeys = (Boolean (*)(uintptr_t, uintptr_t))kCFTypeSetKeyCallBacks.equal;
    callbacks.hashKey = (CFHashCode (*)(uintptr_t))kCFTypeSetKeyCallBacks.hash;
    callbacks.getIndirectKey = NULL;
    callbacks.copyKeyDescription = (CFStringRef (*)(uintptr_t))kCFTypeSetKeyCallBacks.copyDescription;
    callbacks.retainValue = CFDictionary ? (uintptr_t (*)(CFAllocatorRef, uintptr_t))kCFTypeSetValueCallBacks.retain : callbacks.retainKey;
    callbacks.releaseValue = CFDictionary ? (void (*)(CFAllocatorRef, uintptr_t))kCFTypeSetValueCallBacks.release : callbacks.releaseKey;
    callbacks.equateValues = CFDictionary ? (Boolean (*)(uintptr_t, uintptr_t))kCFTypeSetValueCallBacks.equal : callbacks.equateKeys;
    callbacks.copyValueDescription = CFDictionary ? (CFStringRef (*)(uintptr_t))kCFTypeSetValueCallBacks.copyDescription : callbacks.copyKeyDescription;

    CFBasicHashRef ht = CFBasicHashCreate(allocator, flags, &callbacks);
    CFBasicHashSuppressRC(ht);
    if (0 < numValues) CFBasicHashSetCapacity(ht, numValues);
    for (CFIndex idx = 0; idx < numValues; idx++) {
        CFBasicHashAddValue(ht, (uintptr_t)klist[idx], (uintptr_t)vlist[idx]);
    }
    CFBasicHashUnsuppressRC(ht);
    CFBasicHashMakeImmutable(ht);
    _CFRuntimeSetInstanceTypeIDAndIsa(ht, typeID);
    if (__CFOASafe) __CFSetLastAllocationEventName(ht, "CFSet (immutable)");
    return (CFHashRef)ht;
}

#if CFDictionary
CFHashRef CFSetCreate(CFAllocatorRef allocator, const_any_pointer_t *klist, const_any_pointer_t *vlist, CFIndex numValues, const CFSetKeyCallBacks *keyCallBacks, const CFSetValueCallBacks *valueCallBacks) {
#endif
#if CFSet || CFBag
CFHashRef CFSetCreate(CFAllocatorRef allocator, const_any_pointer_t *klist, CFIndex numValues, const CFSetKeyCallBacks *keyCallBacks) {
    const_any_pointer_t *vlist = klist;
    const CFSetValueCallBacks *valueCallBacks = 0;
#endif
    CFTypeID typeID = CFSetGetTypeID();
    CFAssert2(0 <= numValues, __kCFLogAssertion, "%s(): numValues (%ld) cannot be less than zero", __PRETTY_FUNCTION__, numValues);
    CFBasicHashRef ht = __CFSetCreateGeneric(allocator, keyCallBacks, valueCallBacks, CFDictionary);
    if (!ht) return NULL;
    if (0 < numValues) CFBasicHashSetCapacity(ht, numValues);
    for (CFIndex idx = 0; idx < numValues; idx++) {
        CFBasicHashAddValue(ht, (uintptr_t)klist[idx], (uintptr_t)vlist[idx]);
    }
    CFBasicHashMakeImmutable(ht);
    _CFRuntimeSetInstanceTypeIDAndIsa(ht, typeID);
    if (__CFOASafe) __CFSetLastAllocationEventName(ht, "CFSet (immutable)");
    return (CFHashRef)ht;
}

#if CFDictionary
CFMutableHashRef CFSetCreateMutable(CFAllocatorRef allocator, CFIndex capacity, const CFSetKeyCallBacks *keyCallBacks, const CFSetValueCallBacks *valueCallBacks) {
#endif
#if CFSet || CFBag
CFMutableHashRef CFSetCreateMutable(CFAllocatorRef allocator, CFIndex capacity, const CFSetKeyCallBacks *keyCallBacks) {
    const CFSetValueCallBacks *valueCallBacks = 0;
#endif
    CFTypeID typeID = CFSetGetTypeID();
    CFAssert2(0 <= capacity, __kCFLogAssertion, "%s(): capacity (%ld) cannot be less than zero", __PRETTY_FUNCTION__, capacity);
    CFBasicHashRef ht = __CFSetCreateGeneric(allocator, keyCallBacks, valueCallBacks, CFDictionary);
    if (!ht) return NULL;
    _CFRuntimeSetInstanceTypeIDAndIsa(ht, typeID);
    if (__CFOASafe) __CFSetLastAllocationEventName(ht, "CFSet (mutable)");
    return (CFMutableHashRef)ht;
}

CFHashRef CFSetCreateCopy(CFAllocatorRef allocator, CFHashRef other) {
    CFTypeID typeID = CFSetGetTypeID();
    CFAssert1(other, __kCFLogAssertion, "%s(): other CFSet cannot be NULL", __PRETTY_FUNCTION__);
    __CFGenericValidateType(other, typeID);
    Boolean markImmutable = false;
    CFBasicHashRef ht = NULL;
    if (CF_IS_OBJC(typeID, other)) {
#if CFDictionary || CFSet
        ht = (CFBasicHashRef)CF_OBJC_CALLV((id)other, copyWithZone:NULL);
#elif CFBag
        CFIndex numValues = CFSetGetCount(other);
        const_any_pointer_t vbuffer[256];
        const_any_pointer_t *vlist = (numValues <= 256) ? vbuffer : (const_any_pointer_t *)CFAllocatorAllocate(kCFAllocatorSystemDefault, numValues * sizeof(const_any_pointer_t), 0);
        const_any_pointer_t *klist = vlist;
        CFSetGetValues(other, vlist);
        ht = __CFSetCreateGeneric(allocator, & kCFTypeSetKeyCallBacks, CFDictionary ? & kCFTypeSetValueCallBacks : NULL, CFDictionary);
        if (ht && 0 < numValues) CFBasicHashSetCapacity(ht, numValues);
        for (CFIndex idx = 0; ht && idx < numValues; idx++) {
            CFBasicHashAddValue(ht, (uintptr_t)klist[idx], (uintptr_t)vlist[idx]);
        }
        if (vlist != vbuffer) CFAllocatorDeallocate(kCFAllocatorSystemDefault, vlist);
        markImmutable = true;
#endif // CFBag
    } else if (CF_IS_SWIFT(typeID, other)) {
#if CFDictionary || CFSet
        ht = (CFBasicHashRef)CF_SWIFT_CALLV(other, NSObject.copyWithZone, nil);
#endif
    } else { // non-objc types
        ht = CFBasicHashCreateCopy(allocator, (CFBasicHashRef)other);
        markImmutable = true;
    }
    if (ht && markImmutable) {
        CFBasicHashMakeImmutable(ht);
        _CFRuntimeSetInstanceTypeIDAndIsa(ht, typeID);
        if (__CFOASafe) __CFSetLastAllocationEventName(ht, "CFSet (immutable)");
        return (CFHashRef)ht;
    }
    return (CFHashRef)ht;
}

CFMutableHashRef CFSetCreateMutableCopy(CFAllocatorRef allocator, CFIndex capacity, CFHashRef other) {
    CFTypeID typeID = CFSetGetTypeID();
    CFAssert1(other, __kCFLogAssertion, "%s(): other CFSet cannot be NULL", __PRETTY_FUNCTION__);
    __CFGenericValidateType(other, typeID);
    CFAssert2(0 <= capacity, __kCFLogAssertion, "%s(): capacity (%ld) cannot be less than zero", __PRETTY_FUNCTION__, capacity);
    CFBasicHashRef ht = NULL;
    if (CF_IS_OBJC(typeID, other) || CF_IS_SWIFT(typeID, other)) {
        CFIndex numValues = CFSetGetCount(other);
        const_any_pointer_t vbuffer[256], kbuffer[256];
        const_any_pointer_t *vlist = (numValues <= 256) ? vbuffer : (const_any_pointer_t *)CFAllocatorAllocate(kCFAllocatorSystemDefault, numValues * sizeof(const_any_pointer_t), 0);
#if CFSet || CFBag
        const_any_pointer_t *klist = vlist;
        CFSetGetValues(other, vlist);
#endif
#if CFDictionary
        const_any_pointer_t *klist = (numValues <= 256) ? kbuffer : (const_any_pointer_t *)CFAllocatorAllocate(kCFAllocatorSystemDefault, numValues * sizeof(const_any_pointer_t), 0);
        CFDictionaryGetKeysAndValues(other, klist, vlist);
#endif
        ht = __CFSetCreateGeneric(allocator, & kCFTypeSetKeyCallBacks, CFDictionary ? & kCFTypeSetValueCallBacks : NULL, CFDictionary);
        if (ht && 0 < numValues) CFBasicHashSetCapacity(ht, numValues);
        for (CFIndex idx = 0; ht && idx < numValues; idx++) {
            CFBasicHashAddValue(ht, (uintptr_t)klist[idx], (uintptr_t)vlist[idx]);
        }
        if (klist != kbuffer && klist != vlist) CFAllocatorDeallocate(kCFAllocatorSystemDefault, klist);
        if (vlist != vbuffer) CFAllocatorDeallocate(kCFAllocatorSystemDefault, vlist);
    } else {
        ht = CFBasicHashCreateCopy(allocator, (CFBasicHashRef)other);
    }
    if (!ht) return NULL;
    _CFRuntimeSetInstanceTypeIDAndIsa(ht, typeID);
    if (__CFOASafe) __CFSetLastAllocationEventName(ht, "CFSet (mutable)");
    return (CFMutableHashRef)ht;
}

CFIndex CFSetGetCount(CFHashRef hc) {
#if CFDictionary
    if (CFDictionary) CF_SWIFT_FUNCDISPATCHV(CFSetGetTypeID(), CFIndex, (CFSwiftRef)hc, NSDictionary.count);
    if (CFDictionary) CF_OBJC_FUNCDISPATCHV(CFSetGetTypeID(), CFIndex, (NSDictionary *)hc, count);
#endif
#if CFSet
    if (CFSet) CF_SWIFT_FUNCDISPATCHV(CFSetGetTypeID(), CFIndex, (CFSwiftRef)hc, NSSet.count);
    if (CFSet) CF_OBJC_FUNCDISPATCHV(CFSetGetTypeID(), CFIndex, (NSSet *)hc, count);
#endif
    __CFGenericValidateType(hc, CFSetGetTypeID());
    return CFBasicHashGetCount((CFBasicHashRef)hc);
}

#if CFDictionary
CFIndex CFSetGetCountOfKey(CFHashRef hc, const_any_pointer_t key) {
#endif
#if CFSet || CFBag
CFIndex CFSetGetCountOfValue(CFHashRef hc, const_any_pointer_t key) {
#endif
#if CFDictionary
    if (CFDictionary) CF_SWIFT_FUNCDISPATCHV(CFSetGetTypeID(), CFIndex, (CFSwiftRef)hc, NSDictionary.countForKey, key);
    if (CFDictionary) CF_OBJC_FUNCDISPATCHV(CFSetGetTypeID(), CFIndex, (NSDictionary *)hc, countForKey:(id)key);
#endif
#if CFSet
    if (CFSet) CF_SWIFT_FUNCDISPATCHV(CFSetGetTypeID(), CFIndex, (CFSwiftRef)hc, NSSet.countForKey, key);
    if (CFSet) CF_OBJC_FUNCDISPATCHV(CFSetGetTypeID(), CFIndex, (NSSet *)hc, countForObject:(id)key);
#endif
    __CFGenericValidateType(hc, CFSetGetTypeID());
    return CFBasicHashGetCountOfKey((CFBasicHashRef)hc, (uintptr_t)key);
}

#if CFDictionary
Boolean CFSetContainsKey(CFHashRef hc, const_any_pointer_t key) {
#endif
#if CFSet || CFBag
Boolean CFSetContainsValue(CFHashRef hc, const_any_pointer_t key) {
#endif
#if CFDictionary
    if (CFDictionary) CF_SWIFT_FUNCDISPATCHV(CFSetGetTypeID(), char, (CFSwiftRef)hc, NSDictionary.containsKey, key);
    if (CFDictionary) CF_OBJC_FUNCDISPATCHV(CFSetGetTypeID(), char, (NSDictionary *)hc, containsKey:(id)key);
#endif
#if CFSet
    if (CFSet) CF_SWIFT_FUNCDISPATCHV(CFSetGetTypeID(), char, (CFSwiftRef)hc, NSSet.containsObject, (CFSwiftRef)key);
    if (CFSet) CF_OBJC_FUNCDISPATCHV(CFSetGetTypeID(), char, (NSSet *)hc, containsObject:(id)key);
#endif
    __CFGenericValidateType(hc, CFSetGetTypeID());
    return (0 < CFBasicHashGetCountOfKey((CFBasicHashRef)hc, (uintptr_t)key));
}

const_any_pointer_t CFSetGetValue(CFHashRef hc, const_any_pointer_t key) {
#if CFDictionary
    if (CFDictionary) CF_SWIFT_FUNCDISPATCHV(CFSetGetTypeID(), const_any_pointer_t, (CFSwiftRef)hc, NSDictionary.objectForKey, key);
    if (CFDictionary) CF_OBJC_FUNCDISPATCHV(CFSetGetTypeID(), const_any_pointer_t, (NSDictionary *)hc, objectForKey:(id)key);
#endif
#if CFSet
    if (CFSet) CF_SWIFT_FUNCDISPATCHV(CFSetGetTypeID(), const_any_pointer_t, (CFSwiftRef)hc, NSSet.member, key);
    if (CFSet) CF_OBJC_FUNCDISPATCHV(CFSetGetTypeID(), const_any_pointer_t, (NSSet *)hc, member:(id)key);
#endif
    __CFGenericValidateType(hc, CFSetGetTypeID());
    CFBasicHashBucket bkt = CFBasicHashFindBucket((CFBasicHashRef)hc, (uintptr_t)key);
    return (0 < bkt.count ? (const_any_pointer_t)bkt.weak_value : 0);
}

Boolean CFSetGetValueIfPresent(CFHashRef hc, const_any_pointer_t key, const_any_pointer_t *value) {
#if CFDictionary
    if (CFDictionary) CF_SWIFT_FUNCDISPATCHV(CFSetGetTypeID(), Boolean, (CFSwiftRef)hc, NSDictionary.__getValue, value, key);
    if (CFDictionary) CF_OBJC_FUNCDISPATCHV(CFSetGetTypeID(), Boolean, (NSDictionary *)hc, __getValue:(id *)value forKey:(id)key);
#endif
#if CFSet
    if (CFSet) CF_SWIFT_FUNCDISPATCHV(CFSetGetTypeID(), Boolean, (CFSwiftRef)hc, NSSet.__getValue, value, key);
    if (CFSet) CF_OBJC_FUNCDISPATCHV(CFSetGetTypeID(), Boolean, (NSSet *)hc, __getValue:(id *)value forObj:(id)key);
#endif
    __CFGenericValidateType(hc, CFSetGetTypeID());
    CFBasicHashBucket bkt = CFBasicHashFindBucket((CFBasicHashRef)hc, (uintptr_t)key);
    if (0 < bkt.count) {
        if (value) {
            *value = (const_any_pointer_t)bkt.weak_value;
        }
        return true;
    }
    return false;
}

#if CFDictionary
CFIndex CFDictionaryGetCountOfValue(CFHashRef hc, const_any_pointer_t value) {
    CF_SWIFT_FUNCDISPATCHV(CFSetGetTypeID(), CFIndex, (CFSwiftRef)hc, NSDictionary.count);
    CF_OBJC_FUNCDISPATCHV(CFSetGetTypeID(), CFIndex, (NSDictionary *)hc, countForObject:(id)value);
    __CFGenericValidateType(hc, CFSetGetTypeID());
    return CFBasicHashGetCountOfValue((CFBasicHashRef)hc, (uintptr_t)value);
}

Boolean CFDictionaryContainsValue(CFHashRef hc, const_any_pointer_t value) {
    CF_SWIFT_FUNCDISPATCHV(CFSetGetTypeID(), char, (CFSwiftRef)hc, NSDictionary.containsObject, value);
    CF_OBJC_FUNCDISPATCHV(CFSetGetTypeID(), char, (NSDictionary *)hc, containsObject:(id)value);
    __CFGenericValidateType(hc, CFSetGetTypeID());
    return (0 < CFBasicHashGetCountOfValue((CFBasicHashRef)hc, (uintptr_t)value));
}

CF_EXPORT Boolean CFDictionaryGetKeyIfPresent(CFHashRef hc, const_any_pointer_t key, const_any_pointer_t *actualkey) {
    __CFGenericValidateType(hc, CFSetGetTypeID());
    CFBasicHashBucket bkt = CFBasicHashFindBucket((CFBasicHashRef)hc, (uintptr_t)key);
    if (0 < bkt.count) {
        if (actualkey) {
            *actualkey = (const_any_pointer_t)bkt.weak_key;
        }
        return true;
    }
    return false;
}
#endif

#if CFDictionary
void CFSetGetKeysAndValues(CFHashRef hc, const_any_pointer_t *keybuf, const_any_pointer_t *valuebuf) {
#endif
#if CFSet || CFBag
void CFSetGetValues(CFHashRef hc, const_any_pointer_t *keybuf) {
    const_any_pointer_t *valuebuf = 0;
#endif
#if CFDictionary
    if (CFDictionary) CF_SWIFT_FUNCDISPATCHV(CFSetGetTypeID(), void, (CFSwiftRef)hc, NSDictionary.getObjects, valuebuf, keybuf);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated"
    if (CFDictionary) CF_OBJC_FUNCDISPATCHV(CFSetGetTypeID(), void, (NSDictionary *)hc, getObjects:(id *)valuebuf andKeys:(id *)keybuf);
#pragma GCC diagnostic pop
#endif
#if CFSet
    if (CFSet) CF_SWIFT_FUNCDISPATCHV(CFSetGetTypeID(), void, (CFSwiftRef)hc, NSSet.getObjects, keybuf);
    if (CFSet) CF_OBJC_FUNCDISPATCHV(CFSetGetTypeID(), void, (NSSet *)hc, getObjects:(id *)keybuf);
#endif
    __CFGenericValidateType(hc, CFSetGetTypeID());
    CFBasicHashGetElements((CFBasicHashRef)hc, CFSetGetCount(hc), (uintptr_t *)valuebuf, (uintptr_t *)keybuf);
}

void CFSetApplyFunction(CFHashRef hc, CFSetApplierFunction applier, any_pointer_t context) {
    FAULT_CALLBACK((void **)&(applier));
#if CFDictionary
    if (CFDictionary) CF_SWIFT_FUNCDISPATCHV(CFSetGetTypeID(), void, (CFSwiftRef)hc, NSDictionary.__apply, applier, context);
    if (CFDictionary) CF_OBJC_FUNCDISPATCHV(CFSetGetTypeID(), void, (NSDictionary *)hc, __apply:(void (*)(const void *, const void *, void *))applier context:(void *)context);
#endif
#if CFSet
    if (CFSet) CF_SWIFT_FUNCDISPATCHV(CFSetGetTypeID(), void, (CFSwiftRef)hc, NSSet.__apply, applier, context);
    if (CFSet) CF_OBJC_FUNCDISPATCHV(CFSetGetTypeID(), void, (NSSet *)hc, __applyValues:(void (*)(const void *, void *))applier context:(void *)context);
#endif
    __CFGenericValidateType(hc, CFSetGetTypeID());
    CFBasicHashApply((CFBasicHashRef)hc, ^(CFBasicHashBucket bkt) {
#if CFDictionary
            INVOKE_CALLBACK3(applier, (const_any_pointer_t)bkt.weak_key, (const_any_pointer_t)bkt.weak_value, context);
#endif
#if CFSet
            INVOKE_CALLBACK2(applier, (const_any_pointer_t)bkt.weak_value, context);
#endif
#if CFBag
            for (CFIndex cnt = bkt.count; cnt--;) {
                INVOKE_CALLBACK2(applier, (const_any_pointer_t)bkt.weak_value, context);
            }
#endif
            return (Boolean)true;
        });
}

// This function is for Foundation's benefit; no one else should use it.
CF_EXPORT unsigned long _CFSetFastEnumeration(CFHashRef hc, struct __objcFastEnumerationStateEquivalent *state, void *stackbuffer, unsigned long count) {
    if (CF_IS_SWIFT(CFSetGetTypeID(), hc)) return 0;
    if (CF_IS_OBJC(CFSetGetTypeID(), hc)) return 0;
    __CFGenericValidateType(hc, CFSetGetTypeID());
    return __CFBasicHashFastEnumeration((CFBasicHashRef)hc, (struct __objcFastEnumerationStateEquivalent2 *)state, stackbuffer, count);
}

// This function is for Foundation's benefit; no one else should use it.
CF_EXPORT Boolean _CFSetIsMutable(CFHashRef hc) {
    if (CF_IS_SWIFT(CFSetGetTypeID(), hc)) return false;
    if (CF_IS_OBJC(CFSetGetTypeID(), hc)) return false;
    __CFGenericValidateType(hc, CFSetGetTypeID());
    return CFBasicHashIsMutable((CFBasicHashRef)hc);
}

// This function is for Foundation's benefit; no one else should use it.
CF_EXPORT void _CFSetSetCapacity(CFMutableHashRef hc, CFIndex cap) {
    if (CF_IS_SWIFT(CFSetGetTypeID(), hc)) return;
    if (CF_IS_OBJC(CFSetGetTypeID(), hc)) return;
    __CFGenericValidateType(hc, CFSetGetTypeID());
    CFAssert2(CFBasicHashIsMutable((CFBasicHashRef)hc), __kCFLogAssertion, "%s(): immutable collection %p passed to mutating operation", __PRETTY_FUNCTION__, hc);
    CFAssert3(CFSetGetCount(hc) <= cap, __kCFLogAssertion, "%s(): desired capacity (%ld) is less than count (%ld)", __PRETTY_FUNCTION__, cap, CFSetGetCount(hc));
    CFBasicHashSetCapacity((CFBasicHashRef)hc, cap);
}

CF_INLINE CFIndex __CFSetGetKVOBit(CFHashRef hc) {
    return __CFRuntimeGetFlag(hc, 0);
}

CF_INLINE void __CFSetSetKVOBit(CFHashRef hc, CFIndex bit) {
    __CFRuntimeSetFlag(hc, 0, ((uintptr_t)bit & 0x1));
}

// This function is for Foundation's benefit; no one else should use it.
CF_EXPORT CFIndex _CFSetGetKVOBit(CFHashRef hc) {
    return __CFSetGetKVOBit(hc);
}

// This function is for Foundation's benefit; no one else should use it.
CF_EXPORT void _CFSetSetKVOBit(CFHashRef hc, CFIndex bit) {
    __CFSetSetKVOBit(hc, bit);
}


#if !defined(CF_OBJC_KVO_WILLCHANGE)
#define CF_OBJC_KVO_WILLCHANGE(obj, key)
#define CF_OBJC_KVO_DIDCHANGE(obj, key)
#define CF_OBJC_KVO_WILLCHANGEALL(obj)
#define CF_OBJC_KVO_DIDCHANGEALL(obj)
#endif

#if CFDictionary
void CFSetAddValue(CFMutableHashRef hc, const_any_pointer_t key, const_any_pointer_t value) {
#endif
#if CFSet || CFBag
void CFSetAddValue(CFMutableHashRef hc, const_any_pointer_t key) {
    const_any_pointer_t value = key;
#endif
#if CFDictionary
    if (CFDictionary) CF_SWIFT_FUNCDISPATCHV(CFSetGetTypeID(), void, (CFSwiftRef)hc, NSMutableDictionary.__addObject, key, value);
    if (CFDictionary) CF_OBJC_FUNCDISPATCHV(CFSetGetTypeID(), void, (NSMutableDictionary *)hc, __addObject:(id)value forKey:(id)key);
#endif
#if CFSet
    if (CFSet) CF_SWIFT_FUNCDISPATCHV(CFSetGetTypeID(), void, (CFSwiftRef)hc, NSMutableSet.addObject, (CFSwiftRef)key);
    if (CFSet) CF_OBJC_FUNCDISPATCHV(CFSetGetTypeID(), void, (NSMutableSet *)hc, addObject:(id)key);
#endif
    __CFGenericValidateType(hc, CFSetGetTypeID());
    CFAssert2(CFBasicHashIsMutable((CFBasicHashRef)hc), __kCFLogAssertion, "%s(): immutable collection %p passed to mutating operation", __PRETTY_FUNCTION__, hc);
    if (!CFBasicHashIsMutable((CFBasicHashRef)hc)) {
        CFLog(3, CFSTR("%s(): immutable collection %p given to mutating function"), __PRETTY_FUNCTION__, hc);
    }
    CF_OBJC_KVO_WILLCHANGE(hc, key);
    CFBasicHashAddValue((CFBasicHashRef)hc, (uintptr_t)key, (uintptr_t)value);
    CF_OBJC_KVO_DIDCHANGE(hc, key);
}

#if CFDictionary
void CFSetReplaceValue(CFMutableHashRef hc, const_any_pointer_t key, const_any_pointer_t value) {
#endif
#if CFSet || CFBag
void CFSetReplaceValue(CFMutableHashRef hc, const_any_pointer_t key) {
    const_any_pointer_t value = key;
#endif
#if CFDictionary
    if (CFDictionary) CF_SWIFT_FUNCDISPATCHV(CFSetGetTypeID(), void, (CFSwiftRef)hc, NSMutableDictionary.replaceObject, key, value);
    if (CFDictionary) CF_OBJC_FUNCDISPATCHV(CFSetGetTypeID(), void, (NSMutableDictionary *)hc, replaceObject:(id)value forKey:(id)key);
#endif
#if CFSet
    if (CFSet) CF_SWIFT_FUNCDISPATCHV(CFSetGetTypeID(), void, (CFSwiftRef)hc, NSMutableSet.replaceObject, (CFSwiftRef)key);
    if (CFSet) CF_OBJC_FUNCDISPATCHV(CFSetGetTypeID(), void, (NSMutableSet *)hc, replaceObject:(id)key);
#endif
    __CFGenericValidateType(hc, CFSetGetTypeID());
    CFAssert2(CFBasicHashIsMutable((CFBasicHashRef)hc), __kCFLogAssertion, "%s(): immutable collection %p passed to mutating operation", __PRETTY_FUNCTION__, hc);
    if (!CFBasicHashIsMutable((CFBasicHashRef)hc)) {
        CFLog(3, CFSTR("%s(): immutable collection %p given to mutating function"), __PRETTY_FUNCTION__, hc);
    }
    CF_OBJC_KVO_WILLCHANGE(hc, key);
    CFBasicHashReplaceValue((CFBasicHashRef)hc, (uintptr_t)key, (uintptr_t)value);
    CF_OBJC_KVO_DIDCHANGE(hc, key);
}

#if CFDictionary
void CFSetSetValue(CFMutableHashRef hc, const_any_pointer_t key, const_any_pointer_t value) {
#endif
#if CFSet || CFBag
void CFSetSetValue(CFMutableHashRef hc, const_any_pointer_t key) {
    const_any_pointer_t value = key;
#endif
#if CFDictionary
    if (CFDictionary) CF_SWIFT_FUNCDISPATCHV(CFSetGetTypeID(), void, (CFSwiftRef)hc, NSMutableDictionary.__setObject, key, value);
    if (CFDictionary) CF_OBJC_FUNCDISPATCHV(CFSetGetTypeID(), void, (NSMutableDictionary *)hc, __setObject:(id)value forKey:(id)key);
#endif
#if CFSet
    if (CFSet) CF_SWIFT_FUNCDISPATCHV(CFSetGetTypeID(), void, (CFSwiftRef)hc, NSMutableSet.setObject, (CFSwiftRef)key);
    if (CFSet) CF_OBJC_FUNCDISPATCHV(CFSetGetTypeID(), void, (NSMutableSet *)hc, setObject:(id)key);
#endif
    __CFGenericValidateType(hc, CFSetGetTypeID());
    CFAssert2(CFBasicHashIsMutable((CFBasicHashRef)hc), __kCFLogAssertion, "%s(): immutable collection %p passed to mutating operation", __PRETTY_FUNCTION__, hc);
    if (!CFBasicHashIsMutable((CFBasicHashRef)hc)) {
        CFLog(3, CFSTR("%s(): immutable collection %p given to mutating function"), __PRETTY_FUNCTION__, hc);
    }
    CF_OBJC_KVO_WILLCHANGE(hc, key);
//#warning this for a dictionary used to not replace the key
    CFBasicHashSetValue((CFBasicHashRef)hc, (uintptr_t)key, (uintptr_t)value);
    CF_OBJC_KVO_DIDCHANGE(hc, key);
}

void CFSetRemoveValue(CFMutableHashRef hc, const_any_pointer_t key) {
#if CFDictionary
    if (CFDictionary) CF_SWIFT_FUNCDISPATCHV(CFSetGetTypeID(), void, (CFSwiftRef)hc, NSMutableDictionary.removeObjectForKey, key);
    if (CFDictionary) CF_OBJC_FUNCDISPATCHV(CFSetGetTypeID(), void, (NSMutableDictionary *)hc, removeObjectForKey:(id)key);
#endif
#if CFSet
    if (CFSet) CF_SWIFT_FUNCDISPATCHV(CFSetGetTypeID(), void, (CFSwiftRef)hc, NSMutableSet.removeObject, (CFSwiftRef)key);
    if (CFSet) CF_OBJC_FUNCDISPATCHV(CFSetGetTypeID(), void, (NSMutableSet *)hc, removeObject:(id)key);
#endif
    __CFGenericValidateType(hc, CFSetGetTypeID());
    CFAssert2(CFBasicHashIsMutable((CFBasicHashRef)hc), __kCFLogAssertion, "%s(): immutable collection %p passed to mutating operation", __PRETTY_FUNCTION__, hc);
    if (!CFBasicHashIsMutable((CFBasicHashRef)hc)) {
        CFLog(3, CFSTR("%s(): immutable collection %p given to mutating function"), __PRETTY_FUNCTION__, hc);
    }
    CF_OBJC_KVO_WILLCHANGE(hc, key);
    CFBasicHashRemoveValue((CFBasicHashRef)hc, (uintptr_t)key);
    CF_OBJC_KVO_DIDCHANGE(hc, key);
}

void CFSetRemoveAllValues(CFMutableHashRef hc) {
#if CFDictionary
    if (CFDictionary) CF_SWIFT_FUNCDISPATCHV(CFSetGetTypeID(), void, (CFSwiftRef)hc, NSMutableDictionary.removeAllObjects);
    if (CFDictionary) CF_OBJC_FUNCDISPATCHV(CFSetGetTypeID(), void, (NSMutableDictionary *)hc, removeAllObjects);
#endif
#if CFSet
    if (CFSet) CF_SWIFT_FUNCDISPATCHV(CFSetGetTypeID(), void, (CFSwiftRef)hc, NSMutableSet.removeAllObjects);
    if (CFSet) CF_OBJC_FUNCDISPATCHV(CFSetGetTypeID(), void, (NSMutableSet *)hc, removeAllObjects);
#endif
    __CFGenericValidateType(hc, CFSetGetTypeID());
    CFAssert2(CFBasicHashIsMutable((CFBasicHashRef)hc), __kCFLogAssertion, "%s(): immutable collection %p passed to mutating operation", __PRETTY_FUNCTION__, hc);
    if (!CFBasicHashIsMutable((CFBasicHashRef)hc)) {
        CFLog(3, CFSTR("%s(): immutable collection %p given to mutating function"), __PRETTY_FUNCTION__, hc);
    }
    CF_OBJC_KVO_WILLCHANGEALL(hc);
    CFBasicHashRemoveAllValues((CFBasicHashRef)hc);
    CF_OBJC_KVO_DIDCHANGEALL(hc);
}

#undef CF_OBJC_KVO_WILLCHANGE
#undef CF_OBJC_KVO_DIDCHANGE
#undef CF_OBJC_KVO_WILLCHANGEALL
#undef CF_OBJC_KVO_DIDCHANGEALL

