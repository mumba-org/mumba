/*      CFPlugIn.c
	Copyright (c) 1999-2018, Apple Inc. and the Swift project authors
 
	Portions Copyright (c) 2014-2018, Apple Inc. and the Swift project authors
	Licensed under Apache License v2.0 with Runtime Library Exception
	See http://swift.org/LICENSE.txt for license information
	See http://swift.org/CONTRIBUTORS.txt for the list of Swift project authors
        Responsibility: Tony Parker
*/

#include "CFBundle_Internal.h"
#include "CFInternal.h"

CONST_STRING_DECL(kCFPlugInDynamicRegistrationKey, "CFPlugInDynamicRegistration")
CONST_STRING_DECL(kCFPlugInDynamicRegisterFunctionKey, "CFPlugInDynamicRegisterFunction")
CONST_STRING_DECL(kCFPlugInUnloadFunctionKey, "CFPlugInUnloadFunction")
CONST_STRING_DECL(kCFPlugInFactoriesKey, "CFPlugInFactories")
CONST_STRING_DECL(kCFPlugInTypesKey, "CFPlugInTypes")

CF_EXPORT void *CFPlugInInstanceCreate(CFAllocatorRef allocator, CFUUIDRef factoryID, CFUUIDRef typeID) {
    _CFPFactoryRef factory = _CFPFactoryFind(factoryID, true);
    void *result = NULL;
    if (!factory) {
        /* MF:!!! No such factory. */
        CFLog(__kCFLogPlugIn, CFSTR("Cannot find factory %@"), factoryID);
    } else {
        if (!_CFPFactorySupportsType(factory, typeID)) {
            /* MF:!!! Factory does not support type. */
            CFLog(__kCFLogPlugIn, CFSTR("Factory %@ does not support type %@"), factoryID, typeID);
        } else {
            result = _CFPFactoryCreateInstance(allocator, factory, typeID);
        }
    }
    return result;
}

/* ===================== Registering factories and types ===================== */
/* For plugIn writers who must dynamically register things. */
/* Functions to register factory functions and to associate factories with types. */

CF_EXPORT Boolean CFPlugInRegisterFactoryFunction(CFUUIDRef factoryID, CFPlugInFactoryFunction func) {
    // Create factories without plugIns from default allocator
    // MF:!!! Should probably check that this worked, and maybe do some pre-checking to see if it already exists
    // _CFPFactoryRef factory =
    (void)_CFPFactoryCreate(kCFAllocatorSystemDefault, factoryID, func);
    return true;
}

CF_EXPORT Boolean CFPlugInRegisterFactoryFunctionByName(CFUUIDRef factoryID, CFPlugInRef plugIn, CFStringRef functionName) {
    // Create factories with plugIns from plugIn's allocator
    // MF:!!! Should probably check that this worked, and maybe do some pre-checking to see if it already exists
    // _CFPFactoryRef factory =
    (void)_CFPFactoryCreateByName(CFGetAllocator(plugIn), factoryID, plugIn, functionName);
    return true;
}

CF_EXPORT Boolean CFPlugInUnregisterFactory(CFUUIDRef factoryID) {
    _CFPFactoryRef factory = _CFPFactoryFind(factoryID, true);
    
    if (!factory) {
        /* MF:!!! Error.  No factory registered for this ID. */
    } else {
        _CFPFactoryDisable(factory);
    }
    return true;
}

CF_EXPORT Boolean CFPlugInRegisterPlugInType(CFUUIDRef factoryID, CFUUIDRef typeID) {
    _CFPFactoryRef factory = _CFPFactoryFind(factoryID, true);

    if (!factory) {
        /* MF:!!! Error.  Factory must be registered (and not disabled) before types can be associated with it. */
    } else {
        _CFPFactoryAddType(factory, typeID);
    }
    return true;
}

CF_EXPORT Boolean CFPlugInUnregisterPlugInType(CFUUIDRef factoryID, CFUUIDRef typeID) {
    _CFPFactoryRef factory = _CFPFactoryFind(factoryID, true);

    if (!factory) {
        /* MF:!!! Error.  Could not find factory. */
    } else {
        _CFPFactoryRemoveType(factory, typeID);
    }
    return true;
}


/* ================= Registering instances ================= */
/* When a new instance of a type is created, the instance is responsible for registering itself with the factory that created it and unregistering when it deallocates. */
/* This means that an instance must keep track of the CFUUIDRef of the factory that created it so it can unregister when it goes away. */

CF_EXPORT void CFPlugInAddInstanceForFactory(CFUUIDRef factoryID) {
    _CFPFactoryRef factory = _CFPFactoryFind(factoryID, true);

    if (!factory) {
        /* MF:!!! Error.  Could not find factory. */
    } else {
        _CFPFactoryAddInstance(factory);
    }
}

CF_EXPORT void CFPlugInRemoveInstanceForFactory(CFUUIDRef factoryID) {
    _CFPFactoryRef factory = _CFPFactoryFind(factoryID, true);

    if (!factory) {
        /* MF:!!! Error.  Could not find factory. */
    } else {
        _CFPFactoryRemoveInstance(factory);
    }
}
