// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_SERVICE_REGISTRY_SHIMS_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_SERVICE_REGISTRY_SHIMS_H_

#include "Globals.h"

typedef void* EngineInstanceRef;
typedef void* ApplicationInstanceRef;
typedef void* ServiceRegistryRef;

EXPORT ServiceRegistryRef _ServiceRegistryCreateFromEngine(EngineInstanceRef handle);
EXPORT void _ServiceRegistryDestroy(ServiceRegistryRef handle);   
EXPORT void _ServiceRegistryHaveServiceByName(ServiceRegistryRef registry, const char* scheme, const char* name, void* state, void(*cb)(void*, int));
EXPORT void _ServiceRegistryHaveServiceByUUID(ServiceRegistryRef registry, const char* uuid, void* state, void(*cb)(void*, int));
EXPORT void _ServiceRegistryLookupServiceByName(ServiceRegistryRef registry, const char* scheme, const char* name, void* state, void(*cb)(void*, int, const char*, const char*, const char*, const char*, int));
EXPORT void _ServiceRegistryLookupServiceByUUID(ServiceRegistryRef registry, const char* uuid, void* state, void(*cb)(void*, int, const char*, const char*, const char*, const char*, int));
EXPORT void _ServiceRegistryListServicesWithScheme(ServiceRegistryRef registry, const char* scheme, void* state, void(*cb)(void*, int, int, const char**, const char**, const char**, const char**, int*));
EXPORT void _ServiceRegistryListAllServices(ServiceRegistryRef registry, void* state, void(*cb)(void*, int, int, const char**, const char**, const char**, const char**, int*));
EXPORT void _ServiceRegistryGetServiceCount(ServiceRegistryRef registry, void* state, void(*cb)(void*, int));
EXPORT void _ServiceRegistryAddSubscriber(ServiceRegistryRef registry, 
  const char* scheme, 
  void* state, 
  void* watcher_state,
  void(*cb)(void*, int, void*, void*),
  void(*OnServiceAdded)(void*, const char*, const char*, const char*, const char*, int),
  void(*OnServiceRemoved)(void*, const char*, const char*, const char*, const char*, int),
  void(*OnServiceChanged)(void*, const char*, const char*, const char*, const char*, int),
  void(*OnServiceStateChanged)(void*, const char*, const char*, const char*, const char*, int, int));
EXPORT void _ServiceRegistryRemoveSubscriber(ServiceRegistryRef registry, int id);
EXPORT void _ServiceSubscriberDestroy(void* handle);

#endif