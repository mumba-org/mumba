// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_CHANNEL_REGISTRY_SHIMS_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_CHANNEL_REGISTRY_SHIMS_H_

#include "Globals.h"

typedef void* EngineInstanceRef;
typedef void* ApplicationInstanceRef;
typedef void* ChannelRegistryRef;
typedef void* ChannelRef;
typedef void* ChannelClientRef;

typedef void* ServiceWorkerGlobalScopeRef;
typedef void* WebWorkerRef;
typedef void* WebLocalDomWindowRef;

EXPORT ChannelRegistryRef _ChannelRegistryCreateFromEngine(EngineInstanceRef handle);
EXPORT ChannelRegistryRef _ChannelRegistryCreateFromApp(ApplicationInstanceRef handle);
EXPORT void _ChannelRegistryDestroy(ChannelRegistryRef handle);   
EXPORT void _ChannelRegistryConnectChannel(
  ChannelRegistryRef registry,
  const char* scheme, 
  const char* name,
  void* state,
  void* client_state,
  void(*cb)(void*, int, ChannelClientRef),
  void(*on_message)(void*, void*));
EXPORT void _ChannelRegistryRemoveChannel(ChannelRegistryRef registry, const char* scheme, const char* name, void* state, void(*cb)(void*, int));
EXPORT void _ChannelRegistryRemoveChannelByUUID(ChannelRegistryRef registry, const char* uuid, void* state, void(*cb)(void*, int));
EXPORT void _ChannelRegistryHaveChannel(ChannelRegistryRef registry, const char* scheme, const char* name, void* state, void(*cb)(void*, int));
EXPORT void _ChannelRegistryHaveChannelByUUID(ChannelRegistryRef registry, const char* uuid, void* state, void(*cb)(void*, int));
EXPORT void _ChannelRegistryLookupChannel(ChannelRegistryRef registry, const char* scheme, const char* name, void* state, void(*cb)(void*, int, const char*, const char*, const char*));
EXPORT void _ChannelRegistryLookupChannelByUUID(ChannelRegistryRef registry, const char* uuid, void* state, void(*cb)(void*, int, const char*, const char*, const char*));
EXPORT void _ChannelRegistryListChannelsWithScheme(ChannelRegistryRef registry, const char* scheme, void* state, void(*cb)(void*, int, int, const char**, const char**, const char**, const char**));
EXPORT void _ChannelRegistryListAllChannels(ChannelRegistryRef registry, void* state, void(*cb)(void*, int, int, const char**, const char**, const char**));
EXPORT void _ChannelRegistryGetChannelCount(ChannelRegistryRef registry, void* state, void(*cb)(void*, int));

//EXPORT ChannelClientRef _ChannelClientCreate(ChannelRegistryRef feed, void* state, void(*cb)(void*, const char*, int, void *));
EXPORT void _ChannelClientDestroy(ChannelClientRef handle);
EXPORT void _ChannelClientPostMessageString(ChannelClientRef handle, WebLocalDomWindowRef window, const char* message);
EXPORT void _ChannelClientPostMessageStringFromWorker(ChannelClientRef handle, WebWorkerRef worker, const char* message);
EXPORT void _ChannelClientPostMessageStringFromServiceWorker(ChannelClientRef handle, ServiceWorkerGlobalScopeRef scope, const char* message);
EXPORT void _ChannelClientClose(ChannelClientRef handle);

#endif