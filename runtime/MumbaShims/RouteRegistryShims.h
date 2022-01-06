// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_ROUTE_REGISTRY_SHIMS_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_ROUTE_REGISTRY_SHIMS_H_

#include "Globals.h"

typedef void* EngineInstanceRef;
typedef void* ApplicationInstanceRef;
typedef void* RouteRegistryRef;

typedef struct {
  void (*OnRequestCreated)(void* state, const char* url, int request_id);
  void (*OnComplete)(void* state, int request_id, int status);
  const char* (*GetMethod)(void* state, int request_id);
  const char* (*GetMimeType)(void* state, int request_id);
  int (*GetStatus)(void* state, int request_id);
  int64_t (*GetCreationTime)(void* state, int request_id);
  int64_t (*GetTotalReceivedBytes)(void* state, int request_id);
  int64_t (*GetRawBodyBytes)(void* state, int request_id);
  void (*GetLoadTimingInfo)(void* state, int request_id, void* load_timing_info); 
  int64_t (*GetExpectedContentSize)(void* state, int request_id);
  const char* (*GetResponseHeaders)(void* state, int request_id, int* size); 
  void (*GetResponseInfo)(void* state, int request_id, void* response_info); 
  int (*Start)(void* state, int request_id);
  void (*FollowDeferredRedirect)(void* state, int request_id);
  int (*Read)(void* state, int request_id, void* buf, int max_bytes, int* bytes_read);
  int (*CancelWithError)(void* state, int request_id, int error);
  // control methods
  int (*LookupRouteByPath)(
      void* state, 
      const char* path,
      int* type,
      int* transportType,
      int* transportMode,
      char** scheme,
      int* scheme_size,
      char** name,
      int* name_size,
      char** path_out,
      int* path_size,
      char** url,
      int* url_size,
      char** title,
      int* title_size,
      char** contentType,
      int* content_size);
  int (*LookupRouteByUrl)(
      void* state, 
      const char* url,
      int* type,
      int* transportType,
      int* transportMode,
      char** scheme,
      int* scheme_size,
      char** name,
      int* name_size,
      char** path,
      int* path_size,
      char** url_out,
      int* url_size,
      char** title,
      int* title_size,
      char** contentType,
      int* content_size);
  int (*LookupRouteByUUID)(
      void* state, 
      const char* uuid,
      int* type,
      int* transportType,
      int* transportMode,
      char** scheme,
      int* scheme_size,
      char** name,
      int* name_size,
      char** path,
      int* path_size,
      char** url,
      int* url_size,
      char** title,
      int* title_size,
      char** contentType,
      int* content_size);
  const char* (*GetRouteHeader)(void* state, const char* url, int* size);
  int (*GetRouteCount)(void* state);
  int (*Subscribe)(void* state);
  void (*Unsubscribe)(void* state, int32_t subscriber_id);
} RouteRequestHandlerCallbacks;

EXPORT RouteRegistryRef _RouteRegistryCreateFromEngine(EngineInstanceRef handle, void* handler_state, RouteRequestHandlerCallbacks callbacks);
EXPORT RouteRegistryRef _RouteRegistryCreateFromApp(ApplicationInstanceRef handle);
EXPORT void _RouteRegistryDestroy(RouteRegistryRef handle);   
EXPORT void _RouteRegistryAddRoute(
  RouteRegistryRef registry,
  int type,
  int transportType,
  int transportMode,
  const char* scheme, 
  const char* name,
  const char* path,
  const char* url,
  const char* title,
  const char* content_type,
  const uint8_t* icon_data,
  int icon_data_size);

EXPORT void _RouteRegistryRemoveRoute(RouteRegistryRef registry, const char* path);
EXPORT void _RouteRegistryRemoveRouteByUrl(RouteRegistryRef registry, const char* url);
EXPORT void _RouteRegistryRemoveRouteByUUID(RouteRegistryRef registry, const char* uuid);
EXPORT void _RouteRegistryHaveRouteByPath(RouteRegistryRef registry, const char* path, void* state, void(*cb)(void*, int));
EXPORT void _RouteRegistryHaveRouteByUrl(RouteRegistryRef registry, const char* url, void* state, void(*cb)(void*, int));
EXPORT void _RouteRegistryHaveRouteByUUID(RouteRegistryRef registry, const char* uuid, void* state, void(*cb)(void*, int));
EXPORT void _RouteRegistryLookupRoute(RouteRegistryRef registry, const char* scheme, const char* path, void* state, void(*cb)(void*, int, int, int, int, const char*, const char*, const char*));
EXPORT void _RouteRegistryLookupRouteByPath(RouteRegistryRef registry, const char* path, void* state, void(*cb)(void*, int, int, int, int, const char*, const char*, const char*));
EXPORT void _RouteRegistryLookupRouteByUrl(RouteRegistryRef registry, const char* url, void* state, void(*cb)(void*, int, int, int, int, const char*, const char*, const char*));
EXPORT void _RouteRegistryLookupRouteByUUID(RouteRegistryRef registry, const char* uuid, void* state, void(*cb)(void*, int, int, int, int, const char*, const char*, const char*));
EXPORT void _RouteRegistryListRoutesWithScheme(RouteRegistryRef registry, const char* scheme, void* state, void(*cb)(void*, int, int, int*, int*, int*, const char**, const char**, const char**));
EXPORT void _RouteRegistryListAllRoutes(RouteRegistryRef registry, void* state, void(*cb)(void*, int, int, int*, int*, int*, const char**, const char**, const char**));
EXPORT void _RouteRegistryListSchemes(RouteRegistryRef registry, void* state, void(*cb)(void*, int, int, int*, int*, int*,const char**, const char**, const char**));
EXPORT void _RouteRegistryGetRouteCount(RouteRegistryRef registry, void* state, void(*cb)(void*, int));
EXPORT void _RouteRegistryAddSubscriber(RouteRegistryRef registry, 
  const char* scheme, 
  void* state, 
  void* watcher_state,
  void(*cb)(void*, int, void*, void*),
  void(*OnRouteHeaderChanged)(void*, const char*),
  void(*OnRouteAdded)(void*, int, int, int, const char*, const char*, const char*),
  void(*OnRouteRemoved)(void*, int, int, int, const char*, const char*, const char*),
  void(*OnRouteChanged)(void*, int, int, int, const char*, const char*, const char*));
EXPORT void _RouteRegistryRemoveSubscriber(RouteRegistryRef registry, int id);
EXPORT void _RouteSubscriberDestroy(void* handle);

#endif