// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_ENGINE_ALLBACKS_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_ENGINE_ALLBACKS_H_

#include "WebDefinitions.h"

typedef struct {
   void (*OnInit)(void* state, void* ctx);
   //void (*OnRun)(void* state);
   void (*OnShutdown)(void* state);
   //void* (*GetEventQueue)(void* state);
   void* (*GetServiceWorkerContextClientState)(void* state); 
   ServiceWorkerContextClientCallbacks (*GetServiceWorkerContextClientCallbacks)(void* state);
} CEngineCallbacks;

typedef struct {
  void (*OnApplicationInstanceCreated)(void* state, int id, const char* url, const char* uuid);
  void (*OnApplicationInstanceDestroyed)(void* state, int id);
  void (*OnApplicationInstanceLaunched)(void* state, int id);
  void (*OnApplicationInstanceLaunchFailed)(void* state, int id, int status, const char* message);
  void (*OnApplicationInstanceKilled)(void* state, int id, int status, const char* message);
  void (*OnApplicationInstanceClosed)(void* state, int id, int status, const char* message);
  void (*OnApplicationInstanceActivated)(void* state, int id);
  void (*OnApplicationInstanceStateChanged)(void* state, int id, int app_state);
  void (*OnApplicationInstanceBoundsChanged)(void* state, int id, int width, int height);
  void (*OnApplicationInstanceVisible)(void* state, int id);
  void (*OnApplicationInstanceHidden)(void* state, int id);
} CApplicationHostCallbacks;

typedef struct {
  void(*OnShareDHTAnnounceReply)(void*, const uint8_t*, int);
  void(*OnShareMetadataReceived)(void*, const uint8_t*);
  void(*OnShareMetadataError)(void*, const uint8_t*, int);
  void(*OnSharePieceReadError)(void*, const uint8_t*, int, int);
  void(*OnSharePiecePass)(void*, const uint8_t*, int);
  void(*OnSharePieceFailed)(void*, const uint8_t*, int);
  void(*OnSharePieceRead)(void*, const uint8_t*, int, int, int, int, int);
  void(*OnSharePieceWrite)(void*, const uint8_t*, int, int, int, int, int);
  void(*OnSharePieceHashFailed)(void*, const uint8_t*, int);
  void(*OnShareCheckingFiles)(void*, const uint8_t*);
  void(*OnShareDownloadingMetadata)(void*, const uint8_t*);
  void(*OnShareFileRenamed)(void*, const uint8_t*, int, const char*, int);
  void(*OnShareResumed)(void*, const uint8_t*);
  void(*OnShareChecked)(void*, const uint8_t*, int);
  void(*OnSharePieceComplete)(void*, const uint8_t*, int);
  void(*OnShareFileComplete)(void*, const uint8_t*, int);
  void(*OnShareDownloading)(void*, const uint8_t*);
  void(*OnShareComplete)(void*, const uint8_t*);
  void(*OnShareSeeding)(void*, const uint8_t*);
  void(*OnSharePaused)(void*, const uint8_t*);
} StorageShareCallbacks;


#endif