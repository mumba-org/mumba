// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_SHANZAL_SHIMS_OMPOSITOR_ALLBACKS_H_
#define MUMBA_RUNTIME_SHANZAL_SHIMS_OMPOSITOR_ALLBACKS_H_

//#include "base/macros.h"
#include "Globals.h"

//typedef void (*CLayerTreeHostSingleThreadClientCb)(void* client);

typedef struct {
   // cc::LayerTreeHostClient
   void (*willBeginMainFrame)(void* client);
   void (*beginMainFrame)(void* client, 
      uint64_t source_id,
      uint64_t sequence_number,
      int64_t frame_time, 
      int64_t deadline, 
      int64_t interval);
   void (*beginMainFrameNotExpectedSoon)(void* client);
   void (*beginMainFrameNotExpectedUntil)(void* client, int64_t time);
   void (*didBeginMainFrame)(void* client);
   void (*updateLayerTreeHost)(void* client, int32_t update);
   void (*applyViewportDeltas)(void* client);
   void (*requestNewLayerTreeFrameSink)(void* client);
   void (*didInitializeLayerTreeFrameSink)(void* client);
   void (*didFailToInitializeLayerTreeFrameSink)(void* client);
   void (*willCommit)(void* client);
   void (*didCommit)(void* client);
   void (*didCommitAndDrawFrame)(void* client);
   void (*didReceiveCompositorFrameAck)(void* client);
   void (*didCompletePageScaleAnimation)(void* client);
   int (*isForSubframe)(void* client);
   // cc::LayerTreeHostSingleThreadClient
   void (*didSubmitCompositorFrame)(void* client);
   void (*didLoseLayerTreeFrameSink)(void* client);
   void (*requestScheduleComposite)(void* client);
   void (*requestScheduleAnimation)(void* client);
} CLayerTreeHostSingleThreadClientCbs;

typedef struct {
 void (*CLayerAnimationDelegateNotifyAnimationStarted)(void* peer, int64_t monotonic_time, int property, int group);
 void (*CLayerAnimationDelegateNotifyAnimationFinished)(void* peer, int64_t monotonic_time, int property, int group);
 void (*CLayerAnimationDelegateNotifyAnimationAborted)(void* peer, int64_t monotonic_time, int property, int group);
 void (*CLayerAnimationDelegateNotifyAnimationTakeover)(void* peer, int64_t monotonic_time, 
  int property, int64_t animation_start_time, void* curve);
} CLayerAnimationDelegateCallbacks;

typedef void* CDisplayItemList;

typedef void* (*CLayerClientPaintCallback)(void* layer, int ctrlset);
// TODO: bool PrepareTransferableResource(
//      cc::SharedBitmapIdRegistrar* bitmap_registar,
//      viz::TransferableResource* transferable_resource,
//      std::unique_ptr<viz::SingleReleaseCallback>* release_callback)
typedef void (*CLayerClientPaintableRegion)(void* layer, int *x, int *y, int *w, int *h);
typedef int (*CLayerClientPrepareCallback)(void* layer, void* bitmap_registrar, void* transferable_resource, void* release_callback);
typedef int (*CLayerClientFillCallback)(void* layer);
typedef int (*CLayerClientMemoryUsageCallback)(void* layer);

typedef struct {
   CLayerClientPaintCallback paintContentsToDisplayList;
   CLayerClientPaintableRegion paintableRegion;
   CLayerClientPrepareCallback prepareTransferableResource;
   CLayerClientFillCallback fillsBoundsCompletely;
   CLayerClientMemoryUsageCallback getApproximateUnsharedMemoryUsage;
} CLayerClientCallbacks;

#endif
