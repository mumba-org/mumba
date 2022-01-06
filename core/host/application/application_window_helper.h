// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_APPLICATION_WINDOW_HELPER_H_
#define MUMBA_HOST_APPLICATION_APPLICATION_WINDOW_HELPER_H_

#include <stdint.h>

#include <map>

#include "base/atomic_sequence_num.h"
#include "base/containers/hash_tables.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/process/process.h"
//#include "core/common/render_message_filter.mojom.h"
#include "core/host/host_thread.h"
#include "core/host/host_client.h"
#include "core/host/application/global_request_id.h"
#include "third_party/blink/public/web/web_popup_type.h"
#include "ui/gfx/native_widget_types.h"

namespace host {

//class ResourceDispatcherHostImpl;

// Instantiated per RenderProcessHost to provide various optimizations on
// behalf of a ApplicationWindowHost.  This class bridges between the IO thread
// where the RenderProcessHost's MessageFilter lives and the UI thread where
// the ApplicationWindowHost lives.
class ApplicationWindowHelper
    : public base::RefCountedThreadSafe<ApplicationWindowHelper,
                                        HostThread::DeleteOnIOThread> {
 public:
  ApplicationWindowHelper();

  void Init(int app_process_id);//,
  //          ResourceDispatcherHostImpl* resource_dispatcher_host);

  // Gets the next available routing id.  This is thread safe.
  int GetNextRoutingID();

  // IO THREAD ONLY -----------------------------------------------------------

  // Lookup the ApplicationWindowHelper from the render_process_host_id. Returns NULL
  // if not found. NOTE: The raw pointer is for temporary use only. To retain,
  // store in a scoped_refptr.
  static ApplicationWindowHelper* FromProcessHostID(int app_process_host_id);

  // UI THREAD ONLY -----------------------------------------------------------

  // These two functions provide the backend implementation of the
  // corresponding functions in RenderProcessHost. See those declarations
  // for documentation.
  void ResumeDeferredNavigation(const GlobalRequestID& request_id);

  // IO THREAD ONLY -----------------------------------------------------------
  void CreateNewWindow(int opener_id,
                       blink::WebPopupType popup_type,
  //                     mojom::WidgetPtr,
                       int* route_id);

  void CreateNewFullscreenWindow(int opener_id,
  //                               mojom::WidgetPtr,
                                 int* route_id);

 private:
  friend class base::RefCountedThreadSafe<ApplicationWindowHelper>;
  friend struct HostThread::DeleteOnThread<HostThread::IO>;
  friend class base::DeleteHelper<ApplicationWindowHelper>;

  ~ApplicationWindowHelper();

  // Called on the UI thread to finish creating a widget.
  void OnCreateWindowOnUI(int32_t opener_id,
                          int32_t route_id,
  //                        mojom::WidgetPtrInfo widget,
                          blink::WebPopupType popup_type);

  // Called on the UI thread to create a fullscreen widget.
  void OnCreateFullscreenWindowOnUI(int32_t opener_id,
                                    int32_t route_id);//,
  //                                  mojom::WidgetPtrInfo widget);

  // Called on the IO thread to resume a paused navigation in the network
  // stack without transferring it to a new renderer process.
  void OnResumeDeferredNavigation(const GlobalRequestID& request_id);

  // Called on the IO thread to resume a navigation paused immediately after
  // receiving response headers.
  void OnResumeResponseDeferredAtStart(const GlobalRequestID& request_id);

  int app_process_id_;

  // The next routing id to use.
  base::AtomicSequenceNumber next_routing_id_;

  //ResourceDispatcherHostImpl* resource_dispatcher_host_;

  DISALLOW_COPY_AND_ASSIGN(ApplicationWindowHelper);
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_APPLICATION_WINDOW_HELPER_H_
