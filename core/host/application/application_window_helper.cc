// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/application_window_helper.h"

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/lazy_instance.h"
#include "base/posix/eintr_wrapper.h"
#include "base/threading/thread.h"
#include "base/threading/thread_restrictions.h"
//#include "core/host/loader/resource_dispatcher_host_impl.h"
#include "core/host/application/application_window_host.h"
//#include "core/common/view_messages.h"

namespace host {
namespace {

typedef std::map<int, ApplicationWindowHelper*> WindowHelperMap;
base::LazyInstance<WindowHelperMap>::DestructorAtExit g_window_helpers =
    LAZY_INSTANCE_INITIALIZER;

void AddWindowHelper(int app_process_id,
                     const scoped_refptr<ApplicationWindowHelper>& window_helper) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  // We don't care if ApplicationWindowHelpers overwrite an existing process_id. Just
  // want this to be up to date.
  g_window_helpers.Get()[app_process_id] = window_helper.get();
}

}  // namespace

ApplicationWindowHelper::ApplicationWindowHelper()
    : app_process_id_(-1) {}//, resource_dispatcher_host_(nullptr) {}

ApplicationWindowHelper::~ApplicationWindowHelper() {
  DCHECK_CURRENTLY_ON(HostThread::IO);

  // Delete this RWH from the map if it is found.
  WindowHelperMap& window_map = g_window_helpers.Get();
  WindowHelperMap::iterator it = window_map.find(app_process_id_);
  if (it != window_map.end() && it->second == this)
    window_map.erase(it);
}

void ApplicationWindowHelper::Init(
    int app_process_id) {//,
    //ResourceDispatcherHostImpl* resource_dispatcher_host) {
  app_process_id_ = app_process_id;
  //resource_dispatcher_host_ = resource_dispatcher_host;

  HostThread::PostTask(HostThread::IO, FROM_HERE,
                          base::BindOnce(&AddWindowHelper, app_process_id_,
                                         base::WrapRefCounted(this)));
}

int ApplicationWindowHelper::GetNextRoutingID() {
  return next_routing_id_.GetNext() + 1;
}

// static
ApplicationWindowHelper* ApplicationWindowHelper::FromProcessHostID(
    int app_process_host_id) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  WindowHelperMap::const_iterator ci = g_window_helpers.Get().find(
      app_process_host_id);
  return (ci == g_window_helpers.Get().end())? NULL : ci->second;
}

void ApplicationWindowHelper::ResumeDeferredNavigation(
    const GlobalRequestID& request_id) {
  HostThread::PostTask(
      HostThread::IO, FROM_HERE,
      base::BindOnce(&ApplicationWindowHelper::OnResumeDeferredNavigation, this,
                     request_id));
}

void ApplicationWindowHelper::OnResumeDeferredNavigation(
    const GlobalRequestID& request_id) {
  //resource_dispatcher_host_->ResumeDeferredNavigation(request_id);
}

void ApplicationWindowHelper::CreateNewWindow(int opener_id,
                                         blink::WebPopupType popup_type,
    //                                     mojom::WidgetPtr widget,
                                         int* route_id) {
  *route_id = GetNextRoutingID();

  HostThread::PostTask(
      HostThread::UI, FROM_HERE,
      base::BindOnce(&ApplicationWindowHelper::OnCreateWindowOnUI, this, opener_id,
                     *route_id, popup_type));//widget.PassInterface(), popup_type));
}

void ApplicationWindowHelper::CreateNewFullscreenWindow(int opener_id,
                                                   //mojom::WidgetPtr widget,
                                                   int* route_id) {
  *route_id = GetNextRoutingID();
  HostThread::PostTask(
      HostThread::UI, FROM_HERE,
      base::BindOnce(&ApplicationWindowHelper::OnCreateFullscreenWindowOnUI, this,
                     opener_id, *route_id));//, widget.PassInterface()));
}

void ApplicationWindowHelper::OnCreateWindowOnUI(int32_t opener_id,
                                                 int32_t route_id,
                                                 //mojom::WidgetPtrInfo widget_info,
                                                 blink::WebPopupType popup_type) {
  //mojom::WidgetPtr widget;
  //widget.Bind(std::move(widget_info));
  ApplicationWindowHost* host = ApplicationWindowHost::FromID(
      app_process_id_, opener_id);
  if (host)
    host->CreateNewWindow(route_id, popup_type);//std::move(widget), popup_type);
}

void ApplicationWindowHelper::OnCreateFullscreenWindowOnUI(
    int32_t opener_id,
    int32_t route_id) {//,
    //mojom::WidgetPtrInfo widget_info) {
  //mojom::WidgetPtr widget;
  //widget.Bind(std::move(widget_info));
  ApplicationWindowHost* host = ApplicationWindowHost::FromID(
      app_process_id_, opener_id);
  if (host)
    host->CreateNewFullscreenWindow(route_id);//, std::move(widget));
}

}  // namespace host
