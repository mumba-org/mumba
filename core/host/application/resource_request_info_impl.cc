// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/resource_request_info_impl.h"

#include "core/host/global_routing_id.h"
//#include "core/host/application/resource_message_filter.h"
#include "core/host/application/application_contents.h"
//#include "core/common/net/url_request_service_worker_data.h"
//#include "core/common/net/url_request_user_data.h"
#include "core/host/host_thread.h"
#include "core/host/application/global_request_id.h"
#include "core/common/process_type.h"
#include "net/url_request/url_request.h"

namespace host {

namespace {

int FrameTreeNodeIdFromHostIds(int render_process_host_id,
                               int render_frame_host_id) {
  //ApplicationWindowHost* app_window_host =
  //  ApplicationWindowHost::FromID(render_process_host_id, render_frame_host_id);
  return render_frame_host_id;//render_frame_host ? render_frame_host->GetFrameTreeNodeId() : -1;
}

// static
const void* const kResourceRequestInfoImplKey = &kResourceRequestInfoImplKey;

}  // namespace

// ----------------------------------------------------------------------------
// ResourceRequestInfo

// static
const ResourceRequestInfo* ResourceRequestInfo::ForRequest(
    const net::URLRequest* request) {
  return ResourceRequestInfoImpl::ForRequest(request);
}

// static
bool ResourceRequestInfo::GetRenderFrameForRequest(
    const net::URLRequest* request,
    int* render_process_id,
    int* render_frame_id) {
//  URLRequestUserData* user_data = static_cast<URLRequestUserData*>(
//      request->GetUserData(URLRequestUserData::kUserDataKey));
//  if (!user_data)
    return false;
//  *render_process_id = user_data->render_process_id();
//  *render_frame_id = user_data->render_frame_id();
//  return true;
}

// static
bool ResourceRequestInfo::OriginatedFromServiceWorker(
    const net::URLRequest* request) {
  return false;//!!request->GetUserData(
      //content::URLRequestServiceWorkerData::kUserDataKey);
}

// ----------------------------------------------------------------------------
// ResourceRequestInfoImpl

// static
ResourceRequestInfoImpl* ResourceRequestInfoImpl::ForRequest(
    net::URLRequest* request) {
  return static_cast<ResourceRequestInfoImpl*>(
      request->GetUserData(kResourceRequestInfoImplKey));
}

// static
const ResourceRequestInfoImpl* ResourceRequestInfoImpl::ForRequest(
    const net::URLRequest* request) {
  return ForRequest(const_cast<net::URLRequest*>(request));
}

ResourceRequestInfoImpl::ResourceRequestInfoImpl(
    scoped_refptr<ResourceRequesterInfo> requester_info,
    int route_id,
    int frame_tree_node_id,
    int plugin_child_id,
    int request_id,
    int render_frame_id,
    bool is_main_frame,
    common::ResourceType resource_type,
    ui::PageTransition transition_type,
    bool is_download,
    bool is_stream,
    bool allow_download,
    bool has_user_gesture,
    bool enable_load_timing,
    bool enable_upload_progress,
    bool do_not_prompt_for_login,
    bool keepalive,
    blink::WebReferrerPolicy referrer_policy,
    bool is_prerendering,
    ResourceContext* context,
    bool report_raw_headers,
    bool is_async,
    common::PreviewsState previews_state,
    const scoped_refptr<network::ResourceRequestBody> body,
    bool initiated_in_secure_context)
    : detachable_handler_(nullptr),
      requester_info_(std::move(requester_info)),
      route_id_(route_id),
      frame_tree_node_id_(frame_tree_node_id),
      plugin_child_id_(plugin_child_id),
      request_id_(request_id),
      render_frame_id_(render_frame_id),
      is_main_frame_(is_main_frame),
      is_download_(is_download),
      is_stream_(is_stream),
      allow_download_(allow_download),
      has_user_gesture_(has_user_gesture),
      enable_load_timing_(enable_load_timing),
      enable_upload_progress_(enable_upload_progress),
      do_not_prompt_for_login_(do_not_prompt_for_login),
      keepalive_(keepalive),
      counted_as_in_flight_request_(false),
      resource_type_(resource_type),
      transition_type_(transition_type),
      memory_cost_(0),
      referrer_policy_(referrer_policy),
      is_prerendering_(is_prerendering),
      context_(context),
      report_raw_headers_(report_raw_headers),
      is_async_(is_async),
      previews_state_(previews_state),
      body_(body),
      initiated_in_secure_context_(initiated_in_secure_context),
      blocked_cross_site_document_(false),
      first_auth_attempt_(true) {}

ResourceRequestInfoImpl::~ResourceRequestInfoImpl() {
}

ResourceRequestInfo::ApplicationContentsGetter
ResourceRequestInfoImpl::GetApplicationContentsGetterForRequest() const {
  // PlzNavigate: navigation requests are created with a valid FrameTreeNode ID
  // and invalid RenderProcessHost and RenderFrameHost IDs. The FrameTreeNode
  // ID should be used to access the WebContents.
  //if (frame_tree_node_id_ != -1) {
  //  DCHECK(IsBrowserSideNavigationEnabled());
  //  return base::Bind(ApplicationContents::FromFrameTreeNodeId, frame_tree_node_id_);
  //}

  // In other cases, use the RenderProcessHost ID + RenderFrameHost ID to get
  // the WebContents.
  int render_process_host_id = -1;
  int render_frame_host_id = -1;
  if (!GetAssociatedApplicationWindow(&render_process_host_id,
                                      &render_frame_host_id)) {
    NOTREACHED();
  }

  return base::Bind(&ApplicationContents::FromID,
                    render_process_host_id, 
                    render_frame_host_id);
}

ResourceRequestInfo::FrameTreeNodeIdGetter
ResourceRequestInfoImpl::GetFrameTreeNodeIdGetterForRequest() const {
  //if (frame_tree_node_id_ != -1) {
  //  DCHECK(IsBrowserSideNavigationEnabled());
  //  return base::Bind([](int id) { return id; }, frame_tree_node_id_);
  //}

  int render_process_host_id = -1;
  int render_frame_host_id = -1;
  if (!GetAssociatedApplicationWindow(&render_process_host_id,
                                &render_frame_host_id)) {
    NOTREACHED();
  }

  return base::Bind(&FrameTreeNodeIdFromHostIds, render_process_host_id,
                    render_frame_host_id);
}

ResourceContext* ResourceRequestInfoImpl::GetContext() const {
  return context_;
}

int ResourceRequestInfoImpl::GetChildID() const {
  return requester_info_->child_id();
}

int ResourceRequestInfoImpl::GetRouteID() const {
  return route_id_;
}

GlobalRequestID ResourceRequestInfoImpl::GetGlobalRequestID() const {
  return GlobalRequestID(GetChildID(), request_id_);
}

int ResourceRequestInfoImpl::GetPluginChildID() const {
  return plugin_child_id_;
}

int ResourceRequestInfoImpl::GetApplicationWindowID() const {
  return render_frame_id_;
}

int ResourceRequestInfoImpl::GetFrameTreeNodeId() const {
  return frame_tree_node_id_;
}

bool ResourceRequestInfoImpl::IsMainFrame() const {
  return is_main_frame_;
}

common::ResourceType ResourceRequestInfoImpl::GetResourceType() const {
  return resource_type_;
}

int ResourceRequestInfoImpl::GetProcessType() const {
  //return requester_info_->IsBrowserSideNavigation() ? PROCESS_TYPE_HOST
  //                                                  : PROCESS_TYPE_APPLICATION;
  return common::PROCESS_TYPE_APPLICATION;
}

blink::WebReferrerPolicy ResourceRequestInfoImpl::GetReferrerPolicy() const {
  return referrer_policy_;
}

bool ResourceRequestInfoImpl::IsPrerendering() const {
  return is_prerendering_;
}

ui::PageTransition ResourceRequestInfoImpl::GetPageTransition() const {
  return transition_type_;
}

bool ResourceRequestInfoImpl::HasUserGesture() const {
  return has_user_gesture_;
}

bool ResourceRequestInfoImpl::GetAssociatedApplicationWindow(
    int* render_process_id,
    int* render_frame_id) const {
  *render_process_id = GetChildID();
  *render_frame_id = render_frame_id_;
  return true;
}

bool ResourceRequestInfoImpl::IsAsync() const {
  return is_async_;
}

bool ResourceRequestInfoImpl::IsDownload() const {
  return is_download_;
}

common::PreviewsState ResourceRequestInfoImpl::GetPreviewsState() const {
  return previews_state_;
}

bool ResourceRequestInfoImpl::ShouldReportRawHeaders() const {
  return report_raw_headers_;
}

//NavigationUIData* ResourceRequestInfoImpl::GetNavigationUIData() const {
//  return navigation_ui_data_.get();
//}

//ResourceRequestInfo::DevToolsStatus ResourceRequestInfoImpl::GetDevToolsStatus()
//    const {
//  return devtools_status_;
//}

//base::Optional<blink::ResourceRequestBlockedReason>
//ResourceRequestInfoImpl::GetResourceRequestBlockedReason() const {
//  return resource_request_blocked_reason_;
//}

base::StringPiece ResourceRequestInfoImpl::GetCustomCancelReason() const {
  return custom_cancel_reason_;
}

void ResourceRequestInfoImpl::AssociateWithRequest(net::URLRequest* request) {
  request->SetUserData(kResourceRequestInfoImplKey, base::WrapUnique(this));
  //int render_process_id;
  //int render_frame_id;
  //if (GetAssociatedApplicationWindow(&render_process_id, &render_frame_id)) {
  //  request->SetUserData(URLRequestUserData::kUserDataKey,
  //                       std::make_unique<URLRequestUserData>(render_process_id,
  //                                                            render_frame_id));
  //}
}

int ResourceRequestInfoImpl::GetRequestID() const {
  return request_id_;
}

GlobalRoutingID ResourceRequestInfoImpl::GetGlobalRoutingID() const {
  return GlobalRoutingID(GetChildID(), route_id_);
}

void ResourceRequestInfoImpl::ResetBody() {
  body_ = nullptr;
}

//void ResourceRequestInfoImpl::SetBlobHandles(BlobHandles blob_handles) {
//  blob_handles_ = std::move(blob_handles);
//}

}  // namespace host
