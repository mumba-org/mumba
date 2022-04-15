// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/application_contents.h"

#include <stddef.h>
#include <cmath>
#include <utility>
#include <vector>

#include "base/command_line.h"
#include "base/debug/dump_without_crashing.h"
#include "base/feature_list.h"
#include "base/i18n/character_encoding.h"
#include "base/lazy_instance.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/sha1.h"
#include "base/memory/ptr_util.h"
#include "base/memory/ref_counted.h"
#include "base/metrics/histogram_macros.h"
#include "base/metrics/user_metrics.h"
#include "base/process/process.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string16.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/time.h"
#include "base/trace_event/trace_event.h"
#include "build/build_config.h"
//#include "components/download/public/common/download_stats.h"
//#include "components/rappor/public/rappor_utils.h"
#include "components/url_formatter/url_formatter.h"
//#include "core/host/accessibility/browser_accessibility_state_impl.h"
//#include "core/host/frame_host/cross_process_frame_connector.h"
//#include "core/host/frame_host/frame_tree_node.h"
//#include "core/host/frame_host/navigation_entry_impl.h"
//#include "core/host/frame_host/navigation_handle_impl.h"
//#include "core/host/frame_host/navigation_request.h"
//#include "core/host/frame_host/navigator_impl.h"
//#include "core/host/frame_host/render_frame_host_impl.h"
//#include "core/host/frame_host/render_frame_proxy_host.h"
#include "core/host/gpu/gpu_data_manager_impl.h"
//#include "core/host/loader/loader_io_thread_notifier.h"
//#include "core/host/loader/resource_dispatcher_host_impl.h"
//#include "core/host/manifest/manifest_manager_host.h"
#include "core/host/media/audio_stream_monitor.h"
#include "core/host/media/capture/application_contents_audio_muter.h"
#include "core/host/media/media_application_contents_observer.h"
#include "core/host/media/session/media_session_impl.h"
//#include "core/host/plugin_content_origin_whitelist.h"
#include "core/host/application/application.h"
#include "core/host/application/application_process_host.h"
#include "core/host/application/application_window_host_delegate_view.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/application_window_host_factory.h"
#include "core/host/application/application_window_host_input_event_router.h"
#include "core/host/application/application_window_host_view.h"
#include "core/host/application/interstitial_page_impl.h"
#include "core/host/application/navigation_controller.h"
//#include "core/host/application/application_window_host_view_child_frame.h"
#include "core/host/application/text_input_manager.h"
#include "core/host/application/load_notification_details.h"
#include "core/host/screen_orientation/screen_orientation_provider.h"
//#include "core/host/application/application_contents_view_child_frame.h"
//#include "core/host/application/application_contents_view_guest.h"
#include "core/host/application/application_contents_view.h"
//#include "core/shared/common/drag_messages.h"
//#include "core/shared/common/frame_messages.h"
//#include "core/shared/common/input_messages.h"
//#include "core/shared/common/page_messages.h"
//#include "core/shared/common/page_state_serialization.h"
//#include "core/shared/common/render_message_filter.mojom.h"
//#include "core/shared/common/view_messages.h"
#include "core/host/ax_event_notification_details.h"
#include "core/host/route/route_registry.h"
#include "core/host/route/route_entry.h"
#include "core/host/host_thread.h"
#include "core/host/host.h"
#include "core/host/io_thread.h"
#include "core/host/host_client.h"
//#include "core/host/focused_node_details.h"
//#include "core/host/invalidate_type.h"
#include "core/host/application/keyboard_event_processing_result.h"
//#include "core/host/load_notification_details.h"
//#include "core/host/navigation_details.h"
#include "core/host/notification_details.h"
#include "core/host/notification_service.h"
#include "core/host/notification_types.h"
#include "core/host/application/application_window_host_iterator.h"
//#include "core/host/restore_type.h"
#include "core/host/application/application_contents_binding_set.h"
#include "core/host/application/application_contents_delegate.h"
#include "core/host/application/resource_context_impl.h"
#include "core/host/ui/tablist/sad_tab_helper.h"
//#include "core/host/application/rpc_data_source.h"
#include "core/host/application/url_data_manager.h"
//#include "core/shared/common/bindings_policy.h"
//#include "core/common/browser_side_navigation_policy.h"
#include "core/shared/common/child_process_host.h"
#include "core/shared/common/child_process_host_impl.h"
#include "core/common/content_constants.h"
#include "core/shared/common/content_features.h"
#include "core/shared/common/switches.h"
#include "core/shared/common/page_state.h"
#include "core/shared/common/page_zoom.h"
#include "core/common/result_codes.h"
#include "core/shared/common/service_manager_connection.h"
#include "core/shared/common/url_utils.h"
#include "core/shared/common/web_preferences.h"
#include "net/base/url_util.h"
#include "net/http/http_cache.h"
#include "net/http/http_transaction_factory.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_getter.h"
#include "services/device/public/mojom/constants.mojom.h"
#include "services/metrics/public/cpp/ukm_recorder.h"
#include "services/service_manager/public/cpp/connector.h"
#include "services/service_manager/public/cpp/interface_provider.h"
#include "third_party/blink/public/common/frame/sandbox_flags.h"
#include "third_party/blink/public/common/mime_util/mime_util.h"
#include "third_party/blink/public/platform/web_security_style.h"
#include "third_party/skia/include/core/SkBitmap.h"
#include "ui/accessibility/ax_tree_combiner.h"
#include "ui/base/layout.h"
#include "ui/events/base_event_utils.h"
#include "ui/events/blink/web_input_event_traits.h"
#include "ui/gl/gl_switches.h"

#if defined(OS_WIN)
#include "core/host/application/dip_util.h"
#include "ui/gfx/geometry/dip_util.h"
#endif

#if defined(OS_ANDROID)
#include "core/host/android/content_video_view.h"
#include "core/host/android/date_time_chooser_android.h"
#include "core/host/android/java_interfaces_impl.h"
#include "core/host/media/android/media_application_contents_observer_android.h"
#include "core/host/application_contents/application_contents_android.h"
#include "services/device/public/mojom/nfc.mojom.h"
#else  // !OS_ANDROID
#include "core/host/application/host_zoom_map.h"
#include "core/host/application/host_zoom_map_observer.h"
#endif  // OS_ANDROID

namespace host {

namespace {

const int kMinimumDelayBetweenLoadingUpdatesMS = 100;

base::LazyInstance<std::vector<
    ApplicationContents::FriendWrapper::CreatedCallback>>::DestructorAtExit
    g_created_callbacks = LAZY_INSTANCE_INITIALIZER;

}

void ApplicationContents::FriendWrapper::AddCreatedCallbackForTesting(
    const CreatedCallback& callback) {
  g_created_callbacks.Get().push_back(callback);
}

void ApplicationContents::FriendWrapper::RemoveCreatedCallbackForTesting(
    const CreatedCallback& callback) {
  for (size_t i = 0; i < g_created_callbacks.Get().size(); ++i) {
    if (g_created_callbacks.Get().at(i).Equals(callback)) {
      g_created_callbacks.Get().erase(g_created_callbacks.Get().begin() + i);
      return;
    }
  }
}

// ApplicationContents::DestructionObserver ----------------------------------------

class ApplicationContents::DestructionObserver : public ApplicationContentsObserver {
 public:
  DestructionObserver(ApplicationContents* owner, ApplicationContents* watched_contents)
      : ApplicationContentsObserver(watched_contents),
        owner_(owner) {
  }

  ~DestructionObserver() override {
    
  }

  // ApplicationContentsObserver:
  void ApplicationContentsDestroyed() override {
    owner_->OnApplicationContentsDestroyed(application_contents());
  }

 private:
  ApplicationContents* owner_;

  DISALLOW_COPY_AND_ASSIGN(DestructionObserver);
};


ApplicationContents::CreateParams::CreateParams()
    : opener_application_process_id(common::ChildProcessHost::kInvalidUniqueID),
      opener_suppressed(false),
      routing_id(MSG_ROUTING_NONE),
      initially_hidden(false),
      context(nullptr),
      application_initiated_creation(false),
      initialize_application(false),
      starting_sandbox_flags(blink::WebSandboxFlags::kNone) {}

ApplicationContents::CreateParams::CreateParams(const CreateParams& other) = default;

ApplicationContents::CreateParams::~CreateParams() {
}

ApplicationWindowHost* ApplicationContents::GetFullscreenApplicationWindowHost() const {
  return ApplicationWindowHost::FromID(fullscreen_widget_process_id_,
                                       fullscreen_widget_routing_id_);
}

// static 
std::vector<ApplicationContents*> ApplicationContents::GetAllApplicationContents() {
  std::vector<ApplicationContents*> result;
  std::unique_ptr<ApplicationWindowHostIterator> widgets(
      ApplicationWindowHost::GetApplicationWindowHosts());
  while (ApplicationWindowHost* rwh = widgets->GetNextHost()) {
    ApplicationContents* app_contents = ApplicationContents::FromApplicationWindowHost(rwh);
    if (!app_contents)
      continue;
    if (app_contents->GetApplicationWindowHost() != rwh)
      continue;
    // Because a ApplicationContents can only have one current RVH at a time, there will
    // be no duplicate ApplicationContents here.
    result.push_back(app_contents);
  }
  return result;
}

// internal
ApplicationContents::ApplicationContents(): 
      delegate_(nullptr),
//      controller_(this),
      application_window_host_delegate_view_(nullptr),
      created_with_opener_(false),
      //frame_tree_(new NavigatorImpl(&controller_, this),
      //            this,
      //            this,
      //            this,
      //            this),
  //    node_(this),
 //     is_load_to_different_document_(false),
      crashed_status_(base::TERMINATION_STATUS_STILL_RUNNING),
      crashed_error_code_(0),
      waiting_for_response_(false),
      load_state_(net::LOAD_STATE_IDLE, base::string16()),
      upload_size_(0),
      upload_position_(0),
      is_resume_pending_(false),
      interstitial_page_(nullptr),
      has_accessed_initial_document_(false),
      did_first_visually_non_empty_paint_(false),
      capturer_count_(0),
      is_being_destroyed_(false),
      is_notifying_observers_(false),
      notify_disconnection_(false),
   //   dialog_manager_(nullptr),
      //is_showing_before_unload_dialog_(false),
      last_active_time_(base::TimeTicks::Now()),
      closed_by_user_gesture_(false),
      minimum_zoom_percent_(static_cast<int>(common::kMinimumZoomFactor * 100)),
      maximum_zoom_percent_(static_cast<int>(common::kMaximumZoomFactor * 100)),
      zoom_scroll_remainder_(0),
      application_process_host_(nullptr),
      application_window_host_(nullptr),
      fullscreen_widget_process_id_(common::ChildProcessHost::kInvalidUniqueID),
      fullscreen_widget_routing_id_(MSG_ROUTING_NONE),
      fullscreen_widget_had_focus_at_shutdown_(false),
      //is_subframe_(false),
      force_disable_overscroll_content_(false),
      //last_dialog_suppressed_(false),
      accessibility_mode_(),
          //BrowserAccessibilityStateImpl::GetInstance()->accessibility_mode()),
      bluetooth_connected_device_count_(0),
#if !defined(OS_ANDROID)
      page_scale_factor_is_one_(true),
#endif  // !defined(OS_ANDROID)
      is_overlay_content_(false),
      showing_context_menu_(false),
      resource_context_(nullptr),
      parent_(nullptr),
      url_resolver_(nullptr),
      is_waiting_for_close_ack_(false),
      loading_weak_factory_(this),
      weak_factory_(this) {


  //URLDataManager::AddDataSource(this, new SharedResourcesDataSource());
}

ApplicationContents::~ApplicationContents() {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));
  //DLOG(INFO) << "~ApplicationContents: " << this;
  // Imperfect sanity check against double free, given some crashes unexpectedly
  // observed in the wild.
  //CHECK(!is_being_destroyed_);

  // We generally keep track of is_being_destroyed_ to let other features know
  // to avoid certain actions during destruction.
  //is_being_destroyed_ = true
  if (application_) {
    application_->set_contents(nullptr);
  }

  // A ApplicationContents should never be deleted while it is notifying observers,
  // since this will lead to a use-after-free as it continues to notify later
  // observers.
  CHECK(!is_notifying_observers_);

  awh_input_event_router_.reset();

  for (auto& entry : binding_sets_)
    entry.second->CloseAllBindings();

  //ApplicationContentsImpl* outermost = GetOutermostApplicationContents();
  //if (this != outermost && ContainsOrIsFocusedApplicationContents()) {
    // If the current ApplicationContents is in focus, unset it.
  //  outermost->SetAsFocusedApplicationContentsIfNecessary();
  //}

  if (mouse_lock_widget_)
    mouse_lock_widget_->RejectMouseLockOrUnlockIfNecessary();

  // for (FrameTreeNode* node : frame_tree_.Nodes()) {
  //   // Delete all RFHs pending shutdown, which will lead the corresponding RVHs
  //   // to be shutdown and be deleted as well.
  //   node->render_manager()->ClearRFHsPendingShutdown();
  //   node->render_manager()->ClearWebUIInstances();
  // }

  for (ApplicationWindowHost* window : created_windows_)
    window->DetachDelegate();
  created_windows_.clear();

  NotifyDisconnected();

  // Notify any observer that have a reference on this ApplicationContents.
  NotificationService::current()->Notify(
      NOTIFICATION_WEB_CONTENTS_DESTROYED,
      Source<ApplicationContents>(this),
      NotificationService::NoDetails());

  // Destroy all frame tree nodes except for the root; this notifies observers.
  //frame_tree_.root()->ResetForNewProcess();
  //GetRenderManager()->ResetProxyHosts();

  // Manually call the observer methods for the root frame tree node. It is
  // necessary to manually delete all objects tracking navigations
  // (NavigationHandle, NavigationRequest) for observers to be properly
  // notified of these navigations stopping before the ApplicationContents is
  // destroyed.
  //RenderFrameHostManager* root = GetRenderManager();
  //root->current_frame_host()->SetRenderFrameCreated(false);
  //root->current_frame_host()->ResetNavigationRequests();

  // Do not update state as the ApplicationContents is being destroyed.
  //frame_tree_.root()->ResetNavigationRequest(true, true);
  //if (root->speculative_frame_host()) {
  //  root->speculative_frame_host()->SetRenderFrameCreated(false);
  //  root->speculative_frame_host()->ResetNavigationRequests();
  //}

  //for (auto& observer : observers_)
  //  observer.FrameDeleted(root->current_frame_host());

 
  // NOTE: this is rather unfortunate, but at least URLLoaderFactory
  //       which is a Contents observer must be destroyed on IOThread
  //       or else mojo objects on destruction will complain and crash
  //       (couldnt find any facility to rebind them to UI thread)
  //       But this give us potential thread safety problems.. 
  //       The URLLoader factory already have a Observer that is appart
  //       so that we can destroy it on UI  


  // NOTE: we need this copy here as some observers delete themselves
  //       when those events are called.
  //       otherwise we will be iterating over std iterator pointers
  //       that were removed while we are iterating over it!
  //       while it might be a little bit expensive, at least we are safe
  //       (the WeakPtr based observer will prevent us from calling a dead reference)

  std::vector<base::WeakPtr<ApplicationContentsObserver>> observers = observers_;
  // for (const auto& observer : observers) {
  //   if (observer) {
  //     observer->ApplicationWindowDeleted(application_window_host());//(root->current_host());
  //   }
  // }

  observers = observers_;
  for (const auto& observer : observers) {
    if (observer) {
      observer->ApplicationContentsDestroyed();
    }
  }

  observers = observers_;
  for (const auto& observer : observers) {
    if (observer) {
      observer->ResetApplicationContents();
    }
  }

  application_window_host()->render_frame_metadata_provider()->RemoveObserver(this);

  application_window_host()->DetachDelegate();

  SetDelegate(nullptr);
}

// static
ApplicationContents* ApplicationContents::Create(
    const ApplicationContents::CreateParams& params) {
  TRACE_EVENT0("host", "ApplicationContents::Create");
  ApplicationContents* new_contents = new ApplicationContents();
  new_contents->Init(params);
  return new_contents;
}

// static 
ApplicationContents* ApplicationContents::FromApplicationWindowHost(ApplicationWindowHost* awh) {
  if (!awh || !awh->delegate())
    return nullptr;
  return awh->delegate()->GetAsApplicationContents();
}

// static 
ApplicationContents* ApplicationContents::FromID(int32_t process_id, int32_t routing_id) {
  ApplicationWindowHost* awh = ApplicationWindowHost::FromID(process_id, routing_id);
  if (!awh) {
    return nullptr;
  }
  return awh->delegate()->GetAsApplicationContents(); 
}

void ApplicationContents::Init(const CreateParams& params) {
  DCHECK(params.workspace);

  audio_stream_monitor_ = std::make_unique<AudioStreamMonitor>(this);

#if defined(OS_ANDROID)
  media_application_contents_observer_.reset(new MediaApplicationContentsObserverAndroid(this));
#else
  media_application_contents_observer_.reset(new MediaApplicationContentsObserver(this));
#endif
  //loader_io_thread_notifier_.reset(new LoaderIOThreadNotifier(this));
#if !defined(OS_ANDROID)
  host_zoom_map_observer_.reset(new HostZoomMapObserver(this));
#endif  // !defined(OS_ANDROID)

  url_ = params.url;

  DCHECK(params.parent);
  DCHECK(params.url_resolver);

  parent_ = params.parent;
  resource_context_ = parent_->GetResourceContext();

  application_ = params.application;
  DCHECK(application_);
  application_->set_contents(this);
  application_->set_initial_url(params.url);
  url_resolver_ = params.url_resolver;
  url_controller_ = std::make_unique<RouteController>(url_resolver_);
  navigation_controller_ = std::make_unique<NavigationController>(url_controller_.get());
  navigation_controller_->Navigate(params.url,
                                   base::BindOnce(&ApplicationContents::OnNavigationCompletion,
                                                  weak_factory_.GetWeakPtr(),
                                                  params));
  visibility_ =
      params.initially_hidden ? Visibility::HIDDEN : Visibility::VISIBLE;

  // we need to be sure to create the view before the owned process..
  // the owned process build a owned ApplicationWindowHost wich in turn
  // call the ApplicationContentsView
  ApplicationContentsViewDelegate* delegate =
      common::GetClient()->host()->GetApplicationContentsViewDelegate(this);

  view_.reset(CreateApplicationContentsView(this, delegate,
                                            &application_window_host_delegate_view_));
  
  CHECK(application_window_host_delegate_view_);
  CHECK(view_.get());

    //GetRenderManager()->Init(
  //    site_instance.get(), view_routing_id, params.main_frame_routing_id,
  //    main_frame_widget_routing_id, params.renderer_initiated_creation);

  std::unique_ptr<ApplicationProcessHost> owned_process = std::make_unique<ApplicationProcessHost>(application_->GetWeakPtr());
  application_process_host_ = owned_process.get();  

  int32_t view_routing_id = application_process_host_->GetNextRoutingID();//common::ChildProcessHostImpl::GenerateChildProcessUniqueId();
 
  std::unique_ptr<ApplicationWindowHost> application_window_host( 
      ApplicationWindowHostFactory::Create(
        this,
        application_,
        application_process_host_,
        view_routing_id,
        false,
        true /*hidden*/));
        //false /*hidden*/));

  application_window_host_ = application_window_host.get();
  application_process_host_->SetWindow(std::move(application_window_host));

  application_window_host_->render_frame_metadata_provider()->AddObserver(this);
  
  //gfx::Size initial_size = params.initial_size;
  //if (initial_size.IsEmpty()) {
  //  initial_size = gfx::Size(800, 571);
  //}

  view_->CreateView(params.initial_size, params.context);

  ApplicationWindowHostView* domain_view = 
    view_->CreateViewForWindow(application_window_host_);

  // Now that the ApplicationView has been created, we need to tell it its size.
  if (domain_view) {
    domain_view->SetSize(GetSizeForNewApplicationWindow(true));
  }

  IOThread* io_thread = Host::Instance()->io_thread();
  io_thread->LaunchApplicationProcess(
    std::move(owned_process), 
    base::BindRepeating(&ApplicationContents::InitAfterLaunch, 
      weak_factory_.GetWeakPtr(), 
      params));

  //ApplicationProcessHost* process = nullptr;
  //if (params.opener_application_process_id) {
  //  process = ApplicationProcessHost::FromID(params.opener_application_process_id);
  //  if (process) {
  //    process->RegisterWindow(std::move(application_window_host));
  //  }
  //}
  //if (!process) {
    //should_launch_process = true;
    
  //  IOThread* io_thread = Host::Instance()->io_thread();
  //  io_thread->LaunchApplicationProcess(std::move(owned_process), base::BindRepeating(&ApplicationContents::InitAfterLaunch, weak_factory_.GetWeakPtr(), params));
  //}
  
  //if (!should_launch_process) {
  // if we are not launching it, we need to call this manually
  //  InitAfterLaunch(params, process, true);
  //}
}

void ApplicationContents::OnNavigationCompletion(const CreateParams& params, int result, NavigationEntry* entry) {
  // what to do in this case ?
  if (result != net::OK) {
    DLOG(ERROR) << "navigation to " << params.url << " failed.";
    //DCHECK(false);
    return;
  }

  
}

//bool ApplicationContents::InitApplicationWindow(const CreateParams& params, ApplicationWindowHost* application_window_host) {
  //if (!GetRenderManager()->current_frame_host()->IsRenderFrameLive()) {
  //  GetRenderManager()->InitRenderView(GetApplicationWindowHost(), nullptr);
  //}
  // Ensure the renderer process is initialized before creating the
  // RenderView.
  ////DLOG(INFO) << "ApplicationContents::InitApplicationWindow: launching process..";
  // TODO: see if we can call application_window_host->CreateApplicationWindow()
  //       here instead, giving it already try to launch the ApplicationProcess
  //if (!application_window_host->GetProcess()->Init(base::UUID::generate()))
  //  return false;

  // We may have initialized this RenderViewHost for another RenderFrameHost.
  //if (application_window_host->IsApplicationWindowLive()) {
  //  //DLOG(INFO) << "ApplicationContents::InitApplicationWindow: launching process..";
  //  return true;
  //}
  
//  ApplicationWindowHostView* domain_view = 
//    view_->CreateViewForWindow(application_window_host);

  // Now that the ApplicationView has been created, we need to tell it its size.
//  if (domain_view) {
//    domain_view->SetSize(GetSizeForNewApplicationWindow(true));
//  }

//  return true;
//}

// bool ApplicationContents::CreateApplicationWindowForApplicationContents(
//     ApplicationWindowHost* application_window_host) {
//   //if (proxy_routing_id == MSG_ROUTING_NONE)
//   CreateApplicationWindowHostViewForApplicationContents(application_window_host);

//   if (!application_window_host->CreateApplicationWindow()) {
//     return false;
//   }

// #if defined(OS_POSIX) && !defined(OS_MACOSX) && !defined(OS_ANDROID)
//   // Force a ViewMsg_Resize to be sent, needed to make plugins show up on
//   // linux. See crbug.com/83941.
//   ApplicationWindowHostView* awh_view = application_window_host->GetView();
//   if (awh_view) {
//     if (ApplicationWindowHost* window_host = awh_view->GetApplicationWindowHost()) {
//       window_host->SynchronizeVisualProperties();
//     }
//   }
// #endif

//   return true;
// }

void ApplicationContents::CreateApplicationWindowHostViewForApplicationContents(
    ApplicationWindowHost* application_window_host) {
  
  ApplicationWindowHostView* awh_view = 
    view_->CreateViewForWindow(application_window_host);

  // Now that the RenderView has been created, we need to tell it its size.
  if (awh_view)
    awh_view->SetSize(GetSizeForNewApplicationWindow(true));
}

void ApplicationContents::ClosePage() {
  GetApplicationWindowHost()->ClosePage();
}

device::mojom::WakeLockContext* ApplicationContents::GetWakeLockContext() {
  if (!wake_lock_context_host_)
    wake_lock_context_host_.reset(new WakeLockContextHost(this));
  return wake_lock_context_host_->GetWakeLockContext();
}

void ApplicationContents::DragSourceEndedAt(float client_x,
                       float client_y,
                       float screen_x,
                       float screen_y,
                       blink::WebDragOperation operation,
                       ApplicationWindowHost* source_rwh) {
  if (source_rwh) {
    source_rwh->DragSourceEndedAt(gfx::PointF(client_x, client_y),
                                  gfx::PointF(screen_x, screen_y), operation);
  }
}

void ApplicationContents::LoadStateChanged(const std::string& host,
                      const net::LoadStateWithParam& load_state,
                      uint64_t upload_position,
                      uint64_t upload_size) {
  base::string16 host16 = url_formatter::IDNToUnicode(host);
  // Drop no-op updates.
  if (load_state_.state == load_state.state &&
      load_state_.param == load_state.param &&
      upload_position_ == upload_position && upload_size_ == upload_size &&
      load_state_host_ == host16) {
    return;
  }
  load_state_ = load_state;
  upload_position_ = upload_position;
  upload_size_ = upload_size;
  load_state_host_ = host16;
  if (load_state_.state == net::LOAD_STATE_READING_RESPONSE)
    SetNotWaitingForResponse();
  if (IsLoading()) {
    NotifyNavigationStateChanged(static_cast<InvalidateTypes>(
        INVALIDATE_TYPE_LOAD | INVALIDATE_TYPE_TAB));
  }
}

void ApplicationContents::SetVisibility(Visibility visibility) {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));
  const Visibility previous_visibility = visibility_;
  visibility_ = visibility;

  // Notify observers if the visibility changed or if WasShown() is being called
  // for the first time.
  if (visibility != previous_visibility ||
      (visibility == Visibility::VISIBLE && !did_first_set_visible_)) {
    for (const auto& observer : observers_) {
      if (observer)
        observer->OnVisibilityChanged(visibility);
    }
  }
}

void ApplicationContents::NotifyApplicationContentsFocused(ApplicationWindowHost* application_window_host) {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));
  for (const auto& observer : observers_) {
    if (observer)
      observer->OnApplicationContentsFocused(application_window_host);
  }
}

void ApplicationContents::NotifyApplicationContentsLostFocus(ApplicationWindowHost* application_window_host) {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));
  for (const auto& observer : observers_) {
    if (observer) {
      observer->OnApplicationContentsLostFocus(application_window_host);
    }
  }
}

ApplicationContentsView* ApplicationContents::GetView() const {
  return view_.get();
}

void ApplicationContents::NotifyNavigationStateChanged(
    InvalidateTypes changed_flags) {
  // Notify the media observer of potential audibility changes.
  if (changed_flags & INVALIDATE_TYPE_TAB) {
    media_application_contents_observer_->MaybeUpdateAudibleState();
  }

  if (delegate_)
    delegate_->NavigationStateChanged(this, changed_flags);

  //if (GetOuterWebContents())
  //  GetOuterWebContents()->NotifyNavigationStateChanged(changed_flags);
}

void ApplicationContents::OnScreenOrientationChange() {
  DCHECK(screen_orientation_provider_);
  return screen_orientation_provider_->OnOrientationChange();
}

void ApplicationContents::SetAccessibilityMode(ui::AXMode mode) {
  if (mode == accessibility_mode_)
    return;

  // Don't allow accessibility to be enabled for ApplicationContents that are never
  // visible, like background pages.
  if (IsNeverVisible())
    return;

  accessibility_mode_ = mode;

  // for (FrameTreeNode* node : frame_tree_.Nodes()) {
  //   UpdateAccessibilityModeOnFrame(node->current_frame_host());
  //   // Also update accessibility mode on the speculative RenderFrameHost for
  //   // this FrameTreeNode, if one exists.
  //   RenderFrameHost* speculative_frame_host =
  //       node->render_manager()->speculative_frame_host();
  //   if (speculative_frame_host)
  //     UpdateAccessibilityModeOnFrame(speculative_frame_host);
  // }
}

void ApplicationContents::AddAccessibilityMode(ui::AXMode mode) {
  ui::AXMode new_mode(accessibility_mode_);
  new_mode |= mode;
  SetAccessibilityMode(new_mode);  
}

#if !defined(OS_ANDROID)
void ApplicationContents::SetTemporaryZoomLevel(double level, bool temporary_zoom_enabled) {
  if (auto* window = GetApplicationWindowHost()) {
    window->SetZoomLevel(level);
  }
}

void ApplicationContents::UpdateZoom(double level) {
  if (auto* window = GetApplicationWindowHost()) {
    window->SetZoomLevel(level);
  }
}

// TODO: this can go away as is always necessary giving we dont have frame tree's here
void ApplicationContents::UpdateZoomIfNecessary(const std::string& scheme,
                           const std::string& host,
                           double level) {
  UpdateZoom(level);
}
#endif  // !defined(OS_ANDROID)

base::Closure ApplicationContents::AddBindingSet(const std::string& interface_name,
                              ApplicationContentsBindingSet* binding_set) {
  auto result =
      binding_sets_.insert(std::make_pair(interface_name, binding_set));
  DCHECK(result.second);
  return base::Bind(&ApplicationContents::RemoveBindingSet,
                    weak_factory_.GetWeakPtr(), interface_name);
}

ApplicationContentsBindingSet* ApplicationContents::GetBindingSet(const std::string& interface_name) {
  auto it = binding_sets_.find(interface_name);
  if (it == binding_sets_.end())
    return nullptr;
  return it->second;
}

bool ApplicationContents::HasRecentInteractiveInputEvent() const {
  static constexpr base::TimeDelta kMaxInterval =
      base::TimeDelta::FromSeconds(5);
  base::TimeDelta delta =
      ui::EventTimeForNow() - last_interactive_input_event_time_;
  // Note: the expectation is that the caller is typically expecting an input
  // event, e.g. validating that a WebUI message that requires a gesture is
  // actually attached to a gesture. Logging to UMA here should hopefully give
  // sufficient data if 5 seconds is actually sufficient (or even too high a
  // threshhold).
  UMA_HISTOGRAM_TIMES("Tabs.TimeSinceLastInteraction", delta);
  return delta <= kMaxInterval;
}

ApplicationContentsDelegate* ApplicationContents::GetDelegate() {
  return delegate_;
}

void ApplicationContents::SetDelegate(ApplicationContentsDelegate* delegate) {
  if (delegate == delegate_)
    return;
  if (delegate_)
    delegate_->Detach(this);
  delegate_ = delegate;
  if (delegate_) {
    delegate_->Attach(this);
    // Ensure the visible RVH reflects the new delegate's preferences.
    if (view_)
      view_->SetOverscrollControllerEnabled(CanOverscrollContent());
    //if (GetApplicationWindowHost())
      //RenderFrameDevToolsAgentHost::ApplicationContentsCreated(this);
  }
}

const std::string& ApplicationContents::GetApplicationName() const {
  return application_->name();
}

const base::UUID& ApplicationContents::GetApplicationUUID() const {
  return application_->id();
}

const std::string& ApplicationContents::GetPageName() const {
  RouteEntry* entry = url_controller_->GetCurrent();
  DCHECK(entry);
  return entry->name();
}

const GURL& ApplicationContents::GetURL() const {
  //EntryNode* entry = url_controller_->current_entry();
  //return entry && !entry->url().is_empty() ? entry->url() : invalid_empty_url_;
  return url_;
}

const GURL& ApplicationContents::GetVisibleURL() const {
  RouteEntry* entry = url_controller_->GetCurrent();
  DCHECK(entry);
  return entry->url();
}

const GURL& ApplicationContents::GetLastCommittedURL() const {
  RouteEntry* entry = url_controller_->GetCurrent();
  DCHECK(entry);
  return entry->url();
}

ApplicationProcessHost* ApplicationContents::GetApplicationProcessHost() const {
  return application_process_host_;
}

ApplicationWindowHost* ApplicationContents::GetApplicationWindowHost() const {
  return application_window_host();  
}

ApplicationWindowHostView* ApplicationContents::GetApplicationWindowHostView() const {
  if (!application_window_host()) {
    return nullptr;
  }
  return application_window_host()->GetView();
}

ApplicationWindowHostView* ApplicationContents::GetTopLevelApplicationWindowHostView() {
  return GetApplicationWindowHostView();
}

ApplicationWindowHostView* ApplicationContents::GetFullscreenApplicationWindowHostView() const {
  if (auto* window_host = GetFullscreenApplicationWindowHost()) {
    return window_host->GetView();
  }
  return nullptr;
}

void ApplicationContents::EnableApplicationContentsOnlyAccessibilityMode() {
  //if (!GetAccessibilityMode().is_mode_off()) {
  //  for (RenderFrameHost* rfh : GetAllFrames())
  //    ResetAccessibility(rfh);
  //} else {
    AddAccessibilityMode(ui::kAXModeWebContentsOnly);
  //}
}

bool ApplicationContents::IsApplicationContentsOnlyAccessibilityModeForTesting() const {
  return accessibility_mode_ == ui::kAXModeWebContentsOnly;
}

const base::string16& ApplicationContents::GetTitle() const {
  //DCHECK(url_controller_->GetCurrent());
  if (!url_controller_->GetCurrent()) {
    return page_title_when_no_navigation_entry_;
  }
  return url_controller_->GetCurrent()->title();
  //return page_name_utf16_;//page_title_when_no_navigation_entry_;
}

gfx::Image ApplicationContents::GetFavicon() {
  if (!cached_favicon_.IsEmpty()) {
    return cached_favicon_;
  }

  RouteEntry* current = url_controller_->GetCurrent();
  if (!current) {
    return gfx::Image();
  }
  auto icon_size = current->icon_data_size();

  //DLOG(INFO) << current->url() << " icon size: " << icon_size;
  if (icon_size == 0) {
    //DLOG(INFO) << current->url() << " icon size = " << icon_size << " failed to form a favicon";
    return gfx::Image();
  }

  mojo::ScopedSharedBufferMapping mapping = current->icon_data();
  cached_favicon_ = gfx::Image::CreateFrom1xPNGBytes(reinterpret_cast<const unsigned char *>(mapping.get()), icon_size);//icon);
  return cached_favicon_;
}

bool ApplicationContents::IsLoading() const {
  // TODO: implement
  return false;
}

bool ApplicationContents::IsWaitingForResponse() const {
  return waiting_for_response_;// && is_load_to_different_document_;
}

const net::LoadStateWithParam& ApplicationContents::GetLoadState() const {
  return load_state_;
}

const base::string16& ApplicationContents::GetLoadStateHost() const {
  return load_state_host_;
}

void ApplicationContents::RequestAXTreeSnapshot(AXTreeSnapshotCallback callback,
                           ui::AXMode ax_mode) {
  
}

uint64_t ApplicationContents::GetUploadSize() const {
  return upload_size_;
}

uint64_t ApplicationContents::GetUploadPosition() const {
  return upload_position_;
}

const std::string& ApplicationContents::GetEncoding() const {
  return canonical_encoding_;
}

void ApplicationContents::SetWasDiscarded(bool was_discarded) {
  // burp burp
}

void ApplicationContents::IncrementCapturerCount(const gfx::Size& capture_size) {
  //DCHECK(!is_being_destroyed_);
  //const bool was_captured = IsBeingCaptured();
  ++capturer_count_;
  DVLOG(1) << "There are now " << capturer_count_
           << " capturing(s) of ApplicationContents@" << this;

  // Note: This provides a hint to upstream code to size the views optimally
  // for quality (e.g., to avoid scaling).
  if (!capture_size.IsEmpty() && preferred_size_for_capture_.IsEmpty()) {
    preferred_size_for_capture_ = capture_size;
    OnPreferredSizeChanged(preferred_size_);
  }

  // if (GetVisibility() != Visibility::VISIBLE && !was_captured) {
  //   // Ensure that all views act as if they were visible before capture begins.
  //   // TODO(fdoray): Replace ApplicationWindowHostView::WasUnOccluded() with a method
  //   // to explicitly notify the ApplicationWindowHostView that capture began.
  //   // https://crbug.com/668690
  //   for (ApplicationWindowHostView* view : GetApplicationWindowHostViewsInTree())
  //     view->WasUnOccluded();
  // }
}

void ApplicationContents::DecrementCapturerCount() {
  --capturer_count_;
  DVLOG(1) << "There are now " << capturer_count_
           << " capturing(s) of ApplicationContentsImpl@" << this;
  DCHECK_LE(0, capturer_count_);

  //if (is_being_destroyed_)
  //  return;

  if (!IsBeingCaptured()) {
    const gfx::Size old_size = preferred_size_for_capture_;
    preferred_size_for_capture_ = gfx::Size();
    OnPreferredSizeChanged(old_size);

    if (visibility_ == Visibility::HIDDEN) {
      DVLOG(1) << "Executing delayed WasHidden().";
      WasHidden();
    } else if (visibility_ == Visibility::OCCLUDED) {
      WasOccluded();
    }
  }
}

bool ApplicationContents::IsBeingCaptured() const {
  return capturer_count_ > 0;
}

bool ApplicationContents::IsAudioMuted() const {
  return audio_muter_.get() && audio_muter_->is_muting();
}

void ApplicationContents::SetAudioMuted(bool mute) {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));

  if (mute == IsAudioMuted())
    return;

  if (mute) {
    if (!audio_muter_)
      audio_muter_.reset(new ApplicationContentsAudioMuter(this));
    audio_muter_->StartMuting();
  } else {
    DCHECK(audio_muter_);
    audio_muter_->StopMuting();
  }

  for (const auto& observer : observers_) {
    if (observer) 
      observer->DidUpdateAudioMutingState(mute);
  }

  // Notification for UI updates in response to the changed muting state.
  NotifyNavigationStateChanged(INVALIDATE_TYPE_TAB);
}

bool ApplicationContents::IsCurrentlyAudible() {
  return audio_stream_monitor()->IsCurrentlyAudible();
}

bool ApplicationContents::IsConnectedToBluetoothDevice() const {
  return bluetooth_connected_device_count_ > 0;
}

bool ApplicationContents::IsCrashed() const {
  return (crashed_status_ == base::TERMINATION_STATUS_PROCESS_CRASHED ||
          crashed_status_ == base::TERMINATION_STATUS_ABNORMAL_TERMINATION ||
          crashed_status_ == base::TERMINATION_STATUS_PROCESS_WAS_KILLED ||
#if defined(OS_CHROMEOS)
          crashed_status_ ==
              base::TERMINATION_STATUS_PROCESS_WAS_KILLED_BY_OOM ||
#endif
          crashed_status_ == base::TERMINATION_STATUS_LAUNCH_FAILED);
}

void ApplicationContents::SetIsCrashed(base::TerminationStatus status, int error_code) {
  if (status == crashed_status_)
    return;

  crashed_status_ = status;
  crashed_error_code_ = error_code;
}

base::TerminationStatus ApplicationContents::GetCrashedStatus() const {
  return crashed_status_;
}

int ApplicationContents::GetCrashedErrorCode() const {
  return crashed_error_code_;
}

bool ApplicationContents::IsBeingDestroyed() const {
  return is_being_destroyed_;
}

void ApplicationContents::OnAudioStateChanged(bool is_audible) {
  if (auto* window = GetApplicationWindowHost()) {  
    window->AudioStateChanged(is_audible);
  }
  //SendPageMessage(new PageMsg_AudioStateChanged(MSG_ROUTING_NONE, is_audible));

  // Notification for UI updates in response to the changed audio state.
  NotifyNavigationStateChanged(INVALIDATE_TYPE_TAB);

  was_ever_audible_ = was_ever_audible_ || is_audible;

  if (delegate_)
    delegate_->OnAudioStateChanged(this, is_audible);
}

base::TimeTicks ApplicationContents::GetLastActiveTime() const {
  return last_active_time_;
}

void ApplicationContents::SetLastActiveTime(base::TimeTicks last_active_time) {
  last_active_time_ = last_active_time;
}

void ApplicationContents::WasShown() {
  ////DLOG(INFO) << " \n\n ** ApplicationContents::WasShown ** \n\n";
  url_controller_->set_active(true);

  // NOTE: changed here
  // application_window_host_->BeginNavigation();
  // end change

  if (auto* view = GetApplicationWindowHostView()) {
    view->Show();
#if defined(OS_MACOSX)
    view->SetActive(true);
#endif
  }

  //if (!ShowingInterstitialPage())
    SetVisibilityForChildViews(true);

  //SendPageMessage(new PageMsg_WasShown(MSG_ROUTING_NONE));
  if (auto* window = GetApplicationWindowHost()) {
    window->PageWasShown();
  }

  last_active_time_ = base::TimeTicks::Now();
  SetVisibility(Visibility::VISIBLE);
}

void ApplicationContents::WasHidden() {
  ////DLOG(INFO) << " \n\n ** ApplicationContents::WasHidden ** \n\n";
  url_controller_->set_active(false);  
  // If there are entities capturing screenshots or video (e.g., mirroring),
  // don't activate the "disable rendering" optimization.
  if (!IsBeingCaptured()) {
    // |GetApplicationWindowHost()| can be NULL if the user middle clicks a link to
    // open a tab in the background, then closes the tab before selecting it.
    // This is because closing the tab calls ApplicationContentsImpl::Destroy(), which
    // removes the |GetApplicationWindowHost()|; then when we actually destroy the
    // window, OnWindowPosChanged() notices and calls WasHidden() (which
    // calls us).
    if (auto* view = GetApplicationWindowHostView())
      view->Hide();

    if (!ShowingInterstitialPage())
      SetVisibilityForChildViews(false);

    //SendPageMessage(new PageMsg_WasHidden(MSG_ROUTING_NONE));
    if (auto* window = GetApplicationWindowHost()) {
      window->PageWasHidden();
    }

  }

  SetVisibility(Visibility::HIDDEN);
}

void ApplicationContents::WasOccluded() {
  // if (!IsBeingCaptured()) {
  //   for (ApplicationWindowHostView* view : GetApplicationWindowHostViewsInTree())
  //     view->WasOccluded();
  // }
  SetVisibility(Visibility::OCCLUDED);
}

Visibility ApplicationContents::GetVisibility() const {
  return visibility_;
}

bool ApplicationContents::NeedToFireBeforeUnload() {
  return WillNotifyDisconnection() && !ShowingInterstitialPage();// &&
         //!GetApplicationWindowHost()->SuddenTerminationAllowed();
}

void ApplicationContents::DidChangeLoadProgress() {
  double load_progress = application_window_host_->load_progress();

  // The delegate is notified immediately for the first and last updates. Also,
  // since the message loop may be pretty busy when a page is loaded, it might
  // not execute a posted task in a timely manner so the progress report is sent
  // immediately if enough time has passed.
  base::TimeDelta min_delay =
      base::TimeDelta::FromMilliseconds(kMinimumDelayBetweenLoadingUpdatesMS);
  bool delay_elapsed = loading_last_progress_update_.is_null() ||
      base::TimeTicks::Now() - loading_last_progress_update_ > min_delay;

  if (load_progress == 0.0 || load_progress == 1.0 || delay_elapsed) {
    // If there is a pending task to send progress, it is now obsolete.
    loading_weak_factory_.InvalidateWeakPtrs();

    // Notify the load progress change.
    SendChangeLoadProgress();

    // Clean-up the states if needed.
    if (load_progress == 1.0)
      ResetLoadProgressState();
    return;
  }

  if (loading_weak_factory_.HasWeakPtrs())
    return;

  HostThread::PostDelayedTask(
      HostThread::UI,
      FROM_HERE,
      base::BindOnce(&ApplicationContents::SendChangeLoadProgress,
                     loading_weak_factory_.GetWeakPtr()),
      min_delay);
}

void ApplicationContents::DispatchBeforeUnload() {
  ////DLOG(INFO) << "ApplicationContents::DispatchBeforeUnload";
  //bool for_cross_site_transition = false;
  //GetMainFrame()->DispatchBeforeUnload(for_cross_site_transition, false);
  application_window_host_->DispatchBeforeUnload(false, false); 
}

void ApplicationContents::DidChangeVisibleSecurityState() {
  // burp burp: we dont need this 

  //if (delegate_) {
  //  delegate_->VisibleSecurityStateChanged(this);
  //  for (auto& observer : observers_)
  //    observer.DidChangeVisibleSecurityState();
  //}
}

void ApplicationContents::NotifyPreferencesChanged() {
  // burp burp
}

void ApplicationContents::Stop() {
  // burp burp
}

void ApplicationContents::FreezePage() {
  // burp burp
}

ApplicationContents* ApplicationContents::Clone() {
  return nullptr;
}

RouteController* ApplicationContents::GetRouteController() {
  return url_controller_.get();
}

NavigationController* ApplicationContents::GetNavigationController() {
  return navigation_controller_.get();
}

void ApplicationContents::Undo() {
  // burp burp 
}

void ApplicationContents::Redo() {
  // burp burp
}

void ApplicationContents::Cut() {
  // burp burp
}

void ApplicationContents::Copy() {
  // burp burp
}

void ApplicationContents::CopyToFindPboard() {
  // burp burp
}

void ApplicationContents::Paste() {
  // burp burp
}

void ApplicationContents::PasteAndMatchStyle() {
  // burp burp
}

void ApplicationContents::Delete() {
  // burp burp
}

void ApplicationContents::SelectAll() {
  // burp burp
}

void ApplicationContents::CollapseSelection() {
  // burp burp
}

void ApplicationContents::Replace(const base::string16& word) {
  // burp burp
}

void ApplicationContents::ReplaceMisspelling(const base::string16& word) {
  // burp burp
}

void ApplicationContents::NotifyContextMenuClosed(
    const common::CustomContextMenuContext& context) {
  // burp burp
}

void ApplicationContents::ReloadLoFiImages() {
  // burp burp
}

void ApplicationContents::ExecuteCustomContextMenuCommand(
    int action,
    const common::CustomContextMenuContext& context) {
  // burp burp
}

gfx::NativeView ApplicationContents::GetNativeView() {
  return view_->GetNativeView();
}

gfx::NativeView ApplicationContents::GetContentNativeView() {
  return view_->GetContentNativeView();
}

gfx::NativeWindow ApplicationContents::GetTopLevelNativeWindow() {
  return view_->GetTopLevelNativeWindow();
}

gfx::Rect ApplicationContents::GetContainerBounds() {
  gfx::Rect rv;
  view_->GetContainerBounds(&rv);
  return rv;
}

gfx::Rect ApplicationContents::GetViewBounds() {
  return view_->GetViewBounds();
}

common::DropData* ApplicationContents::GetDropData() {
  return view_->GetDropData();
}

void ApplicationContents::Focus() {
  view_->Focus();
}

void ApplicationContents::SetInitialFocus() {
  view_->SetInitialFocus();
}

void ApplicationContents::StoreFocus() {
  view_->StoreFocus();
}

void ApplicationContents::RestoreFocus() {
  view_->RestoreFocus();
}

void ApplicationContents::FocusThroughWindowTraversal(bool reverse) {
  view_->FocusThroughWindowTraversal(reverse);
}

bool ApplicationContents::ShowingInterstitialPage() const {
  return interstitial_page_ != nullptr;
}

InterstitialPageImpl* ApplicationContents::GetInterstitialPage() const {
  return interstitial_page_;
}


bool ApplicationContents::WillNotifyDisconnection() const {
  return notify_disconnection_;
}


common::RendererPreferences* ApplicationContents::GetMutableRendererPrefs() {
  return &renderer_preferences_;
}

void ApplicationContents::Close() {
  if (auto* window = GetApplicationWindowHost()) {
    Close(window);
  }
}

void ApplicationContents::CloseNow() {
  if (auto* window = GetApplicationWindowHost()) {
    CloseNowImpl(window);
  }
}

void ApplicationContents::SystemDragEnded(ApplicationWindowHost* source_awh) {
  if (source_awh) {
    source_awh->DragSourceSystemDragEnded();
  }
}

void ApplicationContents::SetClosedByUserGesture(bool value) {
  closed_by_user_gesture_ = value;
}

bool ApplicationContents::GetClosedByUserGesture() const {
  return closed_by_user_gesture_;
}

int ApplicationContents::GetMinimumZoomPercent() const {
  return minimum_zoom_percent_;
}


int ApplicationContents::GetMaximumZoomPercent() const {
  return maximum_zoom_percent_;
}

void ApplicationContents::SetPageScale(float page_scale_factor) {
  if (auto* window = GetApplicationWindowHost()) {
    window->SetPageScale(page_scale_factor);
  }
}

gfx::Size ApplicationContents::GetPreferredSize() const {
  return IsBeingCaptured() ? preferred_size_for_capture_ : preferred_size_;
}


bool ApplicationContents::GotResponseToLockMouseRequest(bool allowed) {
  if (mouse_lock_widget_) {
    if (mouse_lock_widget_->delegate()->GetAsApplicationContents() != this) {
      return mouse_lock_widget_->delegate()
          ->GetAsApplicationContents()
          ->GotResponseToLockMouseRequest(allowed);
    }

    if (mouse_lock_widget_->GotResponseToLockMouseRequest(allowed))
      return true;
  }

  return false;
}

ApplicationContents* ApplicationContents::GetAsApplicationContents() {
  return this;
}

bool ApplicationContents::GotResponseToKeyboardLockRequest(bool allowed) {
  if (!keyboard_lock_widget_)
    return false;

  if (keyboard_lock_widget_->delegate()->GetAsApplicationContents() != this) {
    NOTREACHED();
    return false;
  }

  // KeyboardLock is only supported when called by the top-level browsing
  // context and is not supported in embedded content scenarios.
  //if (GetOuterApplicationContents())
  //  return false;

  keyboard_lock_widget_->GotResponseToKeyboardLockRequest(allowed);
  return true;
}


bool ApplicationContents::WasRecentlyAudible() {
  return audio_stream_monitor_->WasRecentlyAudible();
}


bool ApplicationContents::WasEverAudible() {
  return was_ever_audible_;
}


//bool ApplicationContents::IsFullscreenForCurrentTab() const {  
//}


void ApplicationContents::ExitFullscreen(bool will_cause_resize) {
  if (auto* window = GetApplicationWindowHost()) {
    window->RejectMouseLockOrUnlockIfNecessary();
    ExitFullscreenMode(will_cause_resize);
  }
}


void ApplicationContents::ResumeLoadingCreatedApplicationContents() {
  if (delayed_open_url_.get()) {
  //if (delayed_open_url_params_.get()) {
    OpenURL(*delayed_open_url_.get());//*delayed_open_url_params_.get());
    delayed_open_url_.reset(nullptr);
    return;
  }

  // Resume blocked requests for both the RenderViewHost and RenderFrameHost.
  // TODO(brettw): It seems bogus to reach into here and initialize the host.
  if (is_resume_pending_) {
    is_resume_pending_ = false;
    if (auto* window = GetApplicationWindowHost()) {
      window->Init();
    }
    //GetMainFrame()->Init();
  }
}


void ApplicationContents::SetIsOverlayContent(bool is_overlay_content) {
  is_overlay_content_ = is_overlay_content;
}


bool ApplicationContents::IsShowingContextMenu() const {
  return showing_context_menu_;
}

void ApplicationContents::SetShowingContextMenu(bool showing) {
  DCHECK_NE(showing_context_menu_, showing);
  showing_context_menu_ = showing;

  if (auto* view = GetApplicationWindowHostView()) {
    // Notify the main frame's RWHV to run the platform-specific code, if any.
    view->SetShowingContextMenu(showing);
  }
}

void ApplicationContents::PausePageScheduledTasks(bool paused) {
  if (auto* window = GetApplicationWindowHost()) {
    window->PausePageScheduledTasks(paused);
  }
}

#if defined(OS_ANDROID)
base::android::ScopedJavaLocalRef<jobject> ApplicationContents::GetJavaApplicationContents() {
  
}


virtual ApplicationContentsAndroid* ApplicationContents::GetApplicationContentsAndroid() {
  
}


service_manager::InterfaceProvider* ApplicationContents::GetJavaInterfaces() {
  
}


#elif defined(OS_MACOSX)
void ApplicationContents::SetAllowOtherViews(bool allow) {
  
}


bool ApplicationContents::GetAllowOtherViews() {
  
}


bool ApplicationContents::CompletedFirstVisuallyNonEmptyPaint() const {
  
}
#endif

ApplicationContents* ApplicationContents::OpenURL(const GURL& url) {//const OpenURLParams& params) {
  return nullptr;
}

void ApplicationContents::EnterFullscreenMode() {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));
  // This method is being called to enter renderer-initiated fullscreen mode.
  // Make sure any existing fullscreen widget is shut down first.
  ApplicationWindowHostView* const window_view = GetFullscreenApplicationWindowHostView();
  if (window_view && window_view->GetApplicationWindowHost()) {
    window_view->GetApplicationWindowHost()->ShutdownAndDestroyWindow(true);
  }

  if (delegate_) {
    delegate_->EnterFullscreenMode(this);//ForTab(this, origin);

    if (keyboard_lock_widget_)
      delegate_->RequestKeyboardLock(this, esc_key_locked_);
  }

  for (const auto& observer : observers_) {
    if (observer)
      observer->DidToggleFullscreenMode(IsFullscreen(), false);
  }
}

void ApplicationContents::ExitFullscreenMode(bool will_cause_resize) {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));
  // This method is being called to leave renderer-initiated fullscreen mode.
  // Make sure any existing fullscreen widget is shut down first.
  ApplicationWindowHostView* const window_view = GetFullscreenApplicationWindowHostView();
  if (window_view && window_view->GetApplicationWindowHost()) {
    window_view->GetApplicationWindowHost()->ShutdownAndDestroyWindow(true);
  }

#if defined(OS_ANDROID)
  ContentVideoView* video_view = ContentVideoView::GetInstance();
  if (video_view != NULL)
    video_view->ExitFullscreen();
#endif

  if (delegate_) {
    delegate_->ExitFullscreenMode(this);

    if (keyboard_lock_widget_)
      delegate_->CancelKeyboardLockRequest(this);
  }

  // The fullscreen state is communicated to the renderer through a resize
  // message. If the change in fullscreen state doesn't cause a view resize
  // then we must ensure web contents exit the fullscreen state by explicitly
  // sending a resize message. This is required for the situation of the browser
  // moving the view into a "browser fullscreen" state and then the contents
  // entering "tab fullscreen". Exiting the contents "tab fullscreen" then won't
  // have the side effect of the view resizing, hence the explicit call here is
  // required.
  if (!will_cause_resize) {
    if (ApplicationWindowHostView* awhv = GetApplicationWindowHostView()) {
        if (ApplicationWindowHost* application_window_host = awhv->GetApplicationWindowHost())
          application_window_host->SynchronizeVisualProperties();
    }
  }

  for (const auto& observer : observers_) {
    if (observer) {
      observer->DidToggleFullscreenMode(IsFullscreen(), will_cause_resize);
    }
  }
}


void ApplicationContents::CreateNewWindow(
    ApplicationWindowHost* opener,
    Domain* parent,
    Application* application,
    int32_t application_window_route_id,
    bool initially_hidden,
    bool application_initiated,  
    const common::mojom::CreateNewWindowParams& params) {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));
  ////DLOG(INFO) << "ApplicationContents::CreateNewWindow (" << this <<"): opener(ApplicationWindowHost) -> " << opener;
  int application_process_id = opener ? opener->GetProcess()->GetID() : MSG_ROUTING_NONE;
  // Create the new web contents. This will automatically create the new
  // ApplicationContentsView. In the future, we may want to create the view separately.
  CreateParams create_params;
  create_params.routing_id = application_window_route_id;
  create_params.opener_application_process_id = application_process_id;
  //if (params.disposition == WindowOpenDisposition::NEW_BACKGROUND_TAB)
  create_params.initially_hidden = initially_hidden;
  create_params.application_initiated_creation = application_initiated;
  ////DLOG(INFO) << "ApplicationContents::CreateNewWindow: view_->GetNativeView() is create_params.context for ApplicationWindowHostView";
  create_params.context = view_->GetNativeView();
  create_params.initial_size = GetContainerBounds().size();
  create_params.application = application;
  create_params.parent = parent;

  ApplicationContents* new_contents = ApplicationContents::Create(create_params);

  // Save the window for later if we're not suppressing the opener (since it
  // will be shown immediately).
  
  if (delegate_) {
    delegate_->ApplicationContentsCreated(this, application_process_id,
                                          opener->GetRoutingID(), params.window_name,
                                          params.target_url, new_contents);
  }

  if (opener) {
    for (const auto& observer : observers_) {
      if (observer) {
        observer->DidOpenRequestedURL(new_contents, 
                                      opener, 
                                      params.target_url,
                                      params.disposition,
                                      ui::PAGE_TRANSITION_LINK,
                                      false,  // started_from_context_menu
                                      true);  // renderer_initiated
      }
    }
  }

  // Any new ApplicationContents opened while this ApplicationContents is in fullscreen can be
  // used to confuse the user, so drop fullscreen.
  if (IsFullscreen())
    ExitFullscreen(true);

  if (params.opener_suppressed) {
    // When the opener is suppressed, the original renderer cannot access the
    // new window.  As a result, we need to show and navigate the window here.
    bool was_blocked = false;
    if (delegate_) {
      gfx::Rect initial_rect;
      base::WeakPtr<ApplicationContents> weak_new_contents =
          new_contents->weak_factory_.GetWeakPtr();

      delegate_->AddNewContents(
          application_->name(), this, new_contents, params.disposition, initial_rect,
          params.user_gesture, &was_blocked);

      if (!weak_new_contents)
        return;  // The delegate deleted |new_contents| during AddNewContents().
    }
    if (!was_blocked) {
      //OpenURLParams open_params(params.target_url, params.referrer,
      //                          WindowOpenDisposition::CURRENT_TAB,
      //                          ui::PAGE_TRANSITION_LINK,
      //                          true /* is_renderer_initiated */);
      //open_params.user_gesture = params.user_gesture;

      if (delegate_ &&
          !delegate_->ShouldResumeRequestsForCreatedWindow()) {
        // We are in asynchronous add new contents path, delay opening url
        new_contents->delayed_open_url_.reset(
            new GURL(params.target_url));
      } else {
        new_contents->OpenURL(params.target_url);//open_params);
      }
    }
  }
}

void ApplicationContents::ShowCreatedWindow(
  Application* application,
  int process_id,
  int main_frame_widget_route_id,
  WindowOpenDisposition disposition,
  const gfx::Rect& initial_rect,
  bool user_gesture) {

  ApplicationContents* popup =
      GetCreatedContents(process_id, main_frame_widget_route_id);
  if (popup) {
    ApplicationContentsDelegate* delegate = GetDelegate();
    popup->is_resume_pending_ = true;
    if (!delegate || delegate->ShouldResumeRequestsForCreatedWindow())
      popup->ResumeLoadingCreatedApplicationContents();

    if (delegate) {
      base::WeakPtr<ApplicationContents> weak_popup =
          popup->weak_factory_.GetWeakPtr();
      delegate->AddNewContents(application_->name(), this, popup, disposition, initial_rect,
                               user_gesture, nullptr);
      if (!weak_popup)
        return;  // The delegate deleted |popup| during AddNewContents().
    }

    //ApplicationWindowHost* awh = popup->GetApplicationWindowHost();//GetMainFrame()->GetApplicationWindowHost();
    //awh->Send(new ViewMsg_Move_ACK(awh->GetRoutingID()));
    if (auto* window = GetApplicationWindowHost()) {
      window->MoveAck();
    }
  }
}

ApplicationWindowHostDelegateView* ApplicationContents::GetDelegateView() {
  return application_window_host_delegate_view_;
}

Domain* ApplicationContents::GetDomain() const {
  return parent_;
}

Application* ApplicationContents::GetApplication() const {
  return application_;
}

bool ApplicationContents::OnMessageReceived(
  ApplicationWindowHost* app_view_host,
  const IPC::Message& message) {
  // burp burp
  return false;
}

void ApplicationContents::ApplicationWindowReady(ApplicationWindowHost* application_window_host) {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));
  // if (application_window_host != ApplicationWindowHost()) {
  //   // Don't notify the world, since this came from a renderer in the
  //   // background.
  //   return;
  // }

  //ApplicationWindowHostView* awhv = GetApplicationWindowHostView();
  //if (awhv)
  //  awhv->SetMainFrameAXTreeID(GetMainFrame()->GetAXTreeID());

  notify_disconnection_ = true;

  bool was_crashed = IsCrashed();
  SetIsCrashed(base::TERMINATION_STATUS_STILL_RUNNING, 0);

  // Restore the focus to the tab (otherwise the focus will be on the top
  // window).
  //if (was_crashed && !FocusLocationBarByDefault() &&
  //    (!delegate_ || delegate_->ShouldFocusPageAfterCrash())) {
  if (was_crashed) {  
    view_->Focus();
  }

  for (const auto& observer : observers_) {
    if (observer)
      observer->ApplicationWindowReady();
  }
}


void ApplicationContents::ApplicationWindowTerminated(
  ApplicationWindowHost* application_window_host,
  base::TerminationStatus status,
  int error_code) {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));
  //DLOG(INFO) << "ApplicationContents::ApplicationWindowTerminated";
  is_being_destroyed_ = true;
  //if (rvh != GetRenderViewHost()) {
  //  // The pending page's RenderViewHost is gone.
  //  return;
  //}

  // Ensure fullscreen mode is exited in the |delegate_| since a crashed
  // renderer may not have made a clean exit.
  if (IsFullscreen())
    ExitFullscreenMode(false);

  // Cancel any visible dialogs so they are not left dangling over the sad tab.
  //CancelActiveAndPendingDialogs();

  audio_stream_monitor_->ApplicationProcessGone(application_window_host->GetProcess()->GetID());

  // Reset the loading progress. TODO(avi): What does it mean to have a
  // "renderer crash" when there is more than one renderer process serving a
  // webpage? Once this function is called at a more granular frame level, we
  // probably will need to more granularly reset the state here.
  ResetLoadProgressState();
  NotifyDisconnected();
  SetIsCrashed(status, error_code);

  // NOTE: this was moved out of the destructor
  //std::vector<base::WeakPtr<ApplicationContentsObserver>> observers = observers_;
  for (const auto& observer : observers_) {
    if (observer) {
      observer->ApplicationWindowDeleted(application_window_host);//(root->current_host());
    }
  }

  for (const auto& observer : observers_) {
    if (observer)
      observer->ApplicationProcessGone(GetCrashedStatus());
  }
}

void ApplicationContents::ApplicationWindowCreated(ApplicationWindowHost* application_window_host) {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));
  // from RenderWidgetCreated: 
  created_windows_.insert(application_window_host);

  // from RenderViewCreated: 
  if (delegate_)
    view_->SetOverscrollControllerEnabled(CanOverscrollContent());

  NotificationService::current()->Notify(
      NOTIFICATION_WEB_CONTENTS_RENDER_VIEW_HOST_CREATED,
      Source<ApplicationContents>(this),
      Details<ApplicationWindowHost>(application_window_host));

  view_->ApplicationWindowCreated(application_window_host);

  for (const auto& observer : observers_) {
    if (observer)
      observer->ApplicationWindowCreated(application_window_host);
  }
}

void ApplicationContents::ApplicationWindowDeleted(ApplicationWindowHost* application_window_host) {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));
  // from RenderWidgetDeleted
  created_windows_.erase(application_window_host);

  //if (is_being_destroyed_)
  //  return;

  if (application_window_host &&
      application_window_host->GetRoutingID() == fullscreen_widget_routing_id_ &&
      application_window_host->GetProcess()->GetID() ==
          fullscreen_widget_process_id_) {
    if (delegate_ && delegate_->EmbedsFullscreenWindow())
      delegate_->ExitFullscreenMode(this);
    for (const auto& observer : observers_) {
      if (observer)
        observer->DidDestroyFullscreenWindow();
    }
    fullscreen_widget_process_id_ = common::ChildProcessHost::kInvalidUniqueID;
    fullscreen_widget_routing_id_ = MSG_ROUTING_NONE;
    if (fullscreen_widget_had_focus_at_shutdown_)
      view_->RestoreFocus();
  }

  if (application_window_host == mouse_lock_widget_)
    LostMouseLock(mouse_lock_widget_);

  CancelKeyboardLock(keyboard_lock_widget_);

  // from RenderViewDeleted

  for (const auto& observer : observers_) {
    if (observer)
      observer->ApplicationWindowDeleted(application_window_host);
  }
}


void ApplicationContents::UpdateTargetURL(
  ApplicationWindowHost* application_window_host,
  const GURL& url) {

  if (fullscreen_widget_routing_id_ != MSG_ROUTING_NONE) {
    // If we're in flash fullscreen (i.e. Pepper plugin fullscreen) only update
    // the url if it's from the fullscreen renderer.
    ApplicationWindowHostView* fs = GetFullscreenApplicationWindowHostView();
    if (fs && fs->GetApplicationWindowHost() != application_window_host)
      return;
  }

  // In case of racey updates from multiple RenderViewHosts, the last URL should
  // be shown - see also some discussion in https://crbug.com/807776.
  if (!url.is_valid() && application_window_host != view_that_set_last_target_url_)
    return;
  view_that_set_last_target_url_ = url.is_valid() ? application_window_host : nullptr;

  if (delegate_)
    delegate_->UpdateTargetURL(this, url);
}


void ApplicationContents::Close(ApplicationWindowHost* application_window_host) {
  is_waiting_for_close_ack_ = true;
  // send a Close message and launch a timer so we kill the app anyway if somehow its
  // not sending a close ack
  if (auto* window = GetApplicationWindowHost()) {
    window->SendCloseFromContents();
  }

  base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
    FROM_HERE,
    base::Bind(&ApplicationContents::CloseNowImpl, 
      loading_weak_factory_.GetWeakPtr(), 
      base::Unretained(application_window_host)),
    base::TimeDelta::FromMilliseconds(1000 * 5));
}

void ApplicationContents::CloseNowImpl(ApplicationWindowHost* application_window_host) {
  is_waiting_for_close_ack_ = false;
#if defined(OS_MACOSX)
  // The UI may be in an event-tracking loop, such as between the
  // mouse-down and mouse-up in text selection or a button click.
  // Defer the close until after tracking is complete, so that we
  // don't free objects out from under the UI.
  // TODO(shess): This could get more fine-grained.  For instance,
  // closing a tab in another window while selecting text in the
  // current window's Omnibox should be just fine.
  if (view_->IsEventTracking()) {
    view_->CloseTabAfterEventTracking();
    return;
  }
#endif

  // Ignore this if it comes from a RenderViewHost that we aren't showing.
  if (delegate_ && application_window_host == GetApplicationWindowHost()) {
    ////DLOG(INFO) << "ApplicationContents::Close: calling delegate_->CloseContents()";
    delegate_->CloseContents(this);
  }
}

void ApplicationContents::OnCloseAckReceived(ApplicationWindowHost* application_window_host) {
  loading_weak_factory_.InvalidateWeakPtrs();
  // use this flag as it may have entered in CloseImpl from the timeout callback
  if (is_waiting_for_close_ack_) {
    CloseNowImpl(application_window_host);
  }
}

void ApplicationContents::RequestMove(const gfx::Rect& new_bounds) {
  if (delegate_ && delegate_->IsPopupOrPanel(this))
    delegate_->MoveContents(this, new_bounds);
}


void ApplicationContents::DocumentAvailableInMainFrame(ApplicationWindowHost* application_window_host) {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));
  for (const auto& observer : observers_) {
    if (observer) {
      observer->DocumentAvailableInMainFrame();
    }
  }
}

void ApplicationContents::RouteCloseEvent(ApplicationWindowHost* application_window_host) {
  //if (application_window_host->GetSiteInstance()->IsRelatedSiteInstance(GetSiteInstance()))
    ClosePage();
}

common::RendererPreferences ApplicationContents::GetRendererPrefs() const {
  //DLOG(INFO) << "ApplicationContents::GetRendererPrefs";
  return renderer_preferences_;
}

void ApplicationContents::DidReceiveInputEvent(
  ApplicationWindowHost* application_window_host,
  const blink::WebInputEvent::Type type) {
  // Ideally, this list would be based more off of
  // https://whatwg.org/C/interaction.html#triggered-by-user-activation.
  if (type != blink::WebInputEvent::kMouseDown &&
      type != blink::WebInputEvent::kGestureScrollBegin &&
      type != blink::WebInputEvent::kTouchStart &&
      type != blink::WebInputEvent::kRawKeyDown)
    return;

  // Ignore unless the widget is currently in the frame tree.
  //if (!HasMatchingWidgetHost(&frame_tree_, application_window_host))
  //  return;

  if (type != blink::WebInputEvent::kGestureScrollBegin)
    last_interactive_input_event_time_ = ui::EventTimeForNow();

  OnUserInteraction(type);
}


void ApplicationContents::OnIgnoredUIEvent() {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));
  for (const auto& observer : observers_) {
    if (observer)
      observer->DidGetIgnoredUIEvent();
  }
}


void ApplicationContents::Activate() {
  if (delegate_)
    delegate_->ActivateContents(this);
}

void ApplicationContents::UpdatePreferredSize(const gfx::Size& pref_size) {
  const gfx::Size old_size = GetPreferredSize();
  preferred_size_ = pref_size;
  OnPreferredSizeChanged(old_size);
}

void ApplicationContents::CreateNewWindow(
  int32_t application_process_id,
  int32_t route_id,
  blink::WebPopupType popup_type) {

  CreateNewWindowImpl(application_process_id, route_id, false, blink::kWebPopupTypeNone);
}

void ApplicationContents::CreateNewFullscreenWindow(
  int32_t application_process_id,
  int32_t route_id) {
  
  CreateNewWindowImpl(application_process_id, route_id, true, blink::kWebPopupTypeNone);
}

void ApplicationContents::CreateNewWindowImpl(
  int32_t application_process_id,
  int32_t route_id,
  bool is_fullscreen,
  blink::WebPopupType popup_type) {
  
  ApplicationProcessHost* process = ApplicationProcessHost::FromID(application_process_id);
  // A message to create a new widget can only come from an active process for
  // this ApplicationContentsImpl instance. If any other process sends the request,
  // it is invalid and the process must be terminated.
  //if (!HasMatchingProcess(&frame_tree_, render_process_id)) {
  //  ReceivedBadMessage(process, bad_message::WCI_NEW_WIDGET_PROCESS_MISMATCH);
  //  return;
  //}

  ApplicationWindowHost* window_host = new ApplicationWindowHost(
      this, application_, process, route_id, IsHidden()); //std::move(widget), IsHidden());

  ApplicationWindowHostView* window_view = view_->CreateViewForPopupWindow(window_host);
  if (!window_view)
    return;

  if (!is_fullscreen) {
    // Popups should not get activated.
    window_view->SetPopupType(popup_type);
  }
  // Save the created widget associated with the route so we can show it later.
  pending_widget_views_[std::make_pair(application_process_id, route_id)] =
      window_view;
}

void ApplicationContents::ShowCreatedWindow(
  int process_id,
  int route_id,
  const gfx::Rect& initial_rect) {
  ShowCreatedWindowImpl(process_id, route_id, false, initial_rect);
}

void ApplicationContents::ShowCreatedFullscreenWindow(int process_id, int route_id) {
  ShowCreatedWindowImpl(process_id, route_id, true, gfx::Rect());
}

void ApplicationContents::ShowCreatedWindowImpl(
  int process_id,
  int route_id,
  bool is_fullscreen,
  const gfx::Rect& initial_rect) {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));
  ApplicationWindowHostView* widget_host_view = GetCreatedWindow(process_id, route_id);
      //static_cast<ApplicationWindowHostView*>(
      //    GetCreatedWindow(process_id, route_id));
  if (!widget_host_view)
    return;

  //ApplicationWindowHostView* view = nullptr;
  //if (GetOuterApplicationContents()) {
  //  view = GetOuterApplicationContents()->GetApplicationWindowHostView();
  //} else {
  //  view = GetApplicationWindowHostView();
  //}

  ApplicationWindowHostView* view = GetApplicationWindowHostView();

  if (is_fullscreen) {
    DCHECK_EQ(MSG_ROUTING_NONE, fullscreen_widget_routing_id_);
    view_->StoreFocus();
    fullscreen_widget_process_id_ =
        widget_host_view->GetApplicationWindowHost()->GetProcess()->GetID();
    fullscreen_widget_routing_id_ = route_id;
    if (delegate_ && delegate_->EmbedsFullscreenWindow()) {
      widget_host_view->InitAsChild(GetApplicationWindowHostView()->GetNativeView());
      delegate_->EnterFullscreenMode(this);
    } else {
      widget_host_view->InitAsFullscreen(view);
    }
    for (const auto& observer : observers_) {
      if (observer)
        observer->DidShowFullscreenWindow();
    }
    if (!widget_host_view->HasFocus())
      widget_host_view->Focus();
  } else {
    widget_host_view->InitAsPopup(view, initial_rect);
  }

  ApplicationWindowHost* application_window_host = widget_host_view->host();
  application_window_host->Init();
  // Only allow privileged mouse lock for fullscreen render widget, which is
  // used to implement Pepper Flash fullscreen.
  application_window_host->set_allow_privileged_mouse_lock(is_fullscreen);
}

void ApplicationContents::ApplicationWindowGotFocus(ApplicationWindowHost* application_window_host) {
  if (delegate_ && application_window_host && delegate_->EmbedsFullscreenWindow() &&
      application_window_host->GetView() == GetFullscreenApplicationWindowHostView()) {
    NotifyApplicationContentsFocused(application_window_host);
  }
}

void ApplicationContents::ApplicationWindowLostFocus(ApplicationWindowHost* application_window_host) {
  if (delegate_ && application_window_host && delegate_->EmbedsFullscreenWindow() &&
      application_window_host->GetView() == GetFullscreenApplicationWindowHostView()) {
    NotifyApplicationContentsLostFocus(application_window_host);
  }
}

void ApplicationContents::ApplicationWindowWasResized(
  ApplicationWindowHost* application_window_host,
  const common::ScreenInfo& screen_info,
  bool width_changed) {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));
  //RenderFrameHostImpl* rfh = GetMainFrame();
  //if (!rfh || application_window_host != rfh->GetApplicationWindowHost())
  //  return;

  //SendPageMessage(new PageMsg_UpdateScreenInfo(MSG_ROUTING_NONE, screen_info));
  if (auto* window = GetApplicationWindowHost()) {
    window->UpdateScreenInfo(screen_info);
  }
  
  for (const auto& observer : observers_) {
    if (observer)
      observer->WindowWasResized(width_changed);
  }
}
void ApplicationContents::ResizeDueToAutoResize(
    ApplicationWindowHost* application_window_host,
    const gfx::Size& new_size,
    const viz::LocalSurfaceId& local_surface_id) {

}

gfx::Size ApplicationContents::GetAutoResizeSize() {
  return auto_resize_size_;
}

void ApplicationContents::ResetAutoResizeSize() {
  auto_resize_size_ = gfx::Size();
}

KeyboardEventProcessingResult ApplicationContents::PreHandleKeyboardEvent(
    const NativeWebKeyboardEvent& event) {
  return delegate_ ? delegate_->PreHandleKeyboardEvent(this, event)
                   : KeyboardEventProcessingResult::NOT_HANDLED;
}

void ApplicationContents::HandleKeyboardEvent(const NativeWebKeyboardEvent& event) {
  if (delegate_)
    delegate_->HandleKeyboardEvent(this, event);
}

bool ApplicationContents::HandleWheelEvent(const blink::WebMouseWheelEvent& event) {
#if !defined(OS_MACOSX)
  // On platforms other than Mac, control+mousewheel may change zoom. On Mac,
  // this isn't done for two reasons:
  //   -the OS already has a gesture to do this through pinch-zoom
  //   -if a user starts an inertial scroll, let's go, and presses control
  //      (i.e. control+tab) then the OS's buffered scroll events will come in
  //      with control key set which isn't what the user wants
  if (delegate_ && event.wheel_ticks_y &&
      !ui::WebInputEventTraits::CanCauseScroll(event)) {
    // Count only integer cumulative scrolls as zoom events; this handles
    // smooth scroll and regular scroll device behavior.
    zoom_scroll_remainder_ += event.wheel_ticks_y;
    int whole_zoom_scroll_remainder_ = std::lround(zoom_scroll_remainder_);
    zoom_scroll_remainder_ -= whole_zoom_scroll_remainder_;
    if (whole_zoom_scroll_remainder_ != 0) {
      delegate_->ContentsZoomChange(whole_zoom_scroll_remainder_ > 0);
    }
    return true;
  }
#endif
  return false;
}

bool ApplicationContents::PreHandleGestureEvent(const blink::WebGestureEvent& event) {
  return delegate_ && delegate_->PreHandleGestureEvent(this, event);
}

void ApplicationContents::ExecuteEditCommand(
  const std::string& command,
  const base::Optional<base::string16>& value) {
  // burp burp
}

void ApplicationContents::MoveRangeSelectionExtent(const gfx::Point& extent) {
  // burp burp
}

void ApplicationContents::SelectRange(const gfx::Point& base, const gfx::Point& extent) {
  // burp burp
}

void ApplicationContents::MoveCaret(const gfx::Point& extent) {
  // burp burp
}

void ApplicationContents::AdjustSelectionByCharacterOffset(int start_adjust,
                                      int end_adjust,
                                      bool show_selection_menu) {
  // burp burp
}

ApplicationWindowHostInputEventRouter* ApplicationContents::GetInputEventRouter() {
  if (!awh_input_event_router_.get())// && !is_being_destroyed_)
    awh_input_event_router_.reset(new ApplicationWindowHostInputEventRouter);
  return awh_input_event_router_.get();
}

void ApplicationContents::ReplicatePageFocus(bool is_focused) {
  // burp burp
}

ApplicationWindowHost* ApplicationContents::GetFocusedApplicationWindowHost(
    ApplicationWindowHost* receiving_widget) {
  //if (receiving_widget != GetMainFrame()->GetApplicationWindowHost())
  if (receiving_widget != GetApplicationWindowHost())  
    return receiving_widget;

  ApplicationContents* focused_contents = GetFocusedApplicationContents();

  // If the focused ApplicationContents is showing an interstitial, return the
  // interstitial's widget.
  if (focused_contents && focused_contents->ShowingInterstitialPage()) {
    //return static_cast<RenderFrameHostImpl*>(
    //           focused_contents->interstitial_page_->GetMainFrame())
    //    ->GetApplicationWindowHost();
    return focused_contents->GetApplicationWindowHost();
  }

  // If the focused ApplicationContents is a guest ApplicationContents, then get the focused
  // frame in the embedder ApplicationContents instead.
  //FrameTreeNode* focused_frame = nullptr;
  //if (focused_contents->browser_plugin_guest_ &&
  //    !GuestMode::IsCrossProcessFrameGuest(focused_contents)) {
  //  focused_frame = frame_tree_.GetFocusedFrame();
  //} else {
  //  focused_frame = GetFocusedApplicationContents()->frame_tree_.GetFocusedFrame();
  //}

  //if (!focused_frame)
  if (!focused_contents)
   return receiving_widget;

  // The view may be null if a subframe's renderer process has crashed while
  // the subframe has focus.  Drop the event in that case.  Do not give
  // it to the main frame, so that the user doesn't unexpectedly type into the
  // wrong frame if a focused subframe renderer crashes while they type.
  ApplicationWindowHostView* view = focused_contents->GetApplicationWindowHost()->GetView();
  if (!view)
      return nullptr;

  return view->GetApplicationWindowHost();
}

ApplicationWindowHost* ApplicationContents::GetApplicationWindowHostWithPageFocus() {
  ApplicationContents* focused_application_contents = GetFocusedApplicationContents();
  return focused_application_contents->GetApplicationWindowHost();//GetMainFrame()->GetApplicationWindowHost();
}

ApplicationContents* ApplicationContents::GetFocusedApplicationContents() {
  // since we dont have a tree of this stuff we just return
  // ourselves for now
  return this;
}

void ApplicationContents::FocusOwningApplicationContents(
    ApplicationWindowHost* application_window_host) {
  // burp burp - makes not sense to us
}

void ApplicationContents::ApplicationUnresponsive(ApplicationWindowHost* application_window_host) {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));

  for (const auto& observer : observers_) {
    if (observer)
      observer->OnApplicationUnresponsive(application_window_host->GetProcess());
  }

  if (ShouldIgnoreUnresponsiveApplication())
    return;

  if (!application_window_host->application_initialized())
    return;

  if (delegate_)
    delegate_->ApplicationUnresponsive(this, application_window_host);
}

void ApplicationContents::ApplicationResponsive(ApplicationWindowHost* application_window_host) {
  if (delegate_)
    delegate_->ApplicationResponsive(this, application_window_host);
}

void ApplicationContents::RequestToLockMouse(
  ApplicationWindowHost* application_window_host,
  bool user_gesture,
  bool last_unlocked_by_target,
  bool privileged) {
  
  mouse_lock_widget_ = application_window_host;
  application_window_host->GotResponseToLockMouseRequest(true);
}

bool ApplicationContents::RequestKeyboardLock(
  ApplicationWindowHost* application_window_host,
  bool esc_key_locked) {

  esc_key_locked_ = esc_key_locked;
  keyboard_lock_widget_ = application_window_host;

  if (delegate_)
    delegate_->RequestKeyboardLock(this, esc_key_locked_);
  return true;
}

void ApplicationContents::CancelKeyboardLock(ApplicationWindowHost* application_window_host) {
  if (!keyboard_lock_widget_ || application_window_host != keyboard_lock_widget_)
    return;

  ApplicationWindowHost* old_keyboard_lock_widget = keyboard_lock_widget_;
  keyboard_lock_widget_ = nullptr;

  if (delegate_)
    delegate_->CancelKeyboardLockRequest(this);

  old_keyboard_lock_widget->CancelKeyboardLock();
}

ApplicationWindowHost* ApplicationContents::GetKeyboardLockWidget() {
  return keyboard_lock_widget_;
}

blink::WebDisplayMode ApplicationContents::GetDisplayMode(
    ApplicationWindowHost* application_window_host) const {
  return delegate_ ? delegate_->GetDisplayMode(this)
                   : blink::kWebDisplayModeBrowser;
}

void ApplicationContents::LostCapture(ApplicationWindowHost* application_window_host) {
  if (delegate_)
    delegate_->LostCapture();
}

void ApplicationContents::LostMouseLock(ApplicationWindowHost* application_window_host) {
  mouse_lock_widget_->SendLostMouseLock();

  if (delegate_)
    delegate_->LostMouseLock();
}

bool ApplicationContents::HasMouseLock(ApplicationWindowHost* application_window_host) {
  return mouse_lock_widget_ == application_window_host &&
         GetTopLevelApplicationWindowHostView()->IsMouseLocked();
}

ApplicationWindowHost* ApplicationContents::GetMouseLockWidget() {
  if (GetTopLevelApplicationWindowHostView()->IsMouseLocked() ||
      (GetFullscreenApplicationWindowHostView() &&
       GetFullscreenApplicationWindowHostView()->IsMouseLocked()))
    return mouse_lock_widget_;

  return nullptr;
}

void ApplicationContents::SendScreenRects() {
  SadTabHelper* sad_tab_helper =
          SadTabHelper::FromApplicationContents(this);
  if (sad_tab_helper && sad_tab_helper->sad_tab()) {
    return;
  }
  ApplicationWindowHostView* awhv = GetApplicationWindowHostView();
  if (awhv) {
    const gfx::Rect& bounds = awhv->GetBoundsInRootWindow();
    ////DLOG(INFO) << "sending UpdateWindowScreenRect with bounds: x: " << bounds.x() << " y: " << bounds.y() << " w: " << bounds.width() << " h: " << bounds.height();
    GetApplicationWindowHost()->UpdateWindowScreenRect(bounds);
  }
}

TextInputManager* ApplicationContents::GetTextInputManager() {
  if (!text_input_manager_)
    text_input_manager_.reset(new TextInputManager());

  return text_input_manager_.get();
}

bool ApplicationContents::OnUpdateDragCursor() {
  return false;
}

void ApplicationContents::FocusedNodeTouched(bool editable) {

}

void ApplicationContents::DidReceiveCompositorFrame() {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));

  for (const auto& observer : observers_) {
    if (observer)
      observer->DidReceiveCompositorFrame();
  }
}

bool ApplicationContents::IsShowingContextMenuOnPage() const {
  return showing_context_menu_;
}

void ApplicationContents::Observe(int type,
             const NotificationSource& source,
             const NotificationDetails& details) {
  switch (type) {
    case NOTIFICATION_RENDER_WIDGET_HOST_DESTROYED: {
      ApplicationWindowHost* host = Source<ApplicationWindowHost>(source).ptr();
      ApplicationWindowHostView* view = host->GetView();
      if (view == GetFullscreenApplicationWindowHostView()) {
        // We cannot just call view_->RestoreFocus() here.  On some platforms,
        // attempting to focus the currently-invisible ApplicationContentsView will be
        // flat-out ignored.  Therefore, this boolean is used to track whether
        // we will request focus after the fullscreen widget has been
        // destroyed.
        fullscreen_widget_had_focus_at_shutdown_ = (view && view->HasFocus());
      } else {
        for (auto i = pending_widget_views_.begin();
             i != pending_widget_views_.end(); ++i) {
          if (host->GetView() == i->second) {
            pending_widget_views_.erase(i);
            break;
          }
        }
      }
      break;
    }
    default:
      NOTREACHED();
  }
}

void ApplicationContents::AttachInterstitialPage(InterstitialPageImpl* interstitial_page) {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));

  DCHECK(!interstitial_page_ && interstitial_page);
  interstitial_page_ = interstitial_page;

  // Cancel any visible dialogs so that they don't interfere with the
  // interstitial.
  //CancelActiveAndPendingDialogs();

  for (const auto& observer : observers_) {
    if (observer)
      observer->DidAttachInterstitialPage();
  }

//#if defined(OS_ANDROID)
  // Update importance of the interstitial.
  // static_cast<RenderFrameHostImpl*>(interstitial_page_->GetMainFrame())
  //     ->GetApplicationWindowHost()
  //     ->SetImportance(GetMainFrame()->GetApplicationWindowHost()->importance());
//#endif

}

void ApplicationContents::MediaMutedStatusChanged(
  const ApplicationContentsObserver::MediaPlayerId& id,
  bool muted) {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));
  
  for (const auto& observer : observers_) {
    if (observer)
      observer->MediaMutedStatusChanged(id, muted);
  }
}

void ApplicationContents::DetachInterstitialPage(bool has_focus) {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));

  bool interstitial_pausing_throbber =
      ShowingInterstitialPage();// && interstitial_page_->pause_throbber();
  if (ShowingInterstitialPage())
    interstitial_page_ = nullptr;

  // Make sure that the main page's accessibility tree is no longer
  // suppressed.
  //RenderFrameHostImpl* rfh = GetMainFrame();
  //if (rfh) {
  //  BrowserAccessibilityManager* accessibility_manager =
  //      rfh->browser_accessibility_manager();
  //  if (accessibility_manager)
  //    accessibility_manager->set_hidden_by_interstitial_page(false);
  //}

  // If the focus was on the interstitial, let's keep it to the page.
  // (Note that in unit-tests the RVH may not have a view).
  //if (has_focus && GetRenderViewHost()->GetWidget()->GetView())
  //  GetRenderViewHost()->GetWidget()->GetView()->Focus();
  if (has_focus && GetApplicationWindowHost()->GetView())
    GetApplicationWindowHost()->GetView()->Focus();

  for (const auto& observer : observers_) {
    if (observer)
      observer->DidDetachInterstitialPage();
  }

  // Disconnect from outer ApplicationContents if necessary. This must happen after the
  // interstitial page is cleared above, since the call to
  // SetRWHViewForInnerContents below may loop over all the
  // ApplicationWindowHostViews in the tree (otherwise, including the now-deleted
  // view for the interstitial).
  //if (node_.OuterContentsFrameTreeNode()) {
  //  if (GetRenderManager()->GetProxyToOuterDelegate()) {
  //    DCHECK(static_cast<ApplicationWindowHostView*>(
  //               GetRenderManager()->current_frame_host()->GetView())
  //               ->IsApplicationWindowHostViewChildFrame());
  //    ApplicationWindowHostViewChildFrame* view =
  //        static_cast<ApplicationWindowHostViewChildFrame*>(
  //            GetRenderManager()->current_frame_host()->GetView());
  //    GetRenderManager()->SetRWHViewForInnerContents(view);
  //  }
  //}

  // Restart the throbber if needed now that the interstitial page is going
  // away.
  if (interstitial_pausing_throbber && IsLoading())//frame_tree_.IsLoading())
    LoadingStateChanged(true, true, nullptr);
}

void ApplicationContents::DidProceedOnInterstitial() {
   //DCHECK(!(ShowingInterstitialPage() && interstitial_page_->pause_throbber()));

  // Restart the throbber now that the interstitial page no longer pauses it.
  if (ShowingInterstitialPage() && IsLoading())//frame_tree_.IsLoading())
    LoadingStateChanged(true, true, nullptr);
}

void ApplicationContents::SetForceDisableOverscrollContent(bool force_disable) {
  force_disable_overscroll_content_ = force_disable;
  if (view_)
    view_->SetOverscrollControllerEnabled(CanOverscrollContent());
}

bool ApplicationContents::SetDeviceEmulationSize(const gfx::Size& new_size) {
  // burp burp.. do we really need this?
  return false;
}

void ApplicationContents::ClearDeviceEmulationSize() {
  // burp burp.. do we really need this?
}

void ApplicationContents::MediaStartedPlaying(
    const ApplicationContentsObserver::MediaPlayerInfo& media_info,
    const ApplicationContentsObserver::MediaPlayerId& id) {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));

  if (media_info.has_video)
    currently_playing_video_count_++;

  for (const auto& observer : observers_) {
    if (observer)
      observer->MediaStartedPlaying(media_info, id);
  }
}

void ApplicationContents::MediaStoppedPlaying(
    const ApplicationContentsObserver::MediaPlayerInfo& media_info,
    const ApplicationContentsObserver::MediaPlayerId& id,
    ApplicationContentsObserver::MediaStoppedReason reason) {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));

  if (media_info.has_video)
    currently_playing_video_count_--;

  for (const auto& observer : observers_) {
    if (observer)
      observer->MediaStoppedPlaying(media_info, id, reason);
  }
}

void ApplicationContents::MediaResized(const gfx::Size& size,
                  const ApplicationContentsObserver::MediaPlayerId& id) {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));
  cached_video_sizes_[id] = size;

  for (const auto& observer : observers_) {
    if (observer)
      observer->MediaResized(size, id);
  }
}

void ApplicationContents::MediaEffectivelyFullscreenChanged(bool is_fullscreen) {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));
  for (const auto& observer : observers_) {
    if (observer)
      observer->MediaEffectivelyFullscreenChanged(is_fullscreen);
  }
}

int ApplicationContents::GetCurrentlyPlayingVideoCount() {
  return currently_playing_video_count_;
}

base::Optional<gfx::Size> ApplicationContents::GetFullscreenVideoSize() {
  base::Optional<ApplicationContentsObserver::MediaPlayerId> id =
      media_application_contents_observer_->GetFullscreenVideoMediaPlayerId();
  if (id && cached_video_sizes_.count(id.value()))
    return base::Optional<gfx::Size>(cached_video_sizes_[id.value()]);
  return base::Optional<gfx::Size>();
}

bool ApplicationContents::IsFullscreen() const {
  return delegate_ ? delegate_->IsFullscreenOrPending(this) : false;
}

void ApplicationContents::UpdateApplicationContentsVisibility(Visibility visibility) {
  if (is_being_destroyed_) {
    return;
  }
  const bool occlusion_is_disabled = true;
      // !base::FeatureList::IsEnabled(features::kApplicationContentsOcclusion) ||
      // base::CommandLine::ForCurrentProcess()->HasSwitch(
      //     switches::kDisableBackgroundingOccludedWindowsForTesting);
  if (occlusion_is_disabled && visibility == Visibility::OCCLUDED)
    visibility = Visibility::VISIBLE;

  if (!did_first_set_visible_) {
    if (visibility == Visibility::VISIBLE) {
      // A ApplicationContents created with CreateParams::initially_hidden = false
      // starts with GetVisibility() == Visibility::VISIBLE even though it is
      // not really visible. Call WasShown() when it becomes visible for real as
      // the page load mechanism and some ApplicationContentsObserver rely on that.
      WasShown();
      did_first_set_visible_ = true;
    }

    // Trust the initial visibility of the ApplicationContents and do not switch it to
    // HIDDEN or OCCLUDED before it becomes VISIBLE for real. Doing so would
    // result in destroying resources that would immediately be recreated (e.g.
    // UpdateApplicationContents(HIDDEN) can be called when a ApplicationContents is added to a
    // hidden window that is about to be shown).

    return;
  }

  if (visibility == visibility_)
    return;

  if (visibility == Visibility::VISIBLE)
    WasShown();
  else if (visibility == Visibility::OCCLUDED)
    WasOccluded();
  else
    WasHidden();
}

void ApplicationContents::IncrementBluetoothConnectedDeviceCount() {
  // Trying to invalidate the tab state while being destroyed could result in a
  // use after free.
  if (IsBeingDestroyed()) {
    return;
  }
  // Notify for UI updates if the state changes.
  bluetooth_connected_device_count_++;
  if (bluetooth_connected_device_count_ == 1) {
    NotifyNavigationStateChanged(INVALIDATE_TYPE_TAB);
  }
}

void ApplicationContents::DecrementBluetoothConnectedDeviceCount() {
  if (IsBeingDestroyed()) {
    return;
  }
  // Notify for UI updates if the state changes.
  DCHECK_NE(bluetooth_connected_device_count_, 0u);
  bluetooth_connected_device_count_--;
  if (bluetooth_connected_device_count_ == 0) {
    NotifyNavigationStateChanged(INVALIDATE_TYPE_TAB);
  }
}

void ApplicationContents::SetHasPersistentVideo(bool has_persistent_video) {
  if (has_persistent_video_ == has_persistent_video)
    return;

  has_persistent_video_ = has_persistent_video;
  NotifyPreferencesChanged();
  media_application_contents_observer()->RequestPersistentVideo(has_persistent_video);
}

bool ApplicationContents::HasActiveEffectivelyFullscreenVideo() const {
  return media_application_contents_observer_->HasActiveEffectivelyFullscreenVideo();
}

bool ApplicationContents::IsPictureInPictureAllowedForFullscreenVideo() const {
   return media_application_contents_observer_->IsPictureInPictureAllowedForFullscreenVideo();
}

void ApplicationContents::AddObserver(base::WeakPtr<ApplicationContentsObserver> observer) {
  base::AutoLock lock(observers_lock_);
  observers_.push_back(std::move(observer));
}

void ApplicationContents::RemoveObserver(ApplicationContentsObserver* observer) {
  base::AutoLock lock(observers_lock_);
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    if (observer == it->get()) {
      observers_.erase(it);
      return;
    }
  }
}

void ApplicationContents::OnApplicationContentsDestroyed(ApplicationContents* application_contents) {
  RemoveDestructionObserver(application_contents);

  // Clear a pending contents that has been closed before being shown.
  for (auto iter = pending_contents_.begin(); iter != pending_contents_.end();
       ++iter) {
    if (iter->second != application_contents)
      continue;
    pending_contents_.erase(iter);
    return;
  }
  NOTREACHED();
}

void ApplicationContents::AddDestructionObserver(ApplicationContents* application_contents) {
  if (!ContainsKey(destruction_observers_, application_contents)) {
    destruction_observers_[application_contents] =
        std::make_unique<DestructionObserver>(this, application_contents);
  }
}

void ApplicationContents::RemoveDestructionObserver(ApplicationContents* application_contents) {
  destruction_observers_.erase(application_contents);
}

void ApplicationContents::OnUpdateZoomLimits(ApplicationWindowHost* source,
                        int minimum_percent,
                        int maximum_percent) {
  
}

void ApplicationContents::OnPageScaleFactorChanged(
  ApplicationWindowHost* source,
  float page_scale_factor) {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));

  #if !defined(OS_ANDROID)
  // While page scale factor is used on mobile, this PageScaleFactorIsOne logic
  // is only needed on desktop.
  bool is_one = page_scale_factor == 1.f;
  if (is_one != page_scale_factor_is_one_) {
    page_scale_factor_is_one_ = is_one;

    HostZoomMap* host_zoom_map = HostZoomMap::GetForApplicationContents(this);

    if (host_zoom_map) {
      host_zoom_map->SetPageScaleFactorIsOneForView(
          source->GetProcess()->GetID(), source->GetRoutingID(),
          page_scale_factor_is_one_);
    }
  }
#endif  // !defined(OS_ANDROID)

  for (const auto& observer : observers_) {
    if (observer)
      observer->OnPageScaleFactorChanged(page_scale_factor);
  }
}

void ApplicationContents::OnFirstVisuallyNonEmptyPaint(ApplicationWindowHost* source) {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));
  for (const auto& observer : observers_) {
    if (observer)
      observer->DidFirstVisuallyNonEmptyPaint();
  }

  did_first_visually_non_empty_paint_ = true;

  //if (theme_color_ != last_sent_theme_color_) {
    // Theme color should have updated by now if there was one.
  //  for (auto& observer : observers_)
  //    observer.DidChangeThemeColor(theme_color_);
  //  last_sent_theme_color_ = theme_color_;
 // }
}

void ApplicationContents::SetNotWaitingForResponse() {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));

  // i guess this should be burp burp, but idk
  if (waiting_for_response_ == false)
    return;

  waiting_for_response_ = false;
  if (delegate_)
    delegate_->LoadingStateChanged(this, false);//, is_load_to_different_document_);
  for (const auto& observer : observers_) {
    if (observer)
      observer->DidReceiveResponse();
  }
}

// void ApplicationContents::ShowCreatedWindow(
//   int process_id,
//   int route_id,
//   bool is_fullscreen,
//   const gfx::Rect& initial_rect) {
  
  
// }

ApplicationWindowHostView* ApplicationContents::GetCreatedWindow(int process_id, int route_id) {
  auto iter = pending_widget_views_.find(std::make_pair(process_id, route_id));
  if (iter == pending_widget_views_.end()) {
    DCHECK(false);
    return nullptr;
  }

  ApplicationWindowHostView* widget_host_view = iter->second;
  pending_widget_views_.erase(std::make_pair(process_id, route_id));

  ApplicationWindowHost* widget_host = widget_host_view->GetApplicationWindowHost();
  if (!widget_host->GetProcess()->HasConnection()) {
    // The view has gone away or the renderer crashed. Nothing to do.
    return nullptr;
  }

  return widget_host_view;
}

ApplicationContents* ApplicationContents::GetCreatedContents(
  int process_id,
  int main_frame_widget_route_id) {
  
  auto key = std::make_pair(process_id, main_frame_widget_route_id);
  auto iter = pending_contents_.find(key);

  // Certain systems can block the creation of new windows. If we didn't succeed
  // in creating one, just return NULL.
  if (iter == pending_contents_.end())
    return nullptr;

  ApplicationContents* new_contents = iter->second;
  pending_contents_.erase(key);
  RemoveDestructionObserver(new_contents);

  if (!new_contents->GetApplicationWindowHost()->GetProcess()->HasConnection() ||
      !new_contents->GetView()) {
    // TODO(nick): http://crbug.com/674318 -- Who deletes |new_contents|?
    return nullptr;
  }

  return new_contents;
}

void ApplicationContents::ResetLoadProgressState() {
  application_window_host_->ResetLoadProgress();
  loading_weak_factory_.InvalidateWeakPtrs();
  loading_last_progress_update_ = base::TimeTicks();
}

void ApplicationContents::SendChangeLoadProgress() {
  loading_last_progress_update_ = base::TimeTicks::Now();
  if (delegate_)
    delegate_->LoadProgressChanged(this, application_window_host_->load_progress());
}

void ApplicationContents::LoadingStateChanged(
  bool to_different_document,
  bool due_to_interstitial,
  LoadNotificationDetails* details) {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));
  // Do not send notifications about loading changes in the FrameTree while the
  // interstitial page is pausing the throbber.
  if (ShowingInterstitialPage() && interstitial_page_->pause_throbber() &&
      !due_to_interstitial) {
    return;
  }

  bool is_loading = IsLoading();

  if (!is_loading) {
    load_state_ = net::LoadStateWithParam(net::LOAD_STATE_IDLE,
                                          base::string16());
    load_state_host_.clear();
    upload_size_ = 0;
    upload_position_ = 0;
  }

  application_window_host_->SetIsLoading(is_loading);

  waiting_for_response_ = is_loading;
  //is_load_to_different_document_ = to_different_document;

  if (delegate_)
    delegate_->LoadingStateChanged(this, to_different_document);
  NotifyNavigationStateChanged(INVALIDATE_TYPE_LOAD);

  std::string url = (details ? details->url.possibly_invalid_spec() : "NULL");
  if (is_loading) {
    //TRACE_EVENT_ASYNC_BEGIN2("browser,navigation", "WebContentsImpl Loading",
    //                         this, "URL", url, "Main FrameTreeNode id",
    //                         GetFrameTree()->root()->frame_tree_node_id());
    for (const auto& observer : observers_) {
      if (observer)
        observer->DidStartLoading();
    }
  } else {
    //TRACE_EVENT_ASYNC_END1("browser,navigation", "WebContentsImpl Loading",
    //                       this, "URL", url);
    for (const auto& observer : observers_) {
      if (observer)
        observer->DidStopLoading();
    }
  }
}

bool ApplicationContents::CanOverscrollContent() const {
  // Disable overscroll when touch emulation is on. See crbug.com/369938.
  if (force_disable_overscroll_content_)
    return false;

  if (delegate_)
    return delegate_->CanOverscrollContent();

  return false;
}

void ApplicationContents::NotifyViewSwapped(ApplicationWindowHost* old_host, ApplicationWindowHost* new_host) {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));
  notify_disconnection_ = true;
  for (const auto& observer : observers_) {
    if (observer)
      observer->ApplicationWindowChanged(old_host, new_host);
  }
}

void ApplicationContents::NotifyDisconnected() {
  if (!notify_disconnection_)
    return;

  notify_disconnection_ = false;
  NotificationService::current()->Notify(
      NOTIFICATION_WEB_CONTENTS_DISCONNECTED,
      Source<ApplicationContents>(this),
      NotificationService::NoDetails());
}

gfx::Size ApplicationContents::GetSizeForNewApplicationWindow(bool is_main_frame) {
  gfx::Size size;
  if (is_main_frame)
    size = device_emulation_size_;
  if (size.IsEmpty() && delegate_)
    size = delegate_->GetSizeForNewApplicationWindow(this);
  if (size.IsEmpty())
    size = GetContainerBounds().size();
  return size;
}

void ApplicationContents::OnPreferredSizeChanged(const gfx::Size& old_size) {
  if (!delegate_)
    return;
  const gfx::Size new_size = GetPreferredSize();
  if (new_size != old_size)
    delegate_->UpdatePreferredSize(this, new_size);
}

void ApplicationContents::OnUserInteraction(const blink::WebInputEvent::Type type) {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));

  for (const auto& observer : observers_) {
    if (observer)
      observer->DidGetUserInteraction(type);
  }

  // TODO(https://crbug.com/827659): This used to check if type != kMouseWheel.
  // However, due to the caller already filtering event types, this would never
  // be called with type == kMouseWheel so checking for that here is pointless.
  // However, mouse wheel events *also* generate a kGestureScrollBegin event...
  // which is *not* filtered out. Maybe they should be?
  //ResourceDispatcherHost* rdh = ResourceDispatcherHost::Get();
  //if (rdh)  // null in unittests. =(
  //  rdh->OnUserGesture();
}

void ApplicationContents::RemoveBindingSet(const std::string& interface_name) {
   // is this for mojo?? what kind of interface
  auto it = binding_sets_.find(interface_name);
  if (it != binding_sets_.end())
    binding_sets_.erase(it);
}

void ApplicationContents::SetVisibilityForChildViews(bool visible) {
  // burp burp
}

void ApplicationContents::NavigatedByUser() {
  OnUserInteraction(blink::WebInputEvent::kUndefined);
}

void ApplicationContents::LoadURL(const GURL& url, const NavigateParams& params) {
  ////DLOG(INFO) << "ApplicationContents::LoadURL: " << url.spec();
  DidStartLoading(true, false);
  //if (application_window_host_) {
  //  application_window_host_->BeginNavigation();
  //}
}

void ApplicationContents::DidStartLoading(bool is_main_frame, bool to_different_document) {
  LoadingStateChanged(is_main_frame && to_different_document, false, nullptr);
}

void ApplicationContents::InitAfterLaunch(const CreateParams& params, ApplicationProcessHost* app_process_host, bool result) {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));

  if (!result) { 
    LOG(ERROR) << "process launch failed. this will make this application contents invalid";
    return;
  }

  // blink::FrameTree::setName always keeps |unique_name| empty in case of a
  // main frame - let's do the same thing here.
  //std::string unique_name;
  //frame_tree_.root()->SetFrameName(params.main_frame_name, unique_name);


  //registrar_.Add(this,
  //               NOTIFICATION_APPLICATION_WINDOW_HOST_DESTROYED,
  //               NotificationService::AllApplicationContentssAndSources());

  screen_orientation_provider_.reset(new ScreenOrientationProvider(this));

  //manifest_manager_host_.reset(new ManifestManagerHost(this));

//#if defined(OS_ANDROID)
//  date_time_chooser_.reset(new DateTimeChooserAndroid());
//#endif

  // BrowserPluginGuest::Init needs to be called after this ApplicationContents has
  // a ApplicationWindowHostViewGuest. That is, |view_->CreateView| above.
//  if (browser_plugin_guest_)
//    browser_plugin_guest_->Init();

  for (size_t i = 0; i < g_created_callbacks.Get().size(); i++) {
    g_created_callbacks.Get().at(i).Run(this);
  }

  // If the ApplicationContents creation was renderer-initiated, it means that the
  // corresponding RenderView and main RenderFrame have already been created.
  // Ensure observers are notified about this.
  if (params.application_initiated_creation) {
    //GetApplicationWindowHost()->GetWindow()->set_application_initialized(true);
    GetApplicationWindowHost()->set_application_initialized(true);
    GetApplicationWindowHost()->DispatchApplicationWindowCreated();
    //GetRenderManager()->current_frame_host()->SetRenderFrameCreated(true);
  }
  //if (params.initialize_application) {
  //  InitApplicationWindow(params, GetApplicationWindowHost());
  //}

  // Ensure that observers are notified of the creation of this ApplicationContents's
  // main RenderFrameHost. It must be done here for main frames, since the
  // NotifySwappedFromRenderManager expects view_ to already be created and that
  // happens after RenderFrameHostManager::Init.
  //NotifySwappedFromRenderManager(
  //    nullptr, GetRenderManager()->current_frame_host(), true);
  NotifySwapped(nullptr, GetApplicationWindowHost()->current_application_frame(), true);

  for (const auto& observer : observers_) {
    //if (observer)
      observer->DidInitializeApplicationContents();
  }
}

void ApplicationContents::UpdateTitle(
  ApplicationWindowHost* application_window_host,
  const base::string16& title,
  base::i18n::TextDirection title_direction) {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));

  base::string16 final_title;
  base::TrimWhitespace(title, base::TRIM_ALL, &final_title);

  page_title_when_no_navigation_entry_ = final_title;

  view_->SetPageTitle(final_title);

  for (const auto& observer : observers_) {
    if (observer)
      observer->TitleWasSet();//entry);
  }

  NotifyNavigationStateChanged(INVALIDATE_TYPE_TITLE);
}

void ApplicationContents::UpdateStateForFrame(ApplicationFrame* application_frame,
                                              const common::mojom::PageState& page_state) {
  ////DLOG(INFO) << "ApplicationContents::UpdateStateForFrame: not implemented";
}

void ApplicationContents::DidFailLoadWithError(const GURL& url, int32_t error_code, const base::string16& error_description) {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));

  for (const auto& observer : observers_) {
    if (observer)
      observer->DidFailLoad(application_window_host_, url, error_code, error_description);
  }
}

void ApplicationContents::DidAccessInitialDocument() {
  //DLOG(INFO) << "ApplicationContents::DidAccessInitialDocument: not implemented";
}

void ApplicationContents::DocumentOnLoadCompleted(ApplicationFrame* application_frame) {
  //DLOG(INFO) << "ApplicationContents::DocumentOnLoadCompleted: not implemented";
}

void ApplicationContents::DidCancelLoading() {
  //DLOG(INFO) << "ApplicationContents::DidCancelLoading: not implemented";
}

void ApplicationContents::CancelModalDialogs() {

}

void ApplicationContents::DidCallFocus() {

}

void ApplicationContents::DidStopLoading() {
  std::unique_ptr<LoadNotificationDetails> details;

  // Use the last committed entry rather than the active one, in case a
  // pending entry has been created.
  //NavigationEntry* entry = controller_.GetLastCommittedEntry();
  //Navigator* navigator = frame_tree_.root()->navigator();

  // An entry may not exist for a stop when loading an initial blank page or
  // if an iframe injected by script into a blank page finishes loading.
  //if (entry) {
  //  base::TimeDelta elapsed =
  //      base::TimeTicks::Now() - navigator->GetCurrentLoadStart();

  //  details.reset(new LoadNotificationDetails(
  //      entry->GetVirtualURL(),
  //      elapsed,
  //      &controller_,
  //      controller_.GetCurrentEntryIndex()));
  //}

  LoadingStateChanged(true, false, details.get());
}

void ApplicationContents::DidNavigateMainFramePreCommit(bool navigation_is_within_page) {
  if (navigation_is_within_page) {
    // No page change?  Then, the renderer and browser can remain in fullscreen.
    return;
  }
  if (IsFullscreen())
    ExitFullscreen(false);
  DCHECK(!IsFullscreen());

  // Clean up keyboard lock state when navigating.
  CancelKeyboardLock(keyboard_lock_widget_);
}

void ApplicationContents::DidNavigateMainFramePostCommit(
    ApplicationFrame* app_window_host,
    const common::mojom::DidCommitProvisionalLoadParams& params) {
  // if (details.is_navigation_to_different_page()) {
  //   // Clear the status bubble. This is a workaround for a bug where WebKit
  //   // doesn't let us know that the cursor left an element during a
  //   // transition (this is also why the mouse cursor remains as a hand after
  //   // clicking on a link); see bugs 1184641 and 980803. We don't want to
  //   // clear the bubble when a user navigates to a named anchor in the same
  //   // page.
  //   ClearTargetURL();

  //   RenderWidgetHostViewBase* rwhvb =
  //       static_cast<RenderWidgetHostViewBase*>(GetRenderWidgetHostView());
  //   if (rwhvb)
  //     rwhvb->OnDidNavigateMainFrameToNewPage();

  //   did_first_visually_non_empty_paint_ = false;

  //   // Reset theme color on navigation to new page.
  //   theme_color_ = SK_ColorTRANSPARENT;
  // }

  if (delegate_)
    delegate_->DidNavigateMainFramePostCommit(this);

  view_->SetOverscrollControllerEnabled(CanOverscrollContent());
}

void ApplicationContents::DidNavigateAnyFramePostCommit(
    ApplicationFrame* app_window_host,
    const common::mojom::DidCommitProvisionalLoadParams& params) {
  // If we navigate off the page, close all JavaScript dialogs.
  //if (!details.is_same_document)
  //  CancelActiveAndPendingDialogs();

  // If this is a user-initiated navigation, start allowing JavaScript dialogs
  // again.
  //if (params.gesture == NavigationGestureUser && dialog_manager_) {
  //  dialog_manager_->CancelDialogs(this, /*reset_state=*/true);
  //}
  
  // Now that something has committed, we don't need to track whether the
  // initial page has been accessed.
  has_accessed_initial_document_ = false;
}

void ApplicationContents::NotifySwapped(ApplicationFrame* old_frame,
                                        ApplicationFrame* new_frame,
                                        bool is_main_frame) {
  if (is_main_frame) {
    NotifyViewSwapped(old_frame ? old_frame->GetWindow() : nullptr,
                      new_frame->GetWindow());
    // Make sure the visible RVH reflects the new delegate's preferences.
    if (delegate_)
      view_->SetOverscrollControllerEnabled(CanOverscrollContent());

    view_->ApplicationWindowSwappedIn(new_frame->GetWindow());//->GetRenderViewHost());

    //RenderWidgetHostViewBase* rwhv =
    //    static_cast<RenderWidgetHostViewBase*>(GetRenderWidgetHostView());
    //if (rwhv)
    //  rwhv->SetMainFrameAXTreeID(GetMainFrame()->GetAXTreeID());
  }

  NotifyFrameSwapped(old_frame, new_frame);
}

void ApplicationContents::NotifyMainFrameSwapped(
    ApplicationFrame* old_frame,
    ApplicationFrame* new_frame) {
  NotifyViewSwapped(
    old_frame->GetWindow(), 
    new_frame->GetWindow());
}

void ApplicationContents::NotifyFrameSwapped(ApplicationFrame* old_frame,
                                             ApplicationFrame* new_frame) {

}

void ApplicationContents::UpdateApplicationWindowSize(bool is_main_frame) {
  // TODO(brettw) this is a hack. See WebContentsView::SizeContents.
  gfx::Size size = GetSizeForNewApplicationWindow(is_main_frame);
  // 0x0 isn't a valid window size (minimal window size is 1x1) but it may be
  // here during container initialization and normal window size will be set
  // later. In case of tab duplication this resizing to 0x0 prevents setting
  // normal size later so just ignore it.
  if (!size.IsEmpty())
    view_->SizeContents(size);
}

void ApplicationContents::OnRenderFrameMetadataChanged() {
  //DLOG(INFO) << "ApplicationContents::OnRenderFrameMetadataChanged";
  GetApplication()->OnRenderFrameMetadataChanged(application_window_host_->last_frame_metadata());
}

}
