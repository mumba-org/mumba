// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/application_window_host.h"

#include <math.h>

#include <algorithm>
#include <set>
#include <tuple>
#include <utility>

#include "base/auto_reset.h"
#include "base/bind.h"
#include "base/command_line.h"
#include "base/containers/hash_tables.h"
#include "base/debug/dump_without_crashing.h"
#include "base/i18n/rtl.h"
#include "base/lazy_instance.h"
#include "base/location.h"
#include "base/macros.h"
#include "base/memory/shared_memory.h"
#include "base/message_loop/message_loop.h"
#include "base/metrics/field_trial.h"
#include "base/metrics/histogram_macros.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "base/strings/utf_string_conversions.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/default_tick_clock.h"
#include "base/trace_event/trace_event.h"
#include "cc/base/switches.h"
#include "cc/trees/render_frame_metadata.h"
#include "components/viz/common/features.h"
#include "components/viz/common/quads/compositor_frame.h"
#include "components/viz/host/host_frame_sink_manager.h"
#include "components/viz/service/display_embedder/server_shared_bitmap_manager.h"
#include "services/resource_coordinator/public/cpp/frame_resource_coordinator.h"
#include "services/resource_coordinator/public/cpp/resource_coordinator_features.h"
#include "services/service_manager/public/cpp/connector.h"
#include "services/service_manager/public/cpp/interface_provider.h"
#include "core/host/application/application_window_host_iterator.h"
//#include "core/host/accessibility/browser_accessibility_state_impl.h"
#include "core/host/bad_message.h"
#include "core/host/host_main_loop.h"
#include "core/host/child_process_security_policy_impl.h"
#include "core/host/compositor/surface_utils.h"
#include "core/host/gpu/compositor_util.h"
#include "core/host/application/dip_util.h"
#include "core/host/application/display_util.h"
//#include "core/host/application/frame_metadata_util.h"
#include "core/host/application/frame_token_message_queue.h"
#include "core/host/application/media/media_stream_dispatcher_host.h"
#include "core/host/application/input/input_router_config_helper.h"
#include "core/host/application/input/input_router_impl.h"
#include "core/host/application/input/synthetic_gesture.h"
#include "core/host/application/input/synthetic_gesture_controller.h"
#include "core/host/application/input/synthetic_gesture_target.h"
#include "core/host/application/input/timeout_monitor.h"
#include "core/host/application/input/touch_emulator.h"
#include "core/host/application/application_window_host_delegate.h"
#include "core/host/application/application_window_host_delegate_view.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/application_window_helper.h"
#include "core/host/application/application_contents.h"
#include "core/host/file_url_loader_factory.h"
#include "core/host/service_worker/service_worker_handle.h"
#include "core/host/route/route_registry.h"
#include "core/host/route/route_entry.h"
#include "core/host/rpc/server/host_rpc_service.h"
#include "core/host/application/domain.h"
#include "core/host/service_worker/service_worker_navigation_handle.h"
#include "core/host/websockets/websocket_manager.h"
#include "net/rpc/rpc.h"
#include "net/url_request/url_request_context.h"
#include "core/host/application/media/audio_input_delegate_impl.h"
#include "core/host/application/media/media_devices_dispatcher_host.h"
#include "core/host/application/media/media_stream_dispatcher_host.h"
#include "core/host/application/media/renderer_audio_output_stream_factory_context_impl.h"
#include "core/host/media/media_interface_proxy.h"
#include "core/host/media/session/media_session_service_impl.h"
#include "core/host/media/capture/audio_mirroring_manager.h"
#include "core/host/net/host_network_context.h"
#include "core/host/image_capture/image_capture_impl.h"
#include "core/host/application/application_window_host_input_event_router.h"
#include "core/host/application/application_window_host_owner_delegate.h"
#include "core/host/application/application_window_host_view.h"
#include "core/host/application/application_window_host_view_aura.h"
#include "core/host/application/render_frame_metadata_provider.h"
#include "core/host/application/application_window_host_iterator.h"
#include "core/host/application/application_window_host_observer.h"
#include "core/host/blob_storage/chrome_blob_storage_context.h"
#include "core/host/application/host_zoom_map.h"
#include "core/host/application/application.h"
#include "core/host/route/route_controller.h"
#include "core/host/application/native_web_keyboard_event.h"
#include "core/host/application/keyboard_event_processing_result.h"
#include "core/host/application/navigation_controller.h"
#include "core/host/application/resource_context_impl.h"
#include "core/host/route/rpc_url_loader_factory.h"
#include "core/host/route/ipc_url_loader_factory.h"
#include "core/host/route/application_url_loader_factory.h"
#include "core/host/io_thread.h"
#include "core/shared/common/media/renderer_audio_output_stream_factory.mojom.h"
#include "core/shared/common/content_constants_internal.h"
#include "core/shared/common/cursors/webcursor.h"
#include "core/shared/common/inter_process_time_ticks_converter.h"

//#include "core/shared/common/drag_messages.h"
//#include "core/shared/common/frame_messages.h"
#include "core/shared/common/input/sync_compositor_messages.h"
#include "core/shared/common/input_messages.h"
#include "core/shared/common/text_input_state.h"
#include "core/shared/common/view_messages.h"
#include "core/shared/common/frame_messages.h"
#include "core/shared/common/visual_properties.h"
//#include "core/host/application_contents.h"
#include "core/host/host_thread.h"
#include "core/host/notification_service.h"
#include "core/host/notification_types.h"
//#include "core/shared/common/constants.h"
//#include "core/shared/common/features.h"
#include "core/shared/common/switches.h"
#include "core/common/result_codes.h"
#include "core/shared/common/content_constants_internal.h"
#include "core/shared/common/associated_interface_provider_impl.h"
#include "core/shared/common/associated_interface_registry_impl.h"
//#include "core/shared/common/use_zoom_for_dsf_policy.h"
#include "core/shared/common/web_preferences.h"
#include "gpu/GLES2/gl2extchromium.h"
#include "gpu/command_buffer/service/gpu_switches.h"
#include "gpu/ipc/common/gpu_messages.h"
#include "media/audio/audio_manager.h"
#include "media/base/media_switches.h"
#include "media/base/user_input_monitor.h"
#include "media/media_buildflags.h"
#include "media/mojo/interfaces/remoting.mojom.h"
#include "media/mojo/services/media_interface_provider.h"
#include "media/mojo/services/media_metrics_provider.h"
#include "mojo/public/cpp/system/platform_handle.h"
#include "net/base/filename_util.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "skia/ext/image_operations.h"
#include "skia/ext/platform_canvas.h"
#include "third_party/blink/public/web/web_ime_text_span.h"
#include "ui/base/clipboard/clipboard.h"
#include "ui/display/display_switches.h"
#include "ui/display/screen.h"
#include "ui/events/blink/web_input_event_traits.h"
#include "ui/events/event.h"
#include "ui/events/keycodes/dom/dom_code.h"
#include "ui/events/keycodes/dom/keycode_converter.h"
#include "ui/events/keycodes/keyboard_code_conversion.h"
#include "ui/events/keycodes/keyboard_codes.h"
#include "ui/gfx/color_space.h"
#include "ui/gfx/geometry/size_conversions.h"
#include "ui/gfx/geometry/vector2d_conversions.h"
#include "ui/gfx/geometry/vector2d_f.h"
#include "ui/gfx/image/image.h"
#include "ui/gfx/image/image_skia.h"
#include "ui/gfx/skbitmap_operations.h"
#include "ui/snapshot/snapshot.h"

#if defined(OS_ANDROID)
#include "ui/android/view_android.h"
#endif

#if defined(OS_MACOSX)
#include "core/shared/common/service_manager_connection.h"
#include "services/device/public/mojom/constants.mojom.h"
#include "services/device/public/mojom/wake_lock_provider.mojom.h"
#include "services/service_manager/public/cpp/connector.h"
#include "ui/accelerated_widget_mac/window_resize_helper_mac.h"
#endif

#if defined (OS_WIN)
#include "base/win/win_util.h"
#include "base/win/win_client_metrics.h"
#include "ui/display/win/screen_win.h"
#include "ui/display/win/display_info.h"
#include "ui/gfx/platform_font_win.h"
#endif

using base::TimeDelta;
using base::TimeTicks;
using blink::WebDragOperation;
using blink::WebDragOperationsMask;
using blink::WebGestureEvent;
using blink::WebInputEvent;
using blink::WebKeyboardEvent;
using blink::WebMouseEvent;
using blink::WebMouseWheelEvent;
using blink::WebTextDirection;

namespace host {

namespace {

bool g_check_for_pending_resize_ack = true;

const int64_t kUnloadTimeoutMS = 1000;
const double kLoadingProgressMinimum = 0.1;
const double kLoadingProgressDone = 1.0;

using ApplicationWindowHostID = std::pair<int32_t, int32_t>;
using RoutingIDWindowMap =
    base::hash_map<ApplicationWindowHostID, ApplicationWindowHost*>;
base::LazyInstance<RoutingIDWindowMap>::DestructorAtExit
    g_routing_id_window_map = LAZY_INSTANCE_INITIALIZER;

// Implements the RenderWidgetHostIterator interface. It keeps a list of
// RenderWidgetHosts, and makes sure it returns a live RenderWidgetHost at each
// iteration (or NULL if there isn't any left).
class ApplicationWindowHostIteratorImpl : public ApplicationWindowHostIterator {
 public:
  ApplicationWindowHostIteratorImpl()
      : current_index_(0) {
  }

  ~ApplicationWindowHostIteratorImpl() override {}

  void Add(ApplicationWindowHost* host) {
    hosts_.push_back(ApplicationWindowHostID(host->GetProcess()->GetID(),
                                        host->GetRoutingID()));
  }

  // RenderWidgetHostIterator:
  ApplicationWindowHost* GetNextHost() override {
    ApplicationWindowHost* host = nullptr;
    while (current_index_ < hosts_.size() && !host) {
      ApplicationWindowHostID id = hosts_[current_index_];
      host = ApplicationWindowHost::FromID(id.first, id.second);
      ++current_index_;
    }
    return host;
  }

 private:
  std::vector<ApplicationWindowHostID> hosts_;
  size_t current_index_;

  DISALLOW_COPY_AND_ASSIGN(ApplicationWindowHostIteratorImpl);
};

class UnboundWindowInputHandler : public common::mojom::WindowInputHandler {
 public:
  void SetFocus(bool focused) override {
    //DLOG(WARNING) << "Input request on unbound interface";
  }
  void MouseCaptureLost() override {
    //DLOG(WARNING) << "Input request on unbound interface";
  }
  void SetEditCommandsForNextKeyEvent(
      const std::vector<common::EditCommand>& commands) override {
    //DLOG(WARNING) << "Input request on unbound interface";
  }
  void CursorVisibilityChanged(bool visible) override {
    //DLOG(WARNING) << "Input request on unbound interface";
  }
  void ImeSetComposition(const base::string16& text,
                         const std::vector<ui::ImeTextSpan>& ime_text_spans,
                         const gfx::Range& range,
                         int32_t start,
                         int32_t end) override {
    //DLOG(WARNING) << "Input request on unbound interface";
  }
  void ImeCommitText(const base::string16& text,
                     const std::vector<ui::ImeTextSpan>& ime_text_spans,
                     const gfx::Range& range,
                     int32_t relative_cursor_position) override {
    //DLOG(WARNING) << "Input request on unbound interface";
  }
  void ImeFinishComposingText(bool keep_selection) override {
    //DLOG(WARNING) << "Input request on unbound interface";
  }
  void RequestTextInputStateUpdate() override {
    //DLOG(WARNING) << "Input request on unbound interface";
  }
  void RequestCompositionUpdates(bool immediate_request,
                                 bool monitor_request) override {
    //DLOG(WARNING) << "Input request on unbound interface";
  }
  void DispatchEvent(std::unique_ptr<common::InputEvent> event,
                     DispatchEventCallback callback) override {
    //DLOG(WARNING) << "Input request on unbound interface";
  }
  void DispatchNonBlockingEvent(
      std::unique_ptr<common::InputEvent> event) override {
    //DLOG(WARNING) << "Input request on unbound interface";
  }
  void AttachSynchronousCompositor(
      common::mojom::SynchronousCompositorControlHostPtr control_host,
      common::mojom::SynchronousCompositorHostAssociatedPtrInfo host,
      common::mojom::SynchronousCompositorAssociatedRequest compositor_request)
      override {
    NOTREACHED() << "Input request on unbound interface";
  }

  void WasHidden() override {
    //DLOG(WARNING) << "Input request on unbound interface";
  }
  void SetBackgroundOpaque(bool opaque) override {
    //DLOG(WARNING) << "Input request on unbound interface";
  }
  void SetCompositionFromExistingText(int32_t start, int32_t end, const std::vector<ui::ImeTextSpan>& ime_text_spans) override {
    //DLOG(WARNING) << "Input request on unbound interface";
  }
  void ExtendSelectionAndDelete(int32_t before, int32_t after) override {
    //DLOG(WARNING) << "Input request on unbound interface";
  }
  void DeleteSurroundingText(int32_t before, int32_t after) override {
    //DLOG(WARNING) << "Input request on unbound interface";
  }
  void DeleteSurroundingTextInCodePoints(int32_t before, int32_t after) override {
    //DLOG(WARNING) << "Input request on unbound interface";
  }
  void SetEditableSelectionOffsets(int32_t start, int32_t end) override {
    //DLOG(WARNING) << "Input request on unbound interface";
  }
  void ExecuteEditCommand(const std::string& command, const base::Optional<base::string16>& value) override {
    //DLOG(WARNING) << "Input request on unbound interface";
  }
  void Undo() override {
    //DLOG(WARNING) << "Input request on unbound interface";
  }
  void Redo() override {
    //DLOG(WARNING) << "Input request on unbound interface";
  }
  void Cut() override {
    //DLOG(WARNING) << "Input request on unbound interface";
  }
  void Copy() override {
    //DLOG(WARNING) << "Input request on unbound interface";
  }
  void CopyToFindPboard() override {
    //DLOG(WARNING) << "Input request on unbound interface";
  }
  void Paste() override {
    //DLOG(WARNING) << "Input request on unbound interface";
  }
  void PasteAndMatchStyle() override {
    //DLOG(WARNING) << "Input request on unbound interface";
  }
  void Delete() override {
    //DLOG(WARNING) << "Input request on unbound interface";
  }
  void SelectAll() override {
    //DLOG(WARNING) << "Input request on unbound interface";
  }
  void CollapseSelection() override {
    //DLOG(WARNING) << "Input request on unbound interface";
  }
  void Replace(const base::string16& word) override {
    //DLOG(WARNING) << "Input request on unbound interface";
  }
  void ReplaceMisspelling(const base::string16& word) override {
    //DLOG(WARNING) << "Input request on unbound interface";
  }
  void SelectRange(const gfx::Point& base, const gfx::Point& extent) override {
    //DLOG(WARNING) << "Input request on unbound interface";
  }
  void AdjustSelectionByCharacterOffset(int32_t start, int32_t end, ::blink::mojom::SelectionMenuBehavior behavior) override {
    //DLOG(WARNING) << "Input request on unbound interface";
  }
  void MoveRangeSelectionExtent(const gfx::Point& extent) override {
    //DLOG(WARNING) << "Input request on unbound interface";
  }
  void ScrollFocusedEditableNodeIntoRect(const gfx::Rect& rect) override {
    //DLOG(WARNING) << "Input request on unbound interface";
  }
  void MoveCaret(const gfx::Point& point) override {
    //DLOG(WARNING) << "Input request on unbound interface";
  }
  void GetWindowInputHandler(common::mojom::WindowInputHandlerAssociatedRequest interface_request, common::mojom::WindowInputHandlerHostPtr host) override {
    NOTREACHED() << "Input request on unbound interface";
  }

};


common::WebPreferences ComputeWebkitPrefs() {
  common::WebPreferences preferences;
  // TODO: fix
  return preferences;
}

void GetPlatformSpecificPrefs(common::RendererPreferences* prefs) {
#if defined(OS_WIN)
  NONCLIENTMETRICS_XP metrics = {0};
  base::win::GetNonClientMetrics(&metrics);

  prefs->caption_font_family_name = metrics.lfCaptionFont.lfFaceName;
  prefs->caption_font_height = gfx::PlatformFontWin::GetFontSize(
      metrics.lfCaptionFont);

  prefs->small_caption_font_family_name = metrics.lfSmCaptionFont.lfFaceName;
  prefs->small_caption_font_height = gfx::PlatformFontWin::GetFontSize(
      metrics.lfSmCaptionFont);

  prefs->menu_font_family_name = metrics.lfMenuFont.lfFaceName;
  prefs->menu_font_height = gfx::PlatformFontWin::GetFontSize(
      metrics.lfMenuFont);

  prefs->status_font_family_name = metrics.lfStatusFont.lfFaceName;
  prefs->status_font_height = gfx::PlatformFontWin::GetFontSize(
      metrics.lfStatusFont);

  prefs->message_font_family_name = metrics.lfMessageFont.lfFaceName;
  prefs->message_font_height = gfx::PlatformFontWin::GetFontSize(
      metrics.lfMessageFont);

  prefs->vertical_scroll_bar_width_in_dips =
      display::win::ScreenWin::GetSystemMetricsInDIP(SM_CXVSCROLL);
  prefs->horizontal_scroll_bar_height_in_dips =
      display::win::ScreenWin::GetSystemMetricsInDIP(SM_CYHSCROLL);
  prefs->arrow_bitmap_height_vertical_scroll_bar_in_dips =
      display::win::ScreenWin::GetSystemMetricsInDIP(SM_CYVSCROLL);
  prefs->arrow_bitmap_width_horizontal_scroll_bar_in_dips =
      display::win::ScreenWin::GetSystemMetricsInDIP(SM_CXHSCROLL);
#elif defined(OS_LINUX)
  prefs->system_font_family_name = gfx::Font().GetFontName();
#endif
}

inline blink::WebGestureEvent CreateScrollBeginForWrapping(
    const blink::WebGestureEvent& gesture_event) {
  DCHECK(gesture_event.GetType() == blink::WebInputEvent::kGestureScrollUpdate);

  blink::WebGestureEvent wrap_gesture_scroll_begin(
      blink::WebInputEvent::kGestureScrollBegin, gesture_event.GetModifiers(),
      gesture_event.TimeStamp(), gesture_event.SourceDevice());
  wrap_gesture_scroll_begin.data.scroll_begin.delta_x_hint = 0;
  wrap_gesture_scroll_begin.data.scroll_begin.delta_y_hint = 0;
  wrap_gesture_scroll_begin.resending_plugin_id =
      gesture_event.resending_plugin_id;
  wrap_gesture_scroll_begin.data.scroll_begin.delta_hint_units =
      gesture_event.data.scroll_update.delta_units;

  return wrap_gesture_scroll_begin;
}

inline blink::WebGestureEvent CreateScrollEndForWrapping(
    const blink::WebGestureEvent& gesture_event) {
  DCHECK(gesture_event.GetType() == blink::WebInputEvent::kGestureScrollUpdate);

  blink::WebGestureEvent wrap_gesture_scroll_end(
      blink::WebInputEvent::kGestureScrollEnd, gesture_event.GetModifiers(),
      gesture_event.TimeStamp(), gesture_event.SourceDevice());
  wrap_gesture_scroll_end.resending_plugin_id =
      gesture_event.resending_plugin_id;
  wrap_gesture_scroll_end.data.scroll_end.delta_units =
      gesture_event.data.scroll_update.delta_units;

  return wrap_gesture_scroll_end;
}

base::i18n::TextDirection FromWebTextDirection(blink::WebTextDirection blink_dir) {
  base::i18n::TextDirection result = base::i18n::UNKNOWN_DIRECTION;
  switch (blink_dir) {
    case blink::kWebTextDirectionDefault:
      result = base::i18n::LEFT_TO_RIGHT;
      break;
    case blink::kWebTextDirectionLeftToRight:
      result = base::i18n::LEFT_TO_RIGHT;
      break;
    case blink::kWebTextDirectionRightToLeft:
      result = base::i18n::RIGHT_TO_LEFT;
      break;
    default:
      result = base::i18n::UNKNOWN_DIRECTION;
  }
  return result;
}

// dont know where does it come from in the original
// so just doing this patch for now
bool IsUseZoomForDSFEnabled() {
  return false;
}

std::vector<common::DropDataMetadata> DropDataToMetaData(const common::DropData& drop_data) {
  std::vector<common::DropDataMetadata> metadata;
  if (!drop_data.text.is_null()) {
    metadata.push_back(common::DropDataMetadata::CreateForMimeType(
        common::DropDataMetadataKind::STRING,
        base::ASCIIToUTF16(ui::Clipboard::kMimeTypeText)));
  }

  if (drop_data.url.is_valid()) {
    metadata.push_back(common::DropDataMetadata::CreateForMimeType(
        common::DropDataMetadataKind::STRING,
        base::ASCIIToUTF16(ui::Clipboard::kMimeTypeURIList)));
  }

  if (!drop_data.html.is_null()) {
    metadata.push_back(common::DropDataMetadata::CreateForMimeType(
        common::DropDataMetadataKind::STRING,
        base::ASCIIToUTF16(ui::Clipboard::kMimeTypeHTML)));
  }

  // On Aura, filenames are available before drop.
  for (const auto& file_info : drop_data.filenames) {
    if (!file_info.path.empty()) {
      metadata.push_back(common::DropDataMetadata::CreateForFilePath(file_info.path));
    }
  }

  // On Android, only files' mime types are available before drop.
  for (const auto& mime_type : drop_data.file_mime_types) {
    if (!mime_type.empty()) {
      metadata.push_back(common::DropDataMetadata::CreateForMimeType(
          common::DropDataMetadataKind::FILENAME, mime_type));
    }
  }

  for (const auto& file_system_file : drop_data.file_system_files) {
    if (!file_system_file.url.is_empty()) {
      metadata.push_back(
          common::DropDataMetadata::CreateForFileSystemUrl(file_system_file.url));
    }
  }

  for (const auto& custom_data_item : drop_data.custom_data) {
    metadata.push_back(common::DropDataMetadata::CreateForMimeType(
        common::DropDataMetadataKind::STRING, custom_data_item.first));
  }

  return metadata;
}

base::i18n::TextDirection WebTextDirectionToChromeTextDirection(
    blink::WebTextDirection dir) {
  switch (dir) {
    case blink::kWebTextDirectionLeftToRight:
      return base::i18n::LEFT_TO_RIGHT;
    case blink::kWebTextDirectionRightToLeft:
      return base::i18n::RIGHT_TO_LEFT;
    default:
      NOTREACHED();
      return base::i18n::UNKNOWN_DIRECTION;
  }
}

service_manager::mojom::InterfaceProviderRequest FilterRendererExposedInterfaces(
    const char* spec,
    int process_id,
    service_manager::mojom::InterfaceProviderRequest request) {
  service_manager::mojom::InterfaceProviderPtr provider;
  auto filtered_request = mojo::MakeRequest(&provider);
  
  ApplicationProcessHost* process = ApplicationProcessHost::FromID(process_id);
  if (!process)
    return filtered_request;

  service_manager::Connector* connector = common::ServiceManagerConnection::GetForProcess()->GetConnector();
      //BrowserContext::GetConnectorFor(process->GetBrowserContext());
  // |connector| is null in unit tests.
  if (!connector)
    return filtered_request;

  connector->FilterInterfaces(spec, process->GetChildIdentity(),
                              std::move(request), std::move(provider));
  return filtered_request;
}

const size_t kMaxTitleChars = 4 * 1024;

base::LazyInstance<UnboundWindowInputHandler>::Leaky g_unbound_input_handler =
    LAZY_INSTANCE_INITIALIZER;


using TokenFrameMap = base::hash_map<base::UnguessableToken,
                                     ApplicationWindowHost*,
                                     base::UnguessableTokenHash>;
base::LazyInstance<TokenFrameMap>::Leaky g_token_frame_map =
    LAZY_INSTANCE_INITIALIZER;


} // namespace

// static 
ApplicationWindowHost* ApplicationWindowHost::FromID(int32_t process_id, int32_t routing_id) {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));
  RoutingIDWindowMap* widgets = g_routing_id_window_map.Pointer();
  RoutingIDWindowMap::iterator it = widgets->find(
      ApplicationWindowHostID(process_id, routing_id));
  return it == widgets->end() ? nullptr : it->second;
}

// static
ApplicationWindowHost* ApplicationWindowHost::FromOverlayRoutingToken(
    const base::UnguessableToken& token) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  auto it = g_token_frame_map.Get().find(token);
  return it == g_token_frame_map.Get().end() ? nullptr : it->second;
}

// static 
std::unique_ptr<ApplicationWindowHostIterator> ApplicationWindowHost::GetApplicationWindowHosts() {
  std::unique_ptr<ApplicationWindowHostIteratorImpl> hosts(
      new ApplicationWindowHostIteratorImpl());
  for (auto& it : g_routing_id_window_map.Get()) {
    ApplicationWindowHost* widget = it.second;
    if (widget->is_active()) {
      hosts->Add(widget);
    }
  }
  return std::move(hosts);
}

// static 
std::unique_ptr<ApplicationWindowHostIterator> ApplicationWindowHost::GetAllApplicationWindowHosts() {
  std::unique_ptr<ApplicationWindowHostIteratorImpl> hosts(
      new ApplicationWindowHostIteratorImpl());
  for (auto& it : g_routing_id_window_map.Get())
    hosts->Add(it.second);

  return std::move(hosts);
}

ApplicationWindowHost::ApplicationWindowHost(
    ApplicationWindowHostDelegate* delegate,
    Application* application,
    ApplicationProcessHost* process,
    int32_t routing_id,
    //mojom::WidgetPtr widget_interface,
    bool hidden):
    application_window_host_binding_(this),
    application_initialized_(false),
    destroyed_(false),
    delegate_(delegate),
    //owner_delegate_(nullptr),
    process_(process),
    application_(application),
    routing_id_(routing_id),
    clock_(base::DefaultTickClock::GetInstance()),
    is_loading_(false),
    is_hidden_(hidden),
    repaint_ack_pending_(false),
    resize_ack_pending_(false),
    auto_resize_enabled_(false),
    waiting_for_screen_rects_ack_(false),
    needs_repainting_on_restore_(false),
    is_unresponsive_(false),
    in_flight_event_count_(0),
    in_get_backing_store_(false),
    ignore_input_events_(false),
    text_direction_updated_(false),
    text_direction_(blink::kWebTextDirectionLeftToRight),
    text_direction_canceled_(false),
    suppress_events_until_keydown_(false),
    pending_mouse_lock_request_(false),
    allow_privileged_mouse_lock_(false),
    is_last_unlocked_by_target_(false),
    has_touch_handler_(false),
    is_in_touchpad_gesture_fling_(false),
    latency_tracker_(true, delegate_),
    //next_browser_snapshot_id_(1),
    //owned_by_render_frame_host_(false),
    is_focused_(false),
    hung_renderer_delay_(base::TimeDelta::FromMilliseconds(common::kHungRendererDelayMs)),
    new_content_rendering_delay_(
        TimeDelta::FromMilliseconds(common::kNewContentRenderingDelayMs)),
    current_content_source_id_(0),
    monitoring_composition_info_(false),
    compositor_frame_sink_binding_(this),
    frame_token_message_queue_(
        std::make_unique<FrameTokenMessageQueue>(this)),
    render_frame_metadata_provider_(frame_token_message_queue_.get()),
    frame_sink_id_(base::checked_cast<uint32_t>(process_->GetID()),
                   base::checked_cast<uint32_t>(routing_id_)),
    document_scoped_interface_provider_binding_(this),
    is_waiting_for_swapout_ack_(false),
    has_selection_(false),
    is_audible_(false),
    is_swapped_out_(false),
    is_active_(false),
    updating_web_preferences_(false),
    sudden_termination_allowed_(false),
    app_window_termination_status_(base::TERMINATION_STATUS_STILL_RUNNING),
    is_waiting_for_close_ack_(false),
    has_notified_about_creation_(false),
    application_window_created_(false),
    is_waiting_for_beforeunload_ack_(false),
    unload_ack_is_for_navigation_(false),
    visual_properties_ack_pending_(false),
    is_first_was_shown_(true),
    load_progress_(0.0),
    weak_factory_(this),
    io_weak_factory_(this) {
  
  DCHECK(delegate_);
  //DLOG(INFO) << "ApplicationWindowHost(): this = " << this << " delegate = " << delegate_;
  // to post from IO to UI thread
  weak_this_ = weak_factory_.GetWeakPtr();

  BindProcess(process_);

  //RenderFrameHost stuff    
  swapout_event_monitor_timeout_.reset(new TimeoutMonitor(base::Bind(
      &ApplicationWindowHost::OnSwappedOut, weak_factory_.GetWeakPtr())));//weak_factory_.GetWeakPtr())));

  associated_widget_input_handler_ = nullptr;
  widget_input_handler_ = nullptr;
  SetupInputRouter();
  touch_emulator_.reset();
//  SetWindow(std::move(widget));

  //const auto* command_line = base::CommandLine::ForCurrentProcess();
//  if (!command_line->HasSwitch(switches::kDisableHangMonitor)) {
    //hang_monitor_timeout_.reset(new TimeoutMonitor(
    //    base::Bind(&ApplicationWindowHost::ApplicationIsUnresponsive,
    //               weak_factory_.GetWeakPtr())));
  //}

  //if (!command_line->HasSwitch(switches::kDisableNewContentRenderingTimeout)) {
    new_content_rendering_timeout_.reset(new TimeoutMonitor(
        base::Bind(&ApplicationWindowHost::ClearDisplayedGraphics,
                   weak_factory_.GetWeakPtr())));
  //}

  enable_surface_synchronization_ = features::IsSurfaceSynchronizationEnabled();
  enable_viz_ = base::FeatureList::IsEnabled(features::kVizDisplayCompositor);
  
  close_timeout_.reset(new TimeoutMonitor(base::Bind(
      &ApplicationWindowHost::ClosePageTimeout, weak_factory_.GetWeakPtr())));

  input_device_change_observer_.reset(new InputDeviceChangeObserver(this));

  //associated_registry_ = std::make_unique<common::AssociatedInterfaceRegistryImpl>();
  //registry_ = std::make_unique<service_manager::BinderRegistry>();

  //SetUpMojo();

  // we start a "main frame" here. TODO: check if this is the best way
  application_frame_ = std::make_unique<ApplicationFrame>(
    weak_factory_.GetWeakPtr(),
    // TODO: fix with a id for the main frame
    routing_id_,
    false,
    true,
    true);

  delegate_->ApplicationWindowCreated(this);
}

ApplicationWindowHost::~ApplicationWindowHost() {
  ////DLOG(INFO) << "~ApplicationWindowHost";
  // ApplicationWindowHostDestructor
  if (!destroyed_)
    Destroy(false);
  // end ApplicationWindowHostDestructor
  // ApplicationWindowHostDestructor
  //if (ResourceDispatcherHostImpl::Get()) {
  //  HostThread::PostTask(
  //      HostThread::IO, FROM_HERE,
  //      base::BindOnce(&ResourceDispatcherHostImpl::OnApplicationWindowHostDeleted,
  //                     base::Unretained(ResourceDispatcherHostImpl::Get()),
  //                     GetProcess()->GetID(), GetRoutingID()));
  //}
  if (delegate_)
    delegate_->ApplicationWindowDeleted(this);
  
  if (process_) {
    GetProcess()->RemoveObserver(this);
  }
  // end

  for (const auto& iter : visual_state_callbacks_)
    iter.second.Run(false);

  // RenderFrameHost

  //if (delegate_ && render_frame_created_)
  //  delegate_->RenderFrameDeleted(this);

  // Null out the swapout timer; in crash dumps this member will be null only if
  // the dtor has run.  (It may also be null in tests.)
  swapout_event_monitor_timeout_.reset();
 
  // RenderFrameHost back to us
  //if (application_window_host_ &&
  //    application_window_host_->owned_by_render_frame_host()) {
    // Shutdown causes the ApplicationWindowHost to delete itself.
  //  application_window_host_->ShutdownAndDestroyWindow(true);
  //}

  // Notify the FrameTree that this RFH is going away, allowing it to shut down
  // the corresponding RenderViewHost if it is no longer needed.
  //frame_tree_->ReleaseRenderViewHostRef(application_window_host_);

   if (overlay_routing_token_)
    g_token_frame_map.Get().erase(*overlay_routing_token_);
}

const viz::FrameSinkId& ApplicationWindowHost::GetFrameSinkId() const {
  //DLOG(INFO) << "ApplicationWindowHost::GetFrameSinkId: FrameSinkId(" << frame_sink_id_.client_id() << ", " << frame_sink_id_.sink_id() << ")";
  return frame_sink_id_;
}

const base::UnguessableToken& ApplicationWindowHost::GetOverlayRoutingToken() {
  if (!overlay_routing_token_) {
    overlay_routing_token_ = base::UnguessableToken::Create();
    g_token_frame_map.Get().emplace(*overlay_routing_token_, this);
  }

  return *overlay_routing_token_;
}

int64_t ApplicationWindowHost::GetLatencyComponentId() const {
  return latency_tracker_.latency_component_id();
}

common::mojom::ApplicationWindow* ApplicationWindowHost::GetApplicationWindowInterface() {
  //DLOG(INFO) << "ApplicationWindowHost::GetApplicationWindowInterface";
  return application_window_interface_.get();
}

ApplicationContents* ApplicationWindowHost::application_contents() const {
  return delegate()->GetAsApplicationContents();
}

void ApplicationWindowHost::AddBinding(common::mojom::ApplicationWindowHostAssociatedRequest request) {
  //DLOG(INFO) << "ApplicationWindowHost::AddBinding";
  application_window_host_binding_.Bind(std::move(request));
}

// static 
void ApplicationWindowHost::OnGpuSwapBuffersCompleted(
      const std::vector<ui::LatencyInfo>& latency_info) {
  //DLOG(INFO) << "ApplicationWindowHost::OnGpuSwapBuffersCompleted: disabled. see how it affects rendering";
  // for (size_t i = 0; i < latency_info.size(); i++) {
  //   std::set<ApplicationWindowHost*> awh_set;
  //   for (const auto& lc : latency_info[i].latency_components()) {
  //     //if (lc.first.first == ui::INPUT_EVENT_LATENCY_BEGIN_RWH_COMPONENT ||
  //     //    lc.first.first == ui::BROWSER_SNAPSHOT_FRAME_NUMBER_COMPONENT ||
  //     //    // TODO: this is probably the right target for us
  //     //    //       we should rename it properly according to our
  //     //    //       reality here (which theres nothing to do with tabs
  //     //    //       but windows
  //     //    lc.first.first == ui::TAB_SHOW_COMPONENT) {
  //     if (lc.first == ui::INPUT_EVENT_LATENCY_BEGIN_RWH_COMPONENT ||
  //         lc.first == ui::TAB_SHOW_COMPONENT ||
  //         lc.first == ui::BROWSER_SNAPSHOT_FRAME_NUMBER_COMPONENT) {
  //       // Matches with GetLatencyComponentId
  //       int routing_id = lc.first.second & 0xffffffff;
  //       int process_id = (lc.first.second >> 32) & 0xffffffff;
  //       ApplicationWindowHost* awh =
  //           ApplicationWindowHost::FromID(process_id, routing_id);
  //       if (!awh) {
  //         continue;
  //       }
  //       if (awh_set.insert(awh).second) {
  //         awh->OnGpuSwapBuffersCompletedInternal(latency_info[i]);
  //       }
  //     }
  //   }
  // }
}

/*
 * ApplicationWindowHost section
 */


void ApplicationWindowHost::ProgressFlingIfNeeded(TimeTicks current_time) {
  browser_fling_needs_begin_frame_ = false;
  //fling_scheduler_->ProgressFlingOnBeginFrameIfneeded(current_time);
  ProgressFling(current_time);
}

void ApplicationWindowHost::SetView(ApplicationWindowHostView* view) {
  if (view) {
    view_ = view->GetWeakPtr();
    if (enable_viz_) {
      if (!create_frame_sink_callback_.is_null())
        std::move(create_frame_sink_callback_).Run(view_->GetFrameSinkId());
    } else {
      if (renderer_compositor_frame_sink_.is_bound()) {
        view->DidCreateNewApplicationCompositorFrameSink(
            renderer_compositor_frame_sink_.get());
      }
      // Views start out not needing begin frames, so only update its state
      // if the value has changed.
      if (needs_begin_frames_) {
        view_->SetNeedsBeginFrames(needs_begin_frames_);
      }
    }
  } else {
    view_.reset();
  }

  synthetic_gesture_controller_.reset();
}

void ApplicationWindowHost::Init() {
  application_initialized_ = true;

  SendScreenRects();
  SynchronizeVisualProperties();

  ApplicationWindowDidInit();

  if (view_)
    view_->OnApplicationWindowInit();
}

void ApplicationWindowHost::SendScreenRects() {
  //DLOG(INFO) << "ApplicationWindowHost::SendScreenRects";
  if (!application_initialized_ || waiting_for_screen_rects_ack_)
    return;

  if (is_hidden_) {
    // On GTK, this comes in for backgrounded tabs. Ignore, to match what
    // happens on Win & Mac, and when the view is shown it'll call this again.
    return;
  }

  if (!view_)
    return;

  last_view_screen_rect_ = view_->GetViewBounds();
  last_window_screen_rect_ = view_->GetBoundsInRootWindow();
  view_->WillSendScreenRects();
  //Send(new ViewMsg_UpdateScreenRects(
  //    GetRoutingID(), last_view_screen_rect_, last_window_screen_rect_));
  //DLOG(INFO) << "ApplicationWindowHost::SendScreenRects: post ApplicationWindow::UpdateScreenRects() on IO";
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendUpdateScreenRects,
      io_weak_this_,
      last_view_screen_rect_,
      last_window_screen_rect_)
  );

  waiting_for_screen_rects_ack_ = true;
}

void ApplicationWindowHost::ResetSizeAndRepaintPendingFlags() {
  //DLOG(INFO) << "ApplicationWindowHost::ResetSizeAndRepaintPendingFlags";
  resize_ack_pending_ = false;
  if (repaint_ack_pending_) {
    TRACE_EVENT_ASYNC_END0(
        "renderer_host", "RenderWidgetHostImpl::repaint_ack_pending_", this);
  }
  repaint_ack_pending_ = false;
  if (old_visual_properties_)
    old_visual_properties_->new_size = gfx::Size();
}


void ApplicationWindowHost::SetFrameDepth(unsigned int depth) {
  if (frame_depth_ == depth)
    return;

  frame_depth_ = depth;
  UpdatePriority();
}

void ApplicationWindowHost::SetPageFocus(bool focused) {
  //DLOG(INFO) << "ApplicationWindowHost::SetPageFocus " << focused;
  is_focused_ = focused;

  if (!focused) {
    // If there is a pending mouse lock request, we don't want to reject it at
    // this point. The user can switch focus back to this view and approve the
    // request later.
    if (IsMouseLocked())
      view_->UnlockMouse();

    if (IsKeyboardLocked())
      UnlockKeyboard();

    if (touch_emulator_)
      touch_emulator_->CancelTouch();
  } else if (keyboard_lock_allowed_) {
    LockKeyboard();
  }

  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendSetFocus,
      io_weak_this_,
      focused)
  );

  // Also send page-level focus state to other SiteInstances involved in
  // rendering the current FrameTree.
  if (delegate_)
    delegate_->ReplicatePageFocus(focused);
}

bool ApplicationWindowHost::ShouldDropInputEvents() const {
  DCHECK(process_);
  return ignore_input_events_ || process_->IgnoreInputEvents() || !delegate_;
}

void ApplicationWindowHost::UpdatePriority() {
  //if (!destroyed_)
  //  process_->UpdateClientPriority(this);
}

void ApplicationWindowHost::UpdateTextDirection(blink::WebTextDirection direction) {
  text_direction_updated_ = true;
  text_direction_ = direction;
}

void ApplicationWindowHost::CancelUpdateTextDirection() {
  if (text_direction_updated_)
    text_direction_canceled_ = true;
}

void ApplicationWindowHost::NotifyTextDirection() {
  if (text_direction_updated_) {
    if (!text_direction_canceled_) {
      HostThread::PostTask(
        HostThread::IO, 
        FROM_HERE, 
        base::BindOnce(
          &ApplicationWindowHost::SendSetTextDirection,
          io_weak_this_,
          text_direction_)
      );
      //Send(new ViewMsg_SetTextDirection(GetRoutingID(), text_direction_));
    }
    text_direction_updated_ = false;
    text_direction_canceled_ = false;
  }
}

void ApplicationWindowHost::ImeSetComposition(
    const base::string16& text,
    const std::vector<ui::ImeTextSpan>& ime_text_spans,
    const gfx::Range& replacement_range,
    int selection_start,
    int selection_end) {
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendImeSetComposition,
      io_weak_this_,
      text, ime_text_spans, replacement_range, selection_start, selection_end)
  );
}

void ApplicationWindowHost::ImeCommitText(
    const base::string16& text,
    const std::vector<ui::ImeTextSpan>& ime_text_spans,
    const gfx::Range& replacement_range,
    int relative_cursor_pos) {
  //DLOG(INFO) << "ApplicationWindowHost::ImeCommitText";
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendImeCommitText,
      io_weak_this_,
      text, ime_text_spans, replacement_range, relative_cursor_pos)
  );
}

void ApplicationWindowHost::ImeFinishComposingText(bool keep_selection) {
  //DLOG(INFO) << "ApplicationWindowHost::ImeFinishComposingText";
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendImeFinishComposingText,
      io_weak_this_,
      keep_selection));
}

void ApplicationWindowHost::ImeCancelComposition() {
  //DLOG(INFO) << "ApplicationWindowHost::ImeCancelComposition"; 
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendImeCancelComposition,
      io_weak_this_));
}

void ApplicationWindowHost::Focus() {
  //DLOG(INFO) << "ApplicationWindowHost::Focus";
  
  // ApplicationWindowHost
  delegate_->Activate();
  // ApplicationWindowHost
  ApplicationWindowHost* focused_widget =
      delegate_ ? delegate_->GetApplicationWindowHostWithPageFocus() : nullptr;

  if (!focused_widget)
    focused_widget = this;
  focused_widget->SetPageFocus(true);
}

void ApplicationWindowHost::Blur() {
  ApplicationWindowHost* focused_widget =
      delegate_ ? delegate_->GetApplicationWindowHostWithPageFocus() : nullptr;

  if (!focused_widget)
    focused_widget = this;
  focused_widget->SetPageFocus(false);
}

void ApplicationWindowHost::SetActive(bool active) {
  //DLOG(INFO) << "ApplicationWindowHost::SetActive " << active;
  //Send(new ViewMsg_SetActive(routing_id_, active));
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendSetActive,
      io_weak_this_,
      active)
  );
}

bool ApplicationWindowHost::OnMessageReceived(
  const IPC::Message& message) {
  //DLOG(INFO) << "ApplicationWindowHost::OnMessageReceived";
  bool handled = true;
  IPC_BEGIN_MESSAGE_MAP(ApplicationWindowHost, message)
    IPC_MESSAGE_HANDLER(ViewHostMsg_FrameSwapMessages,
                        OnFrameSwapMessagesReceived)
    IPC_MESSAGE_HANDLER(FrameHostMsg_VisualStateResponse,
                        OnVisualStateResponse)
   // IPC_MESSAGE_HANDLER(FrameHostMsg_CreateNewWindow,
   //                     OnCreateNewWindow)
    IPC_MESSAGE_UNHANDLED(handled = false)
  IPC_END_MESSAGE_MAP()

  if (!handled && input_router_ && input_router_->OnMessageReceived(message))
    return true;

  return handled;
}

void ApplicationWindowHost::OnCreateNewWindow(
    const FrameHostMsg_CreateNewWindow_Params& params,
    int* new_routing_id,
    mojo::MessagePipeHandle* new_interface_provider) {
  //DLOG(INFO) << "ApplicationWindowHost::OnCreateNewWindow";
  *new_routing_id = process_->GetNextRoutingID();

  service_manager::mojom::InterfaceProviderPtr interface_provider;
  auto interface_provider_request(mojo::MakeRequest(&interface_provider));
  *new_interface_provider =
      interface_provider.PassInterface().PassHandle().release();

  // HostThread::PostTask(
  //     HostThread::UI, FROM_HERE,
  //     base::BindOnce(&CreateChildFrameOnUI, render_process_id_,
  //                    params.parent_routing_id, params.scope, params.frame_name,
  //                    params.frame_unique_name, params.is_created_by_script,
  //                    *devtools_frame_token, params.frame_policy,
  //                    params.frame_owner_properties, *new_routing_id,
  //                    interface_provider_request.PassMessagePipe()));
}

void ApplicationWindowHost::BeginNavigation(const std::string& url) {
  //DCHECK(HostThread::CurrentlyOn(HostThread::IO));

  //DCHECK(factory_for_rpc);

  GURL gurl(url);
  
  // TODO: FILL THIS WITH THE BeginNavigation of 'NavigationRequest'
  // also not forgetting about the "speculative_frame" creation
  // inside of it

  //if (IsURLHandledByNetworkStack(common_params_.url) &&
  //    !navigation_handle_->IsSameDocument()) {
    // It's safe to use base::Unretained because this NavigationRequest owns
    // the NavigationHandle where the callback will be stored.
    // TODO(clamy): pass the method to the NavigationHandle instead of a
    // boolean.
  //  navigation_handle_->WillStartRequest(
  //      base::Bind(&NavigationRequest::OnStartChecksComplete,
  //                 base::Unretained(this)));
  //  return;
  //}

  NavigationController* controller = delegate_->GetNavigationController();
  if (controller->current() && controller->current()->route()) {
    RouteEntry* route = controller->current()->route();
    if (route->url() == gurl.spec()) {
      DLOG(INFO) << "ApplicationWindowHost::BeginNavigation: already navigated. just reusing the current entry";
      OnNavigationCompletion(gurl, net::OK, controller->current());
      return;
    }
  }
  controller->Navigate(gurl,
                       base::BindOnce(&ApplicationWindowHost::OnNavigationCompletion,
                                       weak_factory_.GetWeakPtr(),
                                       gurl));
}

void ApplicationWindowHost::OnNavigationCompletion(const GURL& url, int result, NavigationEntry* entry) {
  if (result != net::OK) {
    // what to do here?
    DLOG(ERROR) << "navigation to " << url << " failed";
    //DCHECK(false);
    return;
  }
  if (HostThread::CurrentlyOn(HostThread::UI)) {
    BeginNavigationImpl(url);
  } else {
    HostThread::PostTask(
      HostThread::UI,
      FROM_HERE,
      base::BindOnce(
        &ApplicationWindowHost::BeginNavigationImpl,
        weak_factory_.GetWeakPtr(),
        url));
  }
}

void ApplicationWindowHost::BeginNavigationImpl(const GURL& url) {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));

  // NavigationController* controller = delegate_->GetNavigationController();
  // NavigationEntry* nav_entry = controller->Navigate(url);
  // if (nav_entry == nullptr) {
  //   //DLOG(INFO) << "ApplicationWindowHost::BeginNavigation: failed to navigate to " << url << ". not found";
  //   return;
  // }
  NavigationEntry* nav_entry = delegate_->GetNavigationController()->current();
  DCHECK(nav_entry);

  //ServiceWorkerProviderHost* provider_host = ServiceWorkerRequestHandler::GetProviderHost(request);
  //DCHECK(provider_host);
  //nav_entry->provider_id = provider_host->provider_id();
 
  //RouteController* controller = delegate_->GetRouteController();
  // if (!controller->GoTo(request->url)) {
  //   //DLOG(INFO) << "ApplicationWindowHost::BeginNavigation: failed to navigate to " << url << ". not found";
  //   return;
  // }
  RouteEntry* url_entry = nav_entry->route(); // controller->GetCurrent();
  //DCHECK(url_entry);
  // TODO: fix
  bool to_different_document = false;//!FrameMsg_Navigate_Type::IsSameDocument(
      //navigation_request_->common_params().navigation_type);

  DidStartLoading(to_different_document);

  std::unique_ptr<ApplicationFrame> frame_proxy = 
    std::make_unique<ApplicationFrame>(
      GetWeakPtr(),
      routing_id_,
      true/* proxy */,
      true/* live */,
      true/* main_frame*/); 
  
  proxy_frames_.emplace(std::make_pair(routing_id_, std::move(frame_proxy)));

  speculative_application_frame_ = std::make_unique<ApplicationFrame>(
      GetWeakPtr(),
      routing_id_,
      false/* proxy */,
      true/* live */,
      true/* main_frame*/);

  bool keep_alive = url_entry->rpc_method_type() != common::mojom::RouteEntryRPCMethodType::kRPC_METHOD_NORMAL;
  // This commit here, must be the very last op
  //CommitNavigation(url, keep_alive, std::move(url_loader_factory));
  // HostThread::PostTask(
  //   HostThread::IO, 
  //   FROM_HERE, 
  //   base::BindOnce(&ApplicationWindowHost::CommitNavigation,
  //    base::Unretained(this),
  //    url,
  //    keep_alive,
  //    base::Passed(std::move(default_factory_info)),
  //    base::Passed(std::move(rpc_url_loader_factory))));
  CommitNavigation(
    nav_entry, 
    keep_alive);
}

void ApplicationWindowHost::DidChangeName(const std::string& name,
                                          const std::string& unique_name) {
  //DLOG(INFO) << "ApplicationWindowHost::DidChangeName";
  delegate_->DidChangeName(this, name);
}

void ApplicationWindowHost::FrameSizeChanged(const gfx::Size& frame_size) {
  //DLOG(INFO) << "ApplicationWindowHost::FrameSizeChanged";
  frame_size_ = frame_size;
}

void ApplicationWindowHost::OnUpdatePictureInPictureSurfaceId(
    const viz::SurfaceId& surface_id,
    const gfx::Size& natural_size) {
  if (delegate_)
    delegate_->UpdatePictureInPictureSurfaceId(surface_id, natural_size);
}

void ApplicationWindowHost::OnExitPictureInPicture() {
  if (delegate_)
    delegate_->ExitPictureInPicture();
}

common::InputEventAckState ApplicationWindowHost::FilterInputEvent(
    const blink::WebInputEvent& input_event,
    const ui::LatencyInfo& latency_info) {
    // Don't ignore touch cancel events, since they may be sent while input
  // events are being ignored in order to keep the renderer from getting
  // confused about how many touches are active.
  if (ShouldDropInputEvents() && input_event.GetType() != WebInputEvent::kTouchCancel)
    return common::INPUT_EVENT_ACK_STATE_NO_CONSUMER_EXISTS;

  if (!process_->HasConnection())
    return common::INPUT_EVENT_ACK_STATE_UNKNOWN;

  if (delegate_) {
    if (input_event.GetType() == WebInputEvent::kMouseDown ||
        input_event.GetType() == WebInputEvent::kTouchStart) {
      delegate_->FocusOwningApplicationContents(this);
    }
    delegate_->DidReceiveInputEvent(this, input_event.GetType());
  }

  return view_ ? view_->FilterInputEvent(input_event)
               : common::INPUT_EVENT_ACK_STATE_NOT_CONSUMED;
}

void ApplicationWindowHost::StopFling() {
  if (input_router_)
    input_router_->StopFling();
}

bool ApplicationWindowHost::FlingCancellationIsDeferred() const {
  if (input_router_)
    return input_router_->FlingCancellationIsDeferred();

  return false;
}

void ApplicationWindowHost::IncrementInFlightEventCount() {
  ++in_flight_event_count_;
  if (!is_hidden_)
    StartHangMonitorTimeout(hung_renderer_delay_);
}

void ApplicationWindowHost::DecrementInFlightEventCount(common::InputEventAckSource ack_source) {
   --in_flight_event_count_;
  if (in_flight_event_count_ <= 0) {
    // Cancel pending hung renderer checks since the renderer is responsive.
    StopHangMonitorTimeout();
  } else {
    // Only restart the hang monitor timer if we got a response from the
    // main thread.
    if (ack_source == common::InputEventAckSource::MAIN_THREAD)
      RestartHangMonitorTimeoutIfNecessary();
  }  
}

void ApplicationWindowHost::OnHasTouchEventHandlers(bool has_handlers) {
  has_touch_handler_ = has_handlers;
}

void ApplicationWindowHost::DidOverscroll(const ui::DidOverscrollParams& params) {
  if (view_)
    view_->DidOverscroll(params);
}

void ApplicationWindowHost::OnSetWhiteListedTouchAction(cc::TouchAction touch_action) {
  
}

void ApplicationWindowHost::DidStopFlinging() {
  is_in_touchpad_gesture_fling_ = false;
  if (view_)
    view_->DidStopFlinging();
}

void ApplicationWindowHost::DidStartScrollingViewport() {
  if (view_)
    view_->set_is_currently_scrolling_viewport(true);
}

void ApplicationWindowHost::SetNeedsBeginFrameForFlingProgress() {
  browser_fling_needs_begin_frame_ = true;
  SetNeedsBeginFrame(true);
}

void ApplicationWindowHost::SetNeedsBeginFrame(bool needs_begin_frames) {
  if (needs_begin_frames_ == needs_begin_frames)
    return;

  needs_begin_frames_ = needs_begin_frames || browser_fling_needs_begin_frame_;
  if (view_)
    view_->SetNeedsBeginFrames(needs_begin_frames_);
}

void ApplicationWindowHost::SetWantsAnimateOnlyBeginFrames() {
  //DLOG(INFO) << "ApplicationWindowHost::SetWantsAnimateOnlyBeginFrames";
  if (view_)
    view_->SetWantsAnimateOnlyBeginFrames();
}

void ApplicationWindowHost::SubmitCompositorFrame(
    const viz::LocalSurfaceId& local_surface_id,
    viz::CompositorFrame frame,
    viz::mojom::HitTestRegionListPtr hit_test_region_list,
    uint64_t submit_time) {
  TRACE_EVENT_FLOW_END0(TRACE_DISABLED_BY_DEFAULT("cc.debug.ipc"),
                        "SubmitCompositorFrame", local_surface_id.hash());

  // Ensure there are no CopyOutputRequests stowed-away in the CompositorFrame.
  // For security/privacy reasons, renderers are not allowed to make copy
  // requests because they could use this to gain access to content from another
  // domain (e.g., in a child frame).
  if (frame.HasCopyOutputRequests()) {
    bad_message::ReceivedBadMessage(GetProcess(),
                                    bad_message::RWH_COPY_REQUEST_ATTEMPT);
    return;
  }

  bool tracing_enabled;
  TRACE_EVENT_CATEGORY_GROUP_ENABLED(TRACE_DISABLED_BY_DEFAULT("cc.debug.ipc"),
                                     &tracing_enabled);
  if (tracing_enabled) {
    TimeDelta elapsed = clock_->NowTicks().since_origin() -
                        TimeDelta::FromMicroseconds(submit_time);
    TRACE_EVENT_INSTANT1(TRACE_DISABLED_BY_DEFAULT("cc.debug.ipc"),
                         "SubmitCompositorFrame::TimeElapsed",
                         TRACE_EVENT_SCOPE_THREAD,
                         "elapsed time:", elapsed.InMicroseconds());
  }
  auto new_surface_properties =
      common::ApplicationWindowSurfaceProperties::FromCompositorFrame(frame);

  if (local_surface_id == last_local_surface_id_ &&
      SurfacePropertiesMismatch(new_surface_properties,
                                last_surface_properties_)) {
    std::string error = base::StringPrintf(
        "[OOPIF? %d] %s\n", view_ && view_->IsApplicationWindowHostViewChildFrame(),
        new_surface_properties.ToDiffString(last_surface_properties_).c_str());
    LOG(ERROR) << "Surface invariants violation: " << error;

    static int invariants_violation_count = 0;
    ++invariants_violation_count;
    UMA_HISTOGRAM_COUNTS_1000("Compositing.SurfaceInvariantsViolations",
                              invariants_violation_count);

    if (features::IsSurfaceInvariantsViolationLoggingEnabled()) {
      static auto* crash_key = base::debug::AllocateCrashKeyString(
          "surface-invariants-violation", base::debug::CrashKeySize::Size256);
      base::debug::ScopedCrashKeyString key_value(crash_key, error);
      base::debug::DumpWithoutCrashing();
    }

    if (view_) {
      frame.metadata.begin_frame_ack.has_damage = false;
      view_->OnDidNotProduceFrame(frame.metadata.begin_frame_ack);
    }
    std::vector<viz::ReturnedResource> resources =
        viz::TransferableResource::ReturnResources(frame.resource_list);
    renderer_compositor_frame_sink_->DidReceiveCompositorFrameAck(resources);

    return;
  }

  last_local_surface_id_ = local_surface_id;
  last_surface_properties_ = new_surface_properties;

  last_received_content_source_id_ = frame.metadata.content_source_id;

  // |has_damage| is not transmitted.
  frame.metadata.begin_frame_ack.has_damage = true;

  last_frame_metadata_ = frame.metadata.Clone();

  bool is_mobile_optimized = false;//IsMobileOptimizedFrame(frame.metadata);
  input_router_->NotifySiteIsMobileOptimized(is_mobile_optimized);
  if (touch_emulator_)
    touch_emulator_->SetDoubleTapSupportForPageEnabled(!is_mobile_optimized);

  if (enable_surface_synchronization_) {
    if (view_) {
      // If Surface Synchronization is on, then |new_content_rendering_timeout_|
      // is stopped in DidReceiveFirstFrameAfterNavigation.
      view_->SubmitCompositorFrame(local_surface_id, std::move(frame),
                                   std::move(hit_test_region_list));
      view_->DidReceiveApplicationFrame();
    } else {
      std::vector<viz::ReturnedResource> resources =
          viz::TransferableResource::ReturnResources(frame.resource_list);
      renderer_compositor_frame_sink_->DidReceiveCompositorFrameAck(resources);
    }
  } else {
    // Ignore this frame if its content has already been unloaded. Source ID
    // is always zero for an OOPIF because we are only concerned with displaying
    // stale graphics on top-level frames. We accept frames that have a source
    // ID greater than |current_content_source_id_| because in some cases the
    // first compositor frame can arrive before the navigation commit message
    // that updates that value.
    if (view_ &&
        frame.metadata.content_source_id >= current_content_source_id_) {
      view_->SubmitCompositorFrame(local_surface_id, std::move(frame),
                                   std::move(hit_test_region_list));
      view_->DidReceiveApplicationFrame();
    } else {
      if (view_) {
        frame.metadata.begin_frame_ack.has_damage = false;
        view_->OnDidNotProduceFrame(frame.metadata.begin_frame_ack);
      }
      std::vector<viz::ReturnedResource> resources =
          viz::TransferableResource::ReturnResources(frame.resource_list);
      renderer_compositor_frame_sink_->DidReceiveCompositorFrameAck(resources);
    }

    // After navigation, if a frame belonging to the new page is received, stop
    // the timer that triggers clearing the graphics of the last page.
    if (last_received_content_source_id_ >= current_content_source_id_) {
      did_receive_first_frame_after_navigation_ = true;
      if (new_content_rendering_timeout_ &&
          new_content_rendering_timeout_->IsRunning()) {
        new_content_rendering_timeout_->Stop();
      }
    }
  }

  if (delegate_) {
    delegate_->DidReceiveCompositorFrame();
  }
}

void ApplicationWindowHost::DidNotProduceFrame(const viz::BeginFrameAck& ack) {
  ////DLOG(INFO) << "ApplicationWindowHost::DidNotProduceFrame";
  // |has_damage| is not transmitted.
  viz::BeginFrameAck modified_ack = ack;
  modified_ack.has_damage = false;

  if (view_)
    view_->OnDidNotProduceFrame(modified_ack);
}

void ApplicationWindowHost::DidAllocateSharedBitmap(
    mojo::ScopedSharedBufferHandle buffer,
    const viz::SharedBitmapId& id) {
  //DLOG(INFO) << "ApplicationWindowHost::DidAllocateSharedBitmap";
  if (!viz::ServerSharedBitmapManager::current()->ChildAllocatedSharedBitmap(
          std::move(buffer), id)) {
    bad_message::ReceivedBadMessage(GetProcess(),
                                    bad_message::RWH_SHARED_BITMAP);
  }
  owned_bitmaps_.insert(id);
}

void ApplicationWindowHost::DidDeleteSharedBitmap(
    const viz::SharedBitmapId& id) {
  //DLOG(INFO) << "ApplicationWindowHost::DidDeleteSharedBitmap";
  viz::ServerSharedBitmapManager::current()->ChildDeletedSharedBitmap(id);
  owned_bitmaps_.erase(id);
}

void ApplicationWindowHost::GetContentRenderingTimeoutFrom(
    ApplicationWindowHost* other) {
  if (other->new_content_rendering_timeout_ &&
      other->new_content_rendering_timeout_->IsRunning()) {
    new_content_rendering_timeout_->Start(
        other->new_content_rendering_timeout_->GetCurrentDelay());
  }
}

common::mojom::WindowInputHandler* ApplicationWindowHost::GetWindowInputHandler() {
  if (application_window_created_ && associated_widget_input_handler_) {
     return associated_widget_input_handler_.get();
  }
  if (widget_input_handler_) {
    return widget_input_handler_.get();
  }
  
  return g_unbound_input_handler.Pointer();
}

void ApplicationWindowHost::OnImeCancelComposition() {
  //DLOG(INFO) << "ApplicationWindowHost::OnImeCancelComposition";
  if (view_)
    view_->ImeCancelComposition();
}

void ApplicationWindowHost::OnInvalidFrameToken(uint32_t frame_token) {
  //DLOG(INFO) << "ApplicationWindowHost::OnInvalidFrameToken";
  bad_message::ReceivedBadMessage(GetProcess(),
                                  bad_message::RWH_INVALID_FRAME_TOKEN);
}

void ApplicationWindowHost::OnMessageDispatchError(const IPC::Message& message) {
  ApplicationProcessHost* aph = GetProcess();
  if (aph)
    aph->OnBadMessageReceived(message);
}

void ApplicationWindowHost::OnProcessSwapMessage(const IPC::Message& message) {
  //DLOG(INFO) << "ApplicationWindowHost::OnProcessSwapMessage";
  ApplicationProcessHost* aph = GetProcess();
  if (aph)
    aph->OnMessageReceived(message);
}

void ApplicationWindowHost::ProcessIgnoreInputEventsChanged(
    bool ignore_input_events) {
  if (ignore_input_events)
    StopHangMonitorTimeout();
  else
    RestartHangMonitorTimeoutIfNecessary();
}

void ApplicationWindowHost::SetAutoResize(bool enable,
                                          const gfx::Size& min_size,
                                          const gfx::Size& max_size) {
  auto_resize_enabled_ = enable;
  min_size_for_auto_resize_ = min_size;
  max_size_for_auto_resize_ = max_size;
}

void ApplicationWindowHost::DidProcessFrame(uint32_t frame_token) {
  frame_token_message_queue_->DidProcessFrame(frame_token);
}

void ApplicationWindowHost::ProgressFling(TimeTicks current_time) {
  browser_fling_needs_begin_frame_ = false;
  if (input_router_) {
    input_router_->ProgressFling(current_time);
  }
}

void ApplicationWindowHost::LayerTreeFrameSinkInitialized() {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowHost::LayerTreeFrameSinkInitializedImpl,
      weak_this_));
  //LayerTreeFrameSinkInitializedImpl();
}

void ApplicationWindowHost::LayerTreeFrameSinkInitializedImpl() {
  //DLOG(INFO) << "ApplicationWindowHost::LayerTreeFrameSinkInitializedImpl";
  //BeginNavigationImpl(delegate_->GetURL());
}

void ApplicationWindowHost::ResetSentVisualProperties() {
  visual_properties_ack_pending_ = false;
  old_visual_properties_.reset();
}

void ApplicationWindowHost::OnImeCompositionRangeChanged(
  const gfx::Range& range,
  const std::vector<gfx::Rect>& bounds) {
  //DLOG(INFO) << "ApplicationWindowHost::OnImeCompositionRangeChanged";  
  if (view_)
    view_->ImeCompositionRangeChanged(range, bounds);
}

void ApplicationWindowHost::ShowContextMenuAtPoint(
    const gfx::Point& point,
    const ui::MenuSourceType source_type) {
  //Send(new ViewMsg_ShowContextMenu(GetRoutingID(), source_type, point));
  
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendShowContextMenuAtPoint,
      io_weak_this_,
      static_cast<common::mojom::MenuSourceType>(source_type), 
      point)
  );
}

void ApplicationWindowHost::ForceFirstFrameAfterNavigationTimeout() {
  //DLOG(INFO) << "ApplicationWindowHost::ForceFirstFrameAfterNavigationTimeout";
  if (did_receive_first_frame_after_navigation_ ||
      !new_content_rendering_timeout_) {
    return;
  }
  new_content_rendering_timeout_->Stop();
  ClearDisplayedGraphics();
}

void ApplicationWindowHost::RequestCompositionUpdates(bool immediate_request,
                                                      bool monitor_updates) {
  //DLOG(INFO) << "ApplicationWindowHost::RequestCompositionUpdates";
  if (!immediate_request && monitor_updates == monitoring_composition_info_)
    return;

  monitoring_composition_info_ = monitor_updates;
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendRequestCompositionUpdates,
      io_weak_this_,
      immediate_request,
      monitor_updates)
  );
}

void ApplicationWindowHost::WindowCreatedAck() {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowHost::WindowCreatedAckImpl, weak_this_));
}

void ApplicationWindowHost::WindowCreatedAckImpl() {
  //DLOG(INFO) << "ApplicationWindowHost::WindowCreatedAckImpl";
  application_window_created_ = true;

#if defined(OS_POSIX) && !defined(OS_MACOSX) && !defined(OS_ANDROID)
  // Force a ViewMsg_Resize to be sent, needed to make plugins show up on
  // linux. See crbug.com/83941.
  SynchronizeVisualProperties();
#endif

  // send a first visual properties

  //std::unique_ptr<common::VisualProperties> params(new common::VisualProperties);
  //GetVisualProperties(params.get());
  //HostThread::PostTask(
  //  HostThread::IO, 
  //  FROM_HERE, 
  //  base::BindOnce(
  //    &common::mojom::ApplicationWindow::SynchronizeVisualProperties,
  //    base::Unretained(GetApplicationWindowInterface()),
  //    *params));
  // begin nav
  //BeginNavigation();
}

void ApplicationWindowHost::DidReceiveFirstFrameAfterNavigation() {
  DCHECK(enable_surface_synchronization_);
  //DLOG(INFO) << "ApplicationWindowHost::DidReceiveFirstFrameAfterNavigation";
  
  did_receive_first_frame_after_navigation_ = true;
  if (!new_content_rendering_timeout_ ||
      !new_content_rendering_timeout_->IsRunning()) {
    return;
  }
  new_content_rendering_timeout_->Stop();
}

void ApplicationWindowHost::ForwardMouseEvent(const blink::WebMouseEvent& mouse_event) {
  if (GetView()->IsInVR() &&
      (is_in_gesture_scroll_[blink::kWebGestureDeviceTouchpad] ||
       is_in_touchpad_gesture_fling_)) {
    return;
  }

  ForwardMouseEventWithLatencyInfo(mouse_event,
                                   ui::LatencyInfo(ui::SourceEventType::MOUSE));
  
  if (mouse_event.GetType() == WebInputEvent::kMouseWheel && ignore_input_events()) {
    delegate_->OnIgnoredUIEvent();
  }
}

void ApplicationWindowHost::ForwardMouseEventWithLatencyInfo(
    const blink::WebMouseEvent& mouse_event,
    const ui::LatencyInfo& latency) {
  DCHECK_GE(mouse_event.GetType(), blink::WebInputEvent::kMouseTypeFirst);
  DCHECK_LE(mouse_event.GetType(), blink::WebInputEvent::kMouseTypeLast);

  for (size_t i = 0; i < mouse_event_callbacks_.size(); ++i) {
    if (mouse_event_callbacks_[i].Run(mouse_event))
      return;
  }

  if (ShouldDropInputEvents()) {
    return;
  }

  if (touch_emulator_ && touch_emulator_->HandleMouseEvent(mouse_event)){
    return;
  }

  common::MouseEventWithLatencyInfo mouse_with_latency(mouse_event, latency);
  DispatchInputEventWithLatencyInfo(mouse_event, &mouse_with_latency.latency);
  input_router_->SendMouseEvent(mouse_with_latency);
}

void ApplicationWindowHost::ForwardWheelEvent(const blink::WebMouseWheelEvent& wheel_event) {
  ForwardWheelEventWithLatencyInfo(wheel_event,
                                   ui::LatencyInfo(ui::SourceEventType::WHEEL));
}

void ApplicationWindowHost::ForwardWheelEventWithLatencyInfo(
    const blink::WebMouseWheelEvent& wheel_event,
    const ui::LatencyInfo& latency) {
  if (ShouldDropInputEvents())
    return;

  if (touch_emulator_ && touch_emulator_->HandleMouseWheelEvent(wheel_event))
    return;

  common::MouseWheelEventWithLatencyInfo wheel_with_latency(wheel_event, latency);
  DispatchInputEventWithLatencyInfo(wheel_event, &wheel_with_latency.latency);
  input_router_->SendWheelEvent(wheel_with_latency);
}

//void ApplicationWindowHost::ForwardEmulatedGestureEvent(
//    const blink::WebGestureEvent& gesture_event) {
//  ForwardGestureEvent(gesture_event);
//}

resource_coordinator::FrameResourceCoordinator* ApplicationWindowHost::GetFrameResourceCoordinator() {
  if (frame_resource_coordinator_)
    return frame_resource_coordinator_.get();

  if (!resource_coordinator::IsResourceCoordinatorEnabled()) {
    frame_resource_coordinator_ =
        std::make_unique<resource_coordinator::FrameResourceCoordinator>(
            nullptr);
  } else {
    auto* connection = common::ServiceManagerConnection::GetForProcess();
    frame_resource_coordinator_ =
        std::make_unique<resource_coordinator::FrameResourceCoordinator>(
            connection ? connection->GetConnector() : nullptr);
  }
  return frame_resource_coordinator_.get();
}

bool ApplicationWindowHost::Send(IPC::Message* message) {
  //DLOG(INFO) << "ApplicationWindowHost::Send";
  //DLOG(ERROR) << "ApplicationWindowHost::Send: trying to use deprecated IPC Send";
  //application_window_host_binding_.channel()->Send(message);
  return false;
}

void ApplicationWindowHost::ForwardGestureEvent(
    const blink::WebGestureEvent& gesture_event) {
  ForwardGestureEventWithLatencyInfo(
      gesture_event,
      ui::WebInputEventTraits::CreateLatencyInfoForWebGestureEvent(
          gesture_event));
}

void ApplicationWindowHost::ForwardGestureEventWithLatencyInfo(
    const blink::WebGestureEvent& gesture_event,
    const ui::LatencyInfo& latency) {
  TRACE_EVENT1("input", "ApplicationWindowHost::ForwardGestureEvent", "type",
               WebInputEvent::GetName(gesture_event.GetType()));
  // Early out if necessary, prior to performing latency logic.
  if (ShouldDropInputEvents())
    return;

  bool scroll_update_needs_wrapping = false;
  if (gesture_event.GetType() == blink::WebInputEvent::kGestureScrollBegin) {
    // When a user starts scrolling while a fling is active, the GSB will arrive
    // when is_in_gesture_scroll_[gesture_event.SourceDevice()] is still true.
    // This is because the fling controller defers handling the GFC event
    // arrived before the GSB and doesn't send a GSE to end the fling; Instead,
    // it waits for a second GFS to arrive and boost the current active fling if
    // possible. While GFC handling is deferred the controller suppresses the
    // GSB and GSU events instead of sending them to the renderer and continues
    // to progress the fling. So, the renderer doesn't receive two GSB events
    // without any GSE in between.
    DCHECK(!is_in_gesture_scroll_[gesture_event.SourceDevice()] ||
           FlingCancellationIsDeferred());
    is_in_gesture_scroll_[gesture_event.SourceDevice()] = true;
  } else if (gesture_event.GetType() ==
             blink::WebInputEvent::kGestureScrollEnd) {
    DCHECK(is_in_gesture_scroll_[gesture_event.SourceDevice()]);
    is_in_gesture_scroll_[gesture_event.SourceDevice()] = false;
    is_in_touchpad_gesture_fling_ = false;
    if (view_)
      view_->set_is_currently_scrolling_viewport(false);
  } else if (gesture_event.GetType() ==
             blink::WebInputEvent::kGestureFlingStart) {
    if (gesture_event.SourceDevice() ==
        blink::WebGestureDevice::kWebGestureDeviceTouchpad) {
      // TODO(sahel): Remove the VR specific case when motion events are used
      // for Android VR event processing and VR touchpad scrolling is handled by
      // sending wheel events rather than directly injecting Gesture Scroll
      // Events. https://crbug.com/797322
      if (GetView()->IsInVR()) {
        // Regardless of the state of the wheel scroll latching
        // WebContentsEventForwarder doesn't inject any GSE events before GFS.
        DCHECK(is_in_gesture_scroll_[gesture_event.SourceDevice()]);

        // Reset the is_in_gesture_scroll since while scrolling in Android VR
        // the first wheel event sent by the FlingController will cause a GSB
        // generation in MouseWheelEventQueue. This is because GSU events before
        // the GFS are directly injected to RWHI rather than being generated
        // from wheel events in MouseWheelEventQueue.
        is_in_gesture_scroll_[gesture_event.SourceDevice()] = false;
      } else if (GetView()->wheel_scroll_latching_enabled()) {
        // When wheel scroll latching is enabled, no GSE is sent before GFS, so
        // is_in_gesture_scroll must be true.
        // TODO(sahel): This often gets tripped on Debug builds in ChromeOS
        // indicating some kind of gesture event ordering race.
        // https://crbug.com/821237.
        // DCHECK(is_in_gesture_scroll_[gesture_event.SourceDevice()]);

        // The FlingController handles GFS with touchpad source and sends wheel
        // events to progress the fling, the wheel events will get processed by
        // the MouseWheelEventQueue and GSU events with inertial phase will be
        // sent to the renderer. is_in_gesture_scroll must stay true till the
        // fling progress is finished. Then the FlingController will generate
        // and send a wheel event with phaseEnded. MouseWheelEventQueue will
        // process the wheel event to generate and send a GSE which shows the
        // end of a scroll sequence.
      } else {  // !GetView()->IsInVR() &&
                // !GetView()->wheel_scroll_latching_enabled()

        // When wheel scroll latching is disabled a GSE is sent before a GFS.
        // The GSE has already finished the scroll sequence.
        DCHECK(!is_in_gesture_scroll_[gesture_event.SourceDevice()]);
      }

      is_in_touchpad_gesture_fling_ = true;
    } else {
      DCHECK(is_in_gesture_scroll_[gesture_event.SourceDevice()]);

      // The FlingController handles GFS with touchscreen source and sends GSU
      // events with inertial state to the renderer to progress the fling.
      // is_in_gesture_scroll must stay true till the fling progress is
      // finished. Then the FlingController will generate and send a GSE which
      // shows the end of a scroll sequence and resets is_in_gesture_scroll_.
    }
  }

  // TODO(wjmaclean) Remove the code for supporting resending gesture events
  // when WebView transitions to OOPIF and BrowserPlugin is removed.
  // http://crbug.com/533069
  scroll_update_needs_wrapping =
      gesture_event.GetType() == blink::WebInputEvent::kGestureScrollUpdate &&
      gesture_event.resending_plugin_id != -1 &&
      !is_in_gesture_scroll_[gesture_event.SourceDevice()];

  // TODO(crbug.com/544782): Fix WebViewGuestScrollTest.TestGuestWheelScrolls-
  // Bubble to test the resending logic of gesture events.
  if (scroll_update_needs_wrapping) {
    ForwardGestureEventWithLatencyInfo(
        CreateScrollBeginForWrapping(gesture_event),
        ui::WebInputEventTraits::CreateLatencyInfoForWebGestureEvent(
            gesture_event));
  }

  // Delegate must be non-null, due to |ShouldDropInputEvents()| test.
  if (delegate_->PreHandleGestureEvent(gesture_event))
    return;
  ui::LatencyInfo local_latency(latency);
  local_latency.set_trace_id(++last_latency_id_);
  common::GestureEventWithLatencyInfo gesture_with_latency(gesture_event, local_latency);
  DispatchInputEventWithLatencyInfo(gesture_event,
                                    &gesture_with_latency.latency);
  input_router_->SendGestureEvent(gesture_with_latency);

  if (scroll_update_needs_wrapping) {
    ForwardGestureEventWithLatencyInfo(
        CreateScrollEndForWrapping(gesture_event),
        ui::WebInputEventTraits::CreateLatencyInfoForWebGestureEvent(
            gesture_event));
  }
}

//void ApplicationWindowHost::ForwardEmulatedTouchEvent(
//      const blink::WebTouchEvent& touch_event) {
//  TRACE_EVENT0("input", "ApplicationWindowHost::ForwardEmulatedTouchEvent");
//  ui::LatencyInfo latency_info(ui::SourceEventType::TOUCH);
//  common::TouchEventWithLatencyInfo touch_with_latency(touch_event, latency_info);
//  DispatchInputEventWithLatencyInfo(touch_event, &touch_with_latency.latency);
//  input_router_->SendTouchEvent(touch_with_latency);
//}

void ApplicationWindowHost::ForwardTouchEventWithLatencyInfo(
    const blink::WebTouchEvent& touch_event,
    const ui::LatencyInfo& latency) {
  TRACE_EVENT0("input", "ApplicationWindowHost::ForwardTouchEvent");

  // Always forward TouchEvents for touch stream consistency. They will be
  // ignored if appropriate in FilterInputEvent().

  common::TouchEventWithLatencyInfo touch_with_latency(touch_event, latency);
  if (touch_emulator_ &&
      touch_emulator_->HandleTouchEvent(touch_with_latency.event)) {
    if (view_) {
      view_->ProcessAckedTouchEvent(
          touch_with_latency, common::INPUT_EVENT_ACK_STATE_CONSUMED);
    }
    return;
  }

  DispatchInputEventWithLatencyInfo(touch_event, &touch_with_latency.latency);
  input_router_->SendTouchEvent(touch_with_latency);
}

void ApplicationWindowHost::DispatchInputEventWithLatencyInfo(
    const blink::WebInputEvent& event,
    ui::LatencyInfo* latency) {
  latency_tracker_.OnInputEvent(event, latency);
  for (auto& observer : input_event_observers_)
    observer.OnInputEvent(event);
}

void ApplicationWindowHost::ForwardKeyboardEvent(const NativeWebKeyboardEvent& key_event) {
  ui::LatencyInfo latency_info;

  if (key_event.GetType() == WebInputEvent::kRawKeyDown ||
      key_event.GetType() == WebInputEvent::kChar) {
    latency_info.set_source_event_type(ui::SourceEventType::KEY_PRESS);
  }
  ForwardKeyboardEventWithLatencyInfo(key_event, latency_info);
}

void ApplicationWindowHost::ForwardKeyboardEventWithLatencyInfo(
    const NativeWebKeyboardEvent& key_event,
    const ui::LatencyInfo& latency) {
  ForwardKeyboardEventWithCommands(key_event, latency, nullptr, nullptr);
}

void ApplicationWindowHost::ForwardKeyboardEventWithCommands(
    const NativeWebKeyboardEvent& key_event,
    const ui::LatencyInfo& latency,
    const std::vector<common::EditCommand>* commands,
    bool* update_event) {
  //DLOG(INFO) << "ApplicationWindowHost::ForwardKeyboardEventWithCommands";
  //DLOG(INFO) << "  KeyUp ? " << (key_event.GetType() == WebKeyboardEvent::kKeyUp ? "true" : "false");
  //DLOG(INFO) << "  Char ? " << (key_event.GetType() == WebKeyboardEvent::kChar ? "true" : "false");
  //DLOG(INFO) << "  RawKeyDown ? " << (key_event.GetType() == WebKeyboardEvent::kRawKeyDown ? "true" : "false");
  //DLOG(INFO) << "  KeyDown ? " << (key_event.GetType() == WebKeyboardEvent::kKeyDown ? "true" : "false");
  DCHECK(process_);
  TRACE_EVENT0("input", "ApplicationWindowHost::ForwardKeyboardEvent");
 
  if (ignore_input_events()) {
    if (key_event.GetType() == WebInputEvent::kRawKeyDown) {
      delegate_->OnIgnoredUIEvent();
    }
    //DLOG(INFO) << "  IgnoreInputEvents = true. cancelling";
    return;
  }

  if (ShouldDropInputEvents()) {
    //DLOG(INFO) << "  ShouldDropInputEvents = true. cancelling";
    return;
  }

  if (!process_->HasConnection()) {
    //DLOG(INFO) << "  process_->HasConnection() = false. cancelling";
    return;
  }

  // First, let keypress listeners take a shot at handling the event.  If a
  // listener handles the event, it should not be propagated to the renderer.
  if (KeyPressListenersHandleEvent(key_event)) {
    //DLOG(INFO) << "  KeyPressListenersHandleEvent() = true. cancelling";
    // Some keypresses that are accepted by the listener may be followed by Char
    // and KeyUp events, which should be ignored.
    if (key_event.GetType() == WebKeyboardEvent::kRawKeyDown) {
      //DLOG(INFO) << "  KeyPressListenersHandleEvent() = true && RawKeyDown -> suppress_events_until_keydown_ = true ";
      suppress_events_until_keydown_ = true;
    }
    return;
  }

  // Double check the type to make sure caller hasn't sent us nonsense that
  // will mess up our key queue.
  if (!WebInputEvent::IsKeyboardEventType(key_event.GetType())) {
    //DLOG(INFO) << "  IsKeyboardEventType() = false. cancelling";
    return;
  }

  if (suppress_events_until_keydown_) {
    //DLOG(INFO) << "  suppress_events_until_keydown_ = true";
    // If the preceding RawKeyDown event was handled by the browser, then we
    // need to suppress all events generated by it until the next RawKeyDown or
    // KeyDown event.
    if (key_event.GetType() == WebKeyboardEvent::kKeyUp ||
        key_event.GetType() == WebKeyboardEvent::kChar) {
      //DLOG(INFO) << "  suppress_events_until_keydown_ & KeyUp || Char = true. cancelling";
      return;
    }
    DCHECK(key_event.GetType() == WebKeyboardEvent::kRawKeyDown ||
           key_event.GetType() == WebKeyboardEvent::kKeyDown);
    //DLOG(INFO) << "  setting suppress_events_until_keydown_ = false";
    suppress_events_until_keydown_ = false;
  }

  bool is_shortcut = false;

  // Only pre-handle the key event if it's not handled by the input method.
  if (delegate_ && !key_event.skip_in_browser) {
    //DLOG(INFO) << "  delegate_ && key_event.skip_in_browser = false";
    // We need to set |suppress_events_until_keydown_| to true if
    // PreHandleKeyboardEvent() handles the event, but |this| may already be
    // destroyed at that time. So set |suppress_events_until_keydown_| true
    // here, then revert it afterwards when necessary.
    if (key_event.GetType() == WebKeyboardEvent::kRawKeyDown) {
      //DLOG(INFO) << "  RawKeyDown event -> suppress_events_until_keydown_ = true";
      suppress_events_until_keydown_ = true;
    }

    // Tab switching/closing accelerators aren't sent to the renderer to avoid
    // a hung/malicious renderer from interfering.
    switch (delegate_->PreHandleKeyboardEvent(key_event)) {
      case KeyboardEventProcessingResult::HANDLED:
        //DLOG(INFO) << "  delegate_->PreHandleKeyboardEvent(key_event) -> HANDLED. cancelling send";
        return;
#if defined(USE_AURA)
      case KeyboardEventProcessingResult::HANDLED_DONT_UPDATE_EVENT:
        if (update_event)
          *update_event = false;
        //DLOG(INFO) << "  delegate_->PreHandleKeyboardEvent(key_event) -> HANDLED_DONT_UPDATE_EVENT. cancelling send";
        return;
#endif
      case KeyboardEventProcessingResult::NOT_HANDLED:
        //DLOG(INFO) << "  delegate_->PreHandleKeyboardEvent(key_event) -> NOT_HANDLED";        
        break;
      case KeyboardEventProcessingResult::NOT_HANDLED_IS_SHORTCUT:
        //DLOG(INFO) << "  delegate_->PreHandleKeyboardEvent(key_event) -> NOT_HANDLED_IS_SHORTCUT";
        is_shortcut = true;
        break;
    }

    if (key_event.GetType() == WebKeyboardEvent::kRawKeyDown) {
      //DLOG(INFO) << "  RawKeyDown event -> suppress_events_until_keydown_ = false";
      suppress_events_until_keydown_ = false;
    }
  }

  if (touch_emulator_ && touch_emulator_->HandleKeyboardEvent(key_event)) {
    //DLOG(INFO) << "  touch_emulator_->HandleKeyboardEvent() = true. cancelling";
    return;
  }
  NativeWebKeyboardEventWithLatencyInfo key_event_with_latency(key_event,
                                                               latency);
  //DLOG(INFO) << "  is_shortcut ? " << is_shortcut;
  key_event_with_latency.event.is_browser_shortcut = is_shortcut;
  DispatchInputEventWithLatencyInfo(key_event, &key_event_with_latency.latency);
  // TODO(foolip): |InputRouter::SendKeyboardEvent()| may filter events, in
  // which the commands will be treated as belonging to the next key event.
  // WindowInputHandler::SetEditCommandsForNextKeyEvent should only be sent if
  // WindowInputHandler::DispatchEvent is, but has to be sent first.
  // https://crbug.com/684298
  if (commands && !commands->empty() && GetWindowInputHandler()) {
    //DLOG(INFO) << "  mojo::WindowInputHandler::SetEditCommandsForNextKeyEvent()";
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE, 
      base::BindOnce(
        &ApplicationWindowHost::SendSetEditCommandsForNextKeyEvent,
        io_weak_this_,
        *commands)
    );
  }
  //DLOG(INFO) << "  input_router_->SendKeyboardEvent()";
  input_router_->SendKeyboardEvent(key_event_with_latency);
}

// void ApplicationWindowHost::ForwardGestureEvent(const blink::WebGestureEvent& gesture_event) {
//   ForwardGestureEventWithLatencyInfo(
//       gesture_event,
//       ui::WebInputEventTraits::CreateLatencyInfoForWebGestureEvent(
//           gesture_event));
// }

// void ApplicationWindowHost::ForwardGestureEventWithLatencyInfo(
//     const blink::WebGestureEvent& gesture_event,
//     const ui::LatencyInfo& latency) {
//   // Early out if necessary, prior to performing latency logic.
//   if (ShouldDropInputEvents())
//     return;

//   bool scroll_update_needs_wrapping = false;
//   if (gesture_event.GetType() == blink::WebInputEvent::kGestureScrollBegin) {
//     // When a user starts scrolling while a fling is active, the GSB will arrive
//     // when is_in_gesture_scroll_[gesture_event.SourceDevice()] is still true.
//     // This is because the fling controller defers handling the GFC event
//     // arrived before the GSB and doesn't send a GSE to end the fling; Instead,
//     // it waits for a second GFS to arrive and boost the current active fling if
//     // possible. While GFC handling is deferred the controller suppresses the
//     // GSB and GSU events instead of sending them to the renderer and continues
//     // to progress the fling. So, the renderer doesn't receive two GSB events
//     // without any GSE in between.
//     DCHECK(!is_in_gesture_scroll_[gesture_event.SourceDevice()] ||
//            FlingCancellationIsDeferred());
//     is_in_gesture_scroll_[gesture_event.SourceDevice()] = true;
//   } else if (gesture_event.GetType() ==
//              blink::WebInputEvent::kGestureScrollEnd) {
//     DCHECK(is_in_gesture_scroll_[gesture_event.SourceDevice()]);
//     is_in_gesture_scroll_[gesture_event.SourceDevice()] = false;
//     is_in_touchpad_gesture_fling_ = false;
//     if (view_)
//       view_->set_is_currently_scrolling_viewport(false);
//   } else if (gesture_event.GetType() ==
//              blink::WebInputEvent::kGestureFlingStart) {
//     if (gesture_event.SourceDevice() ==
//         blink::WebGestureDevice::kWebGestureDeviceTouchpad) {
//       // TODO(sahel): Remove the VR specific case when motion events are used
//       // for Android VR event processing and VR touchpad scrolling is handled by
//       // sending wheel events rather than directly injecting Gesture Scroll
//       // Events. https://crbug.com/797322
//       if (GetView()->IsInVR()) {
//         // Regardless of the state of the wheel scroll latching
//         // WebContentsEventForwarder doesn't inject any GSE events before GFS.
//         DCHECK(is_in_gesture_scroll_[gesture_event.SourceDevice()]);

//         // Reset the is_in_gesture_scroll since while scrolling in Android VR
//         // the first wheel event sent by the FlingController will cause a GSB
//         // generation in MouseWheelEventQueue. This is because GSU events before
//         // the GFS are directly injected to RWHI rather than being generated
//         // from wheel events in MouseWheelEventQueue.
//         is_in_gesture_scroll_[gesture_event.SourceDevice()] = false;
//       } else if (GetView()->wheel_scroll_latching_enabled()) {
//         // When wheel scroll latching is enabled, no GSE is sent before GFS, so
//         // is_in_gesture_scroll must be true.
//         // TODO(sahel): This often gets tripped on Debug builds in ChromeOS
//         // indicating some kind of gesture event ordering race.
//         // https://crbug.com/821237.
//         // DCHECK(is_in_gesture_scroll_[gesture_event.SourceDevice()]);

//         // The FlingController handles GFS with touchpad source and sends wheel
//         // events to progress the fling, the wheel events will get processed by
//         // the MouseWheelEventQueue and GSU events with inertial phase will be
//         // sent to the renderer. is_in_gesture_scroll must stay true till the
//         // fling progress is finished. Then the FlingController will generate
//         // and send a wheel event with phaseEnded. MouseWheelEventQueue will
//         // process the wheel event to generate and send a GSE which shows the
//         // end of a scroll sequence.
//       } else {  // !GetView()->IsInVR() &&
//                 // !GetView()->wheel_scroll_latching_enabled()

//         // When wheel scroll latching is disabled a GSE is sent before a GFS.
//         // The GSE has already finished the scroll sequence.
//         DCHECK(!is_in_gesture_scroll_[gesture_event.SourceDevice()]);
//       }

//       is_in_touchpad_gesture_fling_ = true;
//     } else {
//       DCHECK(is_in_gesture_scroll_[gesture_event.SourceDevice()]);

//       // The FlingController handles GFS with touchscreen source and sends GSU
//       // events with inertial state to the renderer to progress the fling.
//       // is_in_gesture_scroll must stay true till the fling progress is
//       // finished. Then the FlingController will generate and send a GSE which
//       // shows the end of a scroll sequence and resets is_in_gesture_scroll_.
//     }
//   }

//   // TODO(wjmaclean) Remove the code for supporting resending gesture events
//   // when WebView transitions to OOPIF and BrowserPlugin is removed.
//   // http://crbug.com/533069
//   scroll_update_needs_wrapping =
//       gesture_event.GetType() == blink::WebInputEvent::kGestureScrollUpdate &&
//       gesture_event.resending_plugin_id != -1 &&
//       !is_in_gesture_scroll_[gesture_event.SourceDevice()];

//   // TODO(crbug.com/544782): Fix WebViewGuestScrollTest.TestGuestWheelScrolls-
//   // Bubble to test the resending logic of gesture events.
//   if (scroll_update_needs_wrapping) {
//     ForwardGestureEventWithLatencyInfo(
//         CreateScrollBeginForWrapping(gesture_event),
//         ui::WebInputEventTraits::CreateLatencyInfoForWebGestureEvent(
//             gesture_event));
//   }

//   // Delegate must be non-null, due to |ShouldDropInputEvents()| test.
//   if (delegate_->PreHandleGestureEvent(gesture_event))
//     return;

//   common::GestureEventWithLatencyInfo gesture_with_latency(gesture_event, latency);
//   DispatchInputEventWithLatencyInfo(gesture_event,
//                                     &gesture_with_latency.latency);
//   input_router_->SendGestureEvent(gesture_with_latency);

//   if (scroll_update_needs_wrapping) {
//     ForwardGestureEventWithLatencyInfo(
//         CreateScrollEndForWrapping(gesture_event),
//         ui::WebInputEventTraits::CreateLatencyInfoForWebGestureEvent(
//             gesture_event));
//   }
// }

Application* ApplicationWindowHost::GetApplication() const {
  return application_;
}

ApplicationProcessHost* ApplicationWindowHost::GetProcess() const {
  return process_;
}

int ApplicationWindowHost::GetRoutingID() const {
  return routing_id_;
}

ApplicationWindowHostView* ApplicationWindowHost::GetView() const {
  return view_.get();
}

bool ApplicationWindowHost::IsLoading() const {
  return is_loading_;
}

bool ApplicationWindowHost::IsCurrentlyUnresponsive() const {
  return is_unresponsive_;
}

void ApplicationWindowHost::SetIgnoreInputEvents(bool ignore_input_events) {
  //DLOG(INFO) << "ApplicationWindowHost::SetIgnoreInputEvents";
  ignore_input_events_ = ignore_input_events;
}

void ApplicationWindowHost::SynchronizeVisualProperties() {
  SynchronizeVisualProperties(false);
}

void ApplicationWindowHost::WasShown(const ui::LatencyInfo& latency_info) {
  //DLOG(INFO) << "\n\n** ApplicationWindowHost::WasShown **\n\n";
  if (!is_hidden_)
    return;

  TRACE_EVENT0("renderer_host", "RenderWidgetHostImpl::WasShown");
  is_hidden_ = false;

  // If we navigated in background, clear the displayed graphics of the
  // previous page before going visible.
  ForceFirstFrameAfterNavigationTimeout();

  SendScreenRects();
  RestartHangMonitorTimeoutIfNecessary();

  // Always repaint on restore.
  bool needs_repainting = true;
  needs_repainting_on_restore_ = false;
  
  //Send(new ViewMsg_WasShown(routing_id_, needs_repainting, latency_info));
  
  // on the first send, io_weak_this_ is not setup
  // because this is triggered too early
  // (maybe spot a earlier way to create io_weak_this_)    
  if (is_first_was_shown_) {
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE, 
      base::BindOnce(
        &ApplicationWindowHost::SendWasShown,
        base::Unretained(this),
        latency_info,
        needs_repainting)
    );
  } else {
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE, 
      base::BindOnce(
        &ApplicationWindowHost::SendWasShown,
        io_weak_this_, 
        latency_info,
        needs_repainting)
    );
  }
//  process_->UpdateClientPriority(this);

  bool is_visible = true;
  NotificationService::current()->Notify(
      NOTIFICATION_RENDER_WIDGET_VISIBILITY_CHANGED,
      Source<ApplicationWindowHost>(this),
      Details<bool>(&is_visible));
  for (auto& observer : observers_)
    observer.ApplicationWindowHostVisibilityChanged(this, true);

  // It's possible for our size to be out of sync with the renderer. The
  // following is one case that leads to this:
  // 1. SynchronizeVisualProperties -> Send ViewMsg_SynchronizeVisualProperties
  //    to render.
  // 2. SynchronizeVisualProperties -> do nothing as
  //    sync_visual_props_ack_pending_ is true
  // 3. WasHidden
  // 4. OnResizeOrRepaintACK from (1) processed. Does NOT invoke
  //    SynchronizeVisualProperties as view is hidden. Now renderer/browser out
  //    of sync with what they think size is.
  // By invoking SynchronizeVisualProperties the renderer is updated as
  // necessary. SynchronizeVisualProperties does nothing if the sizes are
  // already in sync.
  //
  // TODO: ideally ViewMsg_WasShown would take a size. This way, the renderer
  // could handle both the restore and resize at once. This isn't that big a
  // deal as RenderWidget::WasShown delays updating, so that the resize from
  // SynchronizeVisualProperties is usually processed before the renderer is
  // painted.
  SynchronizeVisualProperties();
  if (is_first_was_shown_)
    is_first_was_shown_ = false;
}

void ApplicationWindowHost::SendCursorVisibilityState(bool is_visible) {
  //DLOG(INFO) << "ApplicationWindowHost::SendCursorVisibilityState " << is_visible;
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendCursorVisibilityChanged,
      io_weak_this_,
      is_visible)
  );
}

void ApplicationWindowHost::SynchronizeVisualProperties(
    bool scroll_focused_node_into_view) {
  //DLOG(INFO) << "ApplicationWindowHost::SynchronizeVisualProperties(bool)";
  DCHECK(process_);
  // Skip if the |delegate_| has already been detached because
  // it's web contents is being deleted.
  if (resize_ack_pending_ || !process_->HasConnection() || !view_ ||
      !view_->HasSize() || !application_initialized_ || !delegate_) {
    return;
  }

  std::unique_ptr<common::VisualProperties> params(new common::VisualProperties);
  if (!GetVisualProperties(params.get()))
    return;

  params->scroll_focused_node_into_view = scroll_focused_node_into_view;

  common::ScreenInfo screen_info = params->screen_info;
  bool width_changed =
      !old_visual_properties_ ||
      old_visual_properties_->new_size.width() != params->new_size.width();

  common::VisualProperties properties_copy(*params);
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendSynchronizeVisualProperties,
      io_weak_this_/*io_weak_this_*/,
      base::Passed(std::move(properties_copy))));
  
  //if (Send(new ViewMsg_SynchronizeVisualProperties(routing_id_, *params))) {
  resize_ack_pending_ = params->needs_resize_ack;
  next_resize_needs_resize_ack_ = false;
  old_visual_properties_.swap(params);
  //}

  if (delegate_)
    delegate_->ApplicationWindowWasResized(this, screen_info, width_changed);
}

void ApplicationWindowHost::WasHidden() {
  //DLOG(INFO) << "\n\n ** ApplicationWindowHost::WasHidden ** \n\n";
  if (is_hidden_)
    return;

  RejectMouseLockOrUnlockIfNecessary();

  TRACE_EVENT0("renderer_host", "RenderWidgetHostImpl::WasHidden");
  is_hidden_ = true;

  // Don't bother reporting hung state when we aren't active.
  StopHangMonitorTimeout();

  // If we have a renderer, then inform it that we are being hidden so it can
  // reduce its resource utilization.
  //Send(new ViewMsg_WasHidden(routing_id_));
  HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE, 
      base::BindOnce(
        &ApplicationWindowHost::SendWasHidden,
        io_weak_this_)
  );

  // Tell the RenderProcessHost we were hidden.
  //process_->UpdateClientPriority(this);

  bool is_visible = false;
  NotificationService::current()->Notify(
      NOTIFICATION_RENDER_WIDGET_VISIBILITY_CHANGED,
      Source<ApplicationWindowHost>(this),
      Details<bool>(&is_visible));
  for (auto& observer : observers_)
    observer.ApplicationWindowHostVisibilityChanged(this, false);
}

void ApplicationWindowHost::SetBackgroundOpaque(bool opaque) {
  //DLOG(INFO) << "ApplicationWindowHost::SetBackgroundOpaque";
  //Send(new ViewMsg_SetBackgroundOpaque(GetRoutingID(), opaque));
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendSetBackgroundOpaque,
      io_weak_this_/*io_weak_this_*/,
      opaque)
  );
}

void ApplicationWindowHost::LostCapture() {
  //DLOG(INFO) << "ApplicationWindowHost::LostCapture";
  if (touch_emulator_)
    touch_emulator_->CancelTouch();

  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE,
    base::BindOnce(
      &ApplicationWindowHost::SendMouseCaptureLost,
      io_weak_this_)
  );

  if (delegate_)
    delegate_->LostCapture(this);
}

void ApplicationWindowHost::AddKeyPressEventCallback(const KeyPressEventCallback& callback) {
  key_press_event_callbacks_.push_back(callback);
}

void ApplicationWindowHost::RemoveKeyPressEventCallback(const KeyPressEventCallback& callback) {
  for (size_t i = 0; i < key_press_event_callbacks_.size(); ++i) {
    if (key_press_event_callbacks_[i].Equals(callback)) {
      key_press_event_callbacks_.erase(
          key_press_event_callbacks_.begin() + i);
      return;
    }
  }
}

void ApplicationWindowHost::AddMouseEventCallback(const MouseEventCallback& callback) {
  mouse_event_callbacks_.push_back(callback);
}

void ApplicationWindowHost::RemoveMouseEventCallback(const MouseEventCallback& callback) {
  for (size_t i = 0; i < mouse_event_callbacks_.size(); ++i) {
    if (mouse_event_callbacks_[i].Equals(callback)) {
      mouse_event_callbacks_.erase(mouse_event_callbacks_.begin() + i);
      return;
    }
  }
}

void ApplicationWindowHost::AddInputEventObserver(InputEventObserver* observer) {
  if (!input_event_observers_.HasObserver(observer))
    input_event_observers_.AddObserver(observer);
}

void ApplicationWindowHost::RemoveInputEventObserver(InputEventObserver* observer) {
  input_event_observers_.RemoveObserver(observer);
}

void ApplicationWindowHost::AddObserver(ApplicationWindowHostObserver* observer) {
  observers_.AddObserver(observer);
}

void ApplicationWindowHost::RemoveObserver(ApplicationWindowHostObserver* observer) {
  observers_.RemoveObserver(observer);
}

void ApplicationWindowHost::GetScreenInfo(common::ScreenInfo* result) {
  if (view_)
    view_->GetScreenInfo(result);
  else
    DisplayUtil::GetDefaultScreenInfo(result);

  // TODO(sievers): find a way to make this done another way so the method
  // can be const.
  if (IsUseZoomForDSFEnabled())
    input_router_->SetDeviceScaleFactor(result->device_scale_factor);
}

void ApplicationWindowHost::DragTargetDragEnter(
                         const common::DropData& drop_data,
                         const gfx::PointF& client_pt,
                         const gfx::PointF& screen_pt,
                         blink::WebDragOperationsMask operations_allowed,
                         int key_modifiers) {
  DragTargetDragEnterWithMetaData(DropDataToMetaData(drop_data), client_pt,
                                  screen_pt, operations_allowed, key_modifiers);
}

void ApplicationWindowHost::DragTargetDragEnterWithMetaData(
    std::vector<common::DropDataMetadata> metadata,
    const gfx::PointF& client_pt,
    const gfx::PointF& screen_pt,
    blink::WebDragOperationsMask operations_allowed,
    int key_modifiers) {
  if (GetApplicationWindowInterface()) {    
    GetApplicationWindowInterface()->DragTargetDragEnter(
      std::move(metadata), 
      client_pt,
      screen_pt, 
      operations_allowed,
      key_modifiers);
  }
  //Send(new DragMsg_TargetDragEnter(GetRoutingID(), metadata, client_pt,
  //                                 screen_pt, operations_allowed,
  //                                 key_modifiers));
}

void ApplicationWindowHost::DragTargetDragOver(
  const gfx::PointF& client_pt,
  const gfx::PointF& screen_pt,
  blink::WebDragOperationsMask operations_allowed,
  int key_modifiers) {
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendDragTargetDragOver,
      io_weak_this_/*io_weak_this_*/,
      client_pt, 
      screen_pt,
      operations_allowed, 
      key_modifiers)
  );
 
  //Send(new DragMsg_TargetDragOver(GetRoutingID(), client_pt, screen_pt,
  //                                operations_allowed, key_modifiers));
}

void ApplicationWindowHost::DragTargetDragLeave(
  const gfx::PointF& client_point,
  const gfx::PointF& screen_point) {
  
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendDragTargetDragLeave,
      io_weak_this_/*io_weak_this_*/,
      client_point, screen_point)
  );
  //Send(new DragMsg_TargetDragLeave(GetRoutingID(), client_point, screen_point));
}

// |drop_data| must have been filtered. The embedder should call
// FilterDropData before passing the drop data to RWHI.

void ApplicationWindowHost::DragTargetDrop(
  const common::DropData& drop_data,
  const gfx::PointF& client_pt,
  const gfx::PointF& screen_pt,
  int key_modifiers) {
  
  common::DropData drop_data_with_permissions(drop_data);
  //GrantFileAccessFromDropData(&drop_data_with_permissions);  
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendDragTargetDrop,
      io_weak_this_/*io_weak_this_*/,
      drop_data_with_permissions,
      client_pt, 
      screen_pt, 
      key_modifiers)
  );
}

void ApplicationWindowHost::DragSourceEndedAt(
  const gfx::PointF& client_pt,
  const gfx::PointF& screen_pt,
  blink::WebDragOperation operation) {

  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendDragSourceEnded,
      io_weak_this_/*io_weak_this_*/,
      client_pt,
      screen_pt,
      operation)
  );  
  
  //Send(new DragMsg_SourceEnded(GetRoutingID(),
  //                             client_pt,
  //                             screen_pt,
  //                             operation));
}

void ApplicationWindowHost::DragSourceSystemDragEnded() {
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendDragSourceSystemDragEnded,
      io_weak_this_/*io_weak_this_*/)
  );
  //Send(new DragMsg_SourceSystemDragEnded(GetRoutingID()));
}

void ApplicationWindowHost::FilterDropData(common::DropData* drop_data) {
#if DCHECK_IS_ON()
  drop_data->view_id = GetRoutingID();
#endif  // DCHECK_IS_ON()

  //GetProcess()->FilterURL(true, &drop_data->url);
  if (drop_data->did_originate_from_renderer) {
    drop_data->filenames.clear();
  }
}

void ApplicationWindowHost::NotifyScreenInfoChanged() {
  ////DLOG(INFO) << "ApplicationWindowHost::NotifyScreenInfoChanged";
  SynchronizeVisualProperties();

  if (touch_emulator_) {
    touch_emulator_->SetDeviceScaleFactor(GetScaleFactorForView(view_.get()));
  }
}

/*
 * end ApplicationWindowHost section
 */

void ApplicationWindowHost::ApplicationProcessGone(int32_t status, int32_t exit_code) {
  //DLOG(INFO) << "ApplicationWindowHost::ApplicationProcessGone";
  visual_state_callbacks_.clear();
  // ApplicationWindowHost::OnRenderProcessGone
  
  in_content_audio_output_stream_factory_.reset();

  if (!is_active()) {
    // If the process has died, we don't need to wait for the swap out ack from
    // this RenderFrame if it is pending deletion.  Complete the swap out to
    // destroy it.
    OnSwappedOut();
  } else {
    // If this was the current pending or speculative RFH dying, cancel and
    // destroy it.
    //frame_tree_node_->render_manager()->CancelPendingIfNecessary(this);
    CancelPendingIfNecessary();
  }
  // ** burp burp **
  // ApplicationWindowHost
  //if (!owned_by_render_frame_host_) {
    // TODO(evanm): This synchronously ends up calling "delete this".
    // Is that really what we want in response to this message?  I'm matching
    // previous behavior of the code here.
    Destroy(true);
  //} else {
  //  ApplicationExited(static_cast<base::TerminationStatus>(status), exit_code);
  //}

}

void ApplicationWindowHost::CancelPendingIfNecessary() {
  //DLOG(INFO) << "ApplicationWindowHost::CancelPendingIfNecessary";
  if (speculative_application_frame_) {
    bool was_loading = speculative_application_frame_->GetWindow()->IsLoading();
    DiscardUnusedFrame(UnsetSpeculativeApplicationFrame());
    if (was_loading) {
      DidStopLoading();
    }
  }
}

std::unique_ptr<ApplicationFrame> ApplicationWindowHost::UnsetSpeculativeApplicationFrame() {
  //speculative_application_frame_->GetProcess()->RemovePendingWindow();
  return std::move(speculative_application_frame_);
}

void ApplicationWindowHost::DiscardUnusedFrame(
  std::unique_ptr<ApplicationFrame> app_frame_state) {
 //DLOG(INFO) << "ApplicationWindowHost::DiscardUnusedFrame";
 ApplicationWindowHost* awh = app_frame_state->GetWindow();
 bool is_main_frame = true;
 // SiteInstanceImpl* site_instance = render_frame_host->GetSiteInstance();
 // RenderViewHostImpl* rvh = render_frame_host->render_view_host();
 // RenderFrameProxyHost* proxy = nullptr;
 // if (site_instance->HasSite() && site_instance->active_frame_count() > 1) {
    // If a proxy already exists for the |site_instance|, just reuse it instead
    // of creating a new one. There is no need to call SwapOut on the
    // |render_frame_host|, as this method is only called to discard a pending
    // or speculative RenderFrameHost, i.e. one that has never hosted an actual
    // document.
 //   proxy = GetRenderFrameProxyHost(site_instance);
 //   if (!proxy)
 //     proxy = CreateRenderFrameProxyHost(site_instance, rvh);
 // }

  // Doing this is important in the case where the replacement proxy is created
  // above, as the RenderViewHost will continue to exist and should be
  // considered swapped out if it is ever reused.  When there's no replacement
  // proxy, this doesn't really matter, as the RenderViewHost will be destroyed
  // shortly, since |render_frame_host| is its last active frame and will be
  // deleted below.  See https://crbug.com/627400.
  if (is_main_frame) {
    //awh->set_main_frame_routing_id(MSG_ROUTING_NONE);
    awh->SetIsActive(false);
    awh->set_is_swapped_out(true);
  }

  //render_frame_host.reset();
  // TODO: see what side-effects theres on the RenderFrameHost destructor
  //       to see if theres something mportant going on
  app_frame_state.reset();

  // If a new RenderFrameProxyHost was created above, or if the old proxy isn't
  // live, create the RenderFrameProxy in the renderer, so that other frames
  // can still communicate with this frame.  See https://crbug.com/653746.
  //if (proxy && !proxy->is_render_frame_proxy_live())
  //  proxy->InitRenderFrameProxy();
}

void ApplicationWindowHost::HittestData(const viz::SurfaceId& surface_id, bool ignored_for_hittest) {
  //DLOG(INFO) << "ApplicationWindowHost::HittestData";
  if (delegate_) {
    delegate_->GetInputEventRouter()->OnHittestData(surface_id, ignored_for_hittest);
  }
}

void ApplicationWindowHost::Close() {
  //DLOG(INFO) << "ApplicationWindowHost::Close";
  // ApplicationWindowHost
  ClosePageIgnoringUnloadEvents();
}

void ApplicationWindowHost::CloseAck() {
  //DLOG(INFO) << "ApplicationWindowHost::CloseAck";
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::CloseAckImpl,
      weak_this_));
}

void ApplicationWindowHost::CloseAckImpl() {
  delegate_->OnCloseAckReceived(this);
}

void ApplicationWindowHost::UpdateScreenRectsAck() {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::UpdateScreenRectsAckImpl,
      weak_this_));
}

void ApplicationWindowHost::UpdateScreenRectsAckImpl() {
  waiting_for_screen_rects_ack_ = false;
  if (!view_)
    return;

  if (view_->GetViewBounds() == last_view_screen_rect_ &&
      view_->GetBoundsInRootWindow() == last_window_screen_rect_) {
    return;
  }

  SendScreenRects();
}

void ApplicationWindowHost::RequestMove(const gfx::Rect& position) {
  //DLOG(INFO) << "ApplicationWindowHost::RequestMove";
// ApplicationWindowHost
  
  if (is_active_)
    delegate_->RequestMove(position);
  
  // HostThread::PostTask(
  //   HostThread::IO, 
  //   FROM_HERE, 
  //   base::BindOnce(
  //     &common::mojom::ApplicationWindow::MoveAck,
  //     base::Unretained(GetApplicationWindowInterface()))
  // );
  //Send(new ViewMsg_Move_ACK(GetRoutingID()));

  // ApplicationWindowHost
  if (view_) {
    view_->SetBounds(position);
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE, 
      base::BindOnce(
        &ApplicationWindowHost::SendMoveAck,
        io_weak_this_/*io_weak_this_*/)
    );
    //Send(new ViewMsg_Move_ACK(routing_id_));
  }
}

void ApplicationWindowHost::SetTooltipText(const base::string16& tooltip_text, base::i18n::TextDirection text_direction_hint) {
  //DLOG(INFO) << "ApplicationWindowHost::SetTooltipText";
  if (!GetView())
    return;

  // First, add directionality marks around tooltip text if necessary.
  // A naive solution would be to simply always wrap the text. However, on
  // windows, Unicode directional embedding characters can't be displayed on
  // systems that lack RTL fonts and are instead displayed as empty squares.
  //
  // To get around this we only wrap the string when we deem it necessary i.e.
  // when the locale direction is different than the tooltip direction hint.
  //
  // Currently, we use element's directionality as the tooltip direction hint.
  // An alternate solution would be to set the overall directionality based on
  // trying to detect the directionality from the tooltip text rather than the
  // element direction.  One could argue that would be a preferable solution
  // but we use the current approach to match Fx & IE's behavior.
  base::string16 wrapped_tooltip_text = tooltip_text;
  if (!tooltip_text.empty()) {
    if (text_direction_hint == base::i18n::LEFT_TO_RIGHT) {
      // Force the tooltip to have LTR directionality.
      wrapped_tooltip_text =
          base::i18n::GetDisplayStringInLTRDirectionality(wrapped_tooltip_text);
    } else if (text_direction_hint == base::i18n::RIGHT_TO_LEFT &&
               !base::i18n::IsRTL()) {
      // Force the tooltip to have RTL directionality.
      base::i18n::WrapStringWithRTLFormatting(&wrapped_tooltip_text);
    }
  }
  view_->SetTooltipText(wrapped_tooltip_text);
}

void ApplicationWindowHost::ResizeOrRepaintACK(const gfx::Size& view_size, int32_t flags, const base::Optional<viz::LocalSurfaceId>& local_surface_id) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE,
    base::BindOnce(&ApplicationWindowHost::ResizeOrRepaintACKImpl,
      weak_this_,
      view_size, 
      flags, 
      local_surface_id));
}

void ApplicationWindowHost::ResizeOrRepaintACKImpl(const gfx::Size& view_size, int32_t flags, const base::Optional<viz::LocalSurfaceId>& local_surface_id) {
  TimeTicks paint_start = clock_->NowTicks();

  // Update our knowledge of the ApplicationWindow's size.
  current_size_ = view_size;

  bool is_resize_ack =
      ViewHostMsg_ResizeOrRepaint_ACK_Flags::is_resize_ack(flags);

  // resize_ack_pending_ needs to be cleared before we call DidPaintRect, since
  // that will end up reaching GetBackingStore.
  if (is_resize_ack) {
    //DCHECK(!g_check_for_pending_resize_ack);// || resize_ack_pending_);
    resize_ack_pending_ = false;
  }

  bool is_repaint_ack =
      ViewHostMsg_ResizeOrRepaint_ACK_Flags::is_repaint_ack(flags);
  if (is_repaint_ack) {
    DCHECK(repaint_ack_pending_);
    TRACE_EVENT_ASYNC_END0(
        "renderer_host", "ApplicationWindowHost::repaint_ack_pending_", this);
    repaint_ack_pending_ = false;
    TimeDelta delta = clock_->NowTicks() - repaint_start_time_;
    UMA_HISTOGRAM_TIMES("MPArch.RWH_RepaintDelta", delta);
  }

  DCHECK(!view_size.IsEmpty());

  DidCompleteResizeOrRepaint(flags, paint_start);

  last_auto_resize_surface_id_ = local_surface_id;//child_allocated_local_surface_id;

  if (auto_resize_enabled_) {
    bool post_callback = new_auto_size_.IsEmpty();
    new_auto_size_ = view_size;
    if (post_callback) {
      base::ThreadTaskRunnerHandle::Get()->PostTask(
          FROM_HERE, base::BindOnce(&ApplicationWindowHost::DelayedAutoResized,
                                    weak_this_));
    }
  }

  // Log the time delta for processing a paint message. On platforms that don't
  // support asynchronous painting, this is equivalent to
  // MPArch.RWH_TotalPaintTime.
  //TimeDelta delta = clock_->NowTicks() - paint_start;
}

void ApplicationWindowHost::DidCompleteResizeOrRepaint(
    int32_t flags,
    const TimeTicks& paint_start) {
  TRACE_EVENT0("renderer_host",
               "ApplicationWindowHost::DidCompleteResizeOrRepaint");

  NotificationService::current()->Notify(
      NOTIFICATION_RENDER_WIDGET_HOST_DID_COMPLETE_RESIZE_OR_REPAINT,
      Source<ApplicationWindowHost>(this), NotificationService::NoDetails());

  // We don't need to update the view if the view is hidden. We must do this
  // early return after the ACK is sent, however, or the renderer will not send
  // us more data.
  if (is_hidden_)
    return;

  // If we got a resize ack, then perhaps we have another resize to send?
  bool is_resize_ack =
      ViewHostMsg_ResizeOrRepaint_ACK_Flags::is_resize_ack(flags);
  if (is_resize_ack)
    SynchronizeVisualProperties();
}

void ApplicationWindowHost::DelayedAutoResized() {
  //DLOG(INFO) << "ApplicationWindowHost::DelayedAutoResized";
  gfx::Size new_size = new_auto_size_;
  // Clear the new_auto_size_ since the empty value is used as a flag to
  // indicate that no callback is in progress (i.e. without this line
  // DelayedAutoResized will not get called again).
  new_auto_size_.SetSize(0, 0);
  if (!auto_resize_enabled_)
    return;

  if (view_) {
    viz::ScopedSurfaceIdAllocator scoped_allocator =
        view_->ResizeDueToAutoResize(new_size,
                                     last_auto_resize_surface_id_.value());

    if (delegate_) {
      delegate_->ResizeDueToAutoResize(this, new_size,
                                       last_auto_resize_surface_id_.value());
    }
  }
}

bool ApplicationWindowHost::KeyPressListenersHandleEvent(
    const NativeWebKeyboardEvent& event) {
  if (event.skip_in_browser || event.GetType() != WebKeyboardEvent::kRawKeyDown)
    return false;

  for (size_t i = 0; i < key_press_event_callbacks_.size(); i++) {
    size_t original_size = key_press_event_callbacks_.size();
    if (key_press_event_callbacks_[i].Run(event))
      return true;

    // Check whether the callback that just ran removed itself, in which case
    // the iterator needs to be decremented to properly account for the removal.
    size_t current_size = key_press_event_callbacks_.size();
    if (current_size != original_size) {
      DCHECK_EQ(original_size - 1, current_size);
      --i;
    }
  }

  return false;
}

void ApplicationWindowHost::DidChangeOpener(int32_t opener) {
  //DLOG(INFO) << "ApplicationWindowHost::DidChangeOpener";
}

void ApplicationWindowHost::SetCursor(const common::WebCursor& cursor) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowHost::SetCursorImpl, 
    weak_this_, cursor));
}

void ApplicationWindowHost::SetCursorImpl(const common::WebCursor& cursor) {
  if (!view_)
    return;
  view_->UpdateCursor(cursor);
}

void ApplicationWindowHost::AutoscrollStart(const gfx::PointF& position) {
  //DLOG(INFO) << "ApplicationWindowHost::AutoscrollStart";
  WebGestureEvent scroll_begin = common::SyntheticWebGestureEventBuilder::Build(
      WebInputEvent::kGestureScrollBegin,
      blink::kWebGestureDeviceSyntheticAutoscroll);
  scroll_begin.SetPositionInWidget(position);

  ForwardGestureEventWithLatencyInfo(
      scroll_begin, ui::LatencyInfo(ui::SourceEventType::OTHER));
}

void ApplicationWindowHost::AutoscrollFling(const gfx::Vector2dF& velocity) {
  //DLOG(INFO) << "ApplicationWindowHost::AutoscrollFling";
  WebGestureEvent event = common::SyntheticWebGestureEventBuilder::Build(
      WebInputEvent::kGestureFlingStart,
      blink::kWebGestureDeviceSyntheticAutoscroll);
  event.data.fling_start.velocity_x = velocity.x();
  event.data.fling_start.velocity_y = velocity.y();

  ForwardGestureEventWithLatencyInfo(
      event, ui::LatencyInfo(ui::SourceEventType::OTHER));
}

void ApplicationWindowHost::AutoscrollEnd() {
  //DLOG(INFO) << "ApplicationWindowHost::AutoscrollEnd";
  WebGestureEvent cancel_event = common::SyntheticWebGestureEventBuilder::Build(
      WebInputEvent::kGestureFlingCancel,
      blink::kWebGestureDeviceSyntheticAutoscroll);
  cancel_event.data.fling_cancel.prevent_boosting = true;

  ForwardGestureEventWithLatencyInfo(
      cancel_event, ui::LatencyInfo(ui::SourceEventType::OTHER));
}

void ApplicationWindowHost::TextInputStateChanged(const common::TextInputState& text_input_state) {
  HostThread::PostTask(
      HostThread::UI, 
      FROM_HERE, 
      base::BindOnce(
        &ApplicationWindowHost::TextInputStateChangedImpl,
        weak_this_,
        text_input_state));
}

void ApplicationWindowHost::TextInputStateChangedImpl(const common::TextInputState& text_input_state) {
  //DLOG(INFO) << "ApplicationWindowHost::TextInputStateChanged";
  if (view_)
    view_->TextInputStateChanged(text_input_state);
}

void ApplicationWindowHost::LockMouse(bool user_gesture, bool privileged) {
  //DLOG(INFO) << "ApplicationWindowHost::LockMouse";
  if (pending_mouse_lock_request_) {
    //Send(new ViewMsg_LockMouse_ACK(routing_id_, false));
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE, 
      base::BindOnce(
        &ApplicationWindowHost::SendLockMouseAck,
        io_weak_this_/*io_weak_this_*/)
    );
    return;
  }

  pending_mouse_lock_request_ = true;
  if (delegate_) {
    delegate_->RequestToLockMouse(this, user_gesture,
                                  is_last_unlocked_by_target_,
                                  privileged && allow_privileged_mouse_lock_);
    // We need to reset |is_last_unlocked_by_target_| here as we don't know
    // request source in |LostMouseLock()|.
    is_last_unlocked_by_target_ = false;
    return;
  }

  if (privileged && allow_privileged_mouse_lock_) {
    // Directly approve to lock the mouse.
    GotResponseToLockMouseRequest(true);
  } else {
    // Otherwise, just reject it.
    GotResponseToLockMouseRequest(false);
  }
}

void ApplicationWindowHost::UnlockMouse() {
  //DLOG(INFO) << "ApplicationWindowHost::UnlockMouse";
  const bool was_mouse_locked = !pending_mouse_lock_request_ && IsMouseLocked();
  RejectMouseLockOrUnlockIfNecessary();
  if (was_mouse_locked)
    is_last_unlocked_by_target_ = true;
}

void ApplicationWindowHost::LostMouseLock() {
  //DLOG(INFO) << "ApplicationWindowHost::LostMouseLock";
  if (delegate_)
    delegate_->LostMouseLock(this);
}

void ApplicationWindowHost::SelectionBoundsChanged(common::mojom::SelectionBoundsParamsPtr params) {
  HostThread::PostTask(
      HostThread::UI, 
      FROM_HERE, 
      base::BindOnce(
        &ApplicationWindowHost::SelectionBoundsChangedImpl,
        weak_this_,
        base::Passed(std::move(params))));
}

void ApplicationWindowHost::SelectionBoundsChangedImpl(common::mojom::SelectionBoundsParamsPtr params) {
  //DLOG(INFO) << "ApplicationWindowHost::SelectionBoundsChanged";
  if (view_)
    view_->SelectionBoundsChanged(std::move(params));
}

void ApplicationWindowHost::FocusedNodeTouched(bool editable) {
  //DLOG(INFO) << "ApplicationWindowHost::FocusedNodeTouched";
  if (delegate_)
    delegate_->FocusedNodeTouched(editable);
}

void ApplicationWindowHost::StartDragging(
                   const common::DropData& drop_data,
                   blink::WebDragOperationsMask drag_operations_mask,
                   const SkBitmap& bitmap,
                   const gfx::Vector2d& bitmap_offset_in_dip,
                   const common::DragEventSourceInfo& event_info) {
  //DLOG(INFO) << "ApplicationWindowHost::StartDragging";
  ApplicationWindowHostDelegateView* view = delegate_->GetDelegateView();
  if (!view || !GetView()) {
    // Need to clear drag and drop state in blink.
    DragSourceSystemDragEnded();
    return;
  }

  common::DropData filtered_data(drop_data);
  //ApplicationProcessHost* process = GetProcess();
  //ChildProcessSecurityPolicyImpl* policy =
  //    ChildProcessSecurityPolicyImpl::GetInstance();

  // Allow drag of Javascript URLs to enable bookmarklet drag to bookmark bar.
  //if (!filtered_data.url.SchemeIs(url::kJavaScriptScheme))
  //  process->FilterURL(true, &filtered_data.url);
  //process->FilterURL(false, &filtered_data.html_base_url);
  // Filter out any paths that the renderer didn't have access to. This prevents
  // the following attack on a malicious renderer:
  // 1. StartDragging IPC sent with renderer-specified filesystem paths that it
  //    doesn't have read permissions for.
  // 2. We initiate a native DnD operation.
  // 3. DnD operation immediately ends since mouse is not held down. DnD events
  //    still fire though, which causes read permissions to be granted to the
  //    renderer for any file paths in the drop.
  //filtered_data.filenames.clear();
  //for (const auto& file_info : drop_data.filenames) {
  //  if (policy->CanReadFile(GetProcess()->GetID(), file_info.path))
  //    filtered_data.filenames.push_back(file_info);
  //}

  //storage::FileSystemContext* file_system_context =
  //    GetProcess()->GetStoragePartition()->GetFileSystemContext();
  //filtered_data.file_system_files.clear();
  //for (size_t i = 0; i < drop_data.file_system_files.size(); ++i) {
  //  storage::FileSystemURL file_system_url =
  //      file_system_context->CrackURL(drop_data.file_system_files[i].url);
  //  if (policy->CanReadFileSystemFile(GetProcess()->GetID(), file_system_url))
  //    filtered_data.file_system_files.push_back(drop_data.file_system_files[i]);
  //}

  float scale = GetScaleFactorForView(GetView());
  gfx::ImageSkia image(gfx::ImageSkiaRep(bitmap, scale));
  view->StartDragging(filtered_data, drag_operations_mask, image,
                      bitmap_offset_in_dip, event_info, this);
}

void ApplicationWindowHost::UpdateDragCursor(blink::WebDragOperation drag_operation) {
  //DLOG(INFO) << "ApplicationWindowHost::UpdateDragCursor";
  if (delegate_->OnUpdateDragCursor())
    return;

  ApplicationWindowHostDelegateView* view = delegate_->GetDelegateView();
  if (view)
    view->UpdateDragCursor(drag_operation);
}

void ApplicationWindowHost::RejectMouseLockOrUnlockIfNecessary() {
  DCHECK(!pending_mouse_lock_request_ || !IsMouseLocked());
  if (pending_mouse_lock_request_) {
    //DLOG(INFO) << "ApplicationWindowHost::RejectMouseLockOrUnlockIfNecessary";
    pending_mouse_lock_request_ = false;
    //Send(new ViewMsg_LockMouse_ACK(routing_id_, false));
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE, 
      base::BindOnce(
        &ApplicationWindowHost::SendLockMouseAck,
        io_weak_this_/*io_weak_this_*/)
    );
  } else if (IsMouseLocked()) {
    view_->UnlockMouse();
  }
}

void ApplicationWindowHost::SetWindowInputHandler(
    common::mojom::WindowInputHandlerAssociatedPtr widget_input_handler,
    common::mojom::WindowInputHandlerHostRequest host_request) {
  //DLOG(INFO) << "ApplicationWindowHost::SetWindowInputHandler";
  associated_widget_input_handler_ = std::move(widget_input_handler);
  input_router_->BindHost(std::move(host_request), true);
}

void ApplicationWindowHost::OnFrameSwapMessagesReceived(
    uint32_t frame_token,
    std::vector<IPC::Message> messages) {
  //DLOG(INFO) << "ApplicationWindowHost::OnFrameSwapMessagesReceived";
  frame_token_message_queue_->OnFrameSwapMessagesReceived(frame_token,
                                                         std::move(messages));
}

void ApplicationWindowHost::FrameSwapMessagesReceived(uint32_t frame_token) {
  //DLOG(INFO) << "ApplicationWindowHost::FrameSwapMessagesReceived";
  std::vector<IPC::Message> messages;
  frame_token_message_queue_->OnFrameSwapMessagesReceived(frame_token,
                                                          std::move(messages));
}

void ApplicationWindowHost::ShowWindow(int32_t route_id, const gfx::Rect& initial_rect) {
  //DLOG(INFO) << "ApplicationWindowHost::ShowWindow";
  // ApplicationWindowHost::OnShowWidget
  delegate_->ShowCreatedWindow(GetProcess()->GetID(), route_id, initial_rect);
  //Send(new ViewMsg_Move_ACK(route_id));
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendMoveAck,
      io_weak_this_)
  );
}

void ApplicationWindowHost::ShowFullscreenWindow(int32_t route_id) {
  //DLOG(INFO) << "ApplicationWindowHost::ShowFullscreenWindow";
  // ApplicationWindowHost::OnShowFullscreenWidget
  delegate_->ShowCreatedFullscreenWindow(GetProcess()->GetID(), route_id);
  //Send(new ViewMsg_Move_ACK(route_id));
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendMoveAck,
      io_weak_this_)
  );
}

void ApplicationWindowHost::UpdateTargetURL(const std::string& url) {
  // ApplicationWindowHost::OnUpdateTargetURL
  //DLOG(INFO) << "ApplicationWindowHost::UpdateTargetURL";
  delegate_->UpdateTargetURL(this, GURL(url));

  // Send a notification back to the renderer that we are ready to
  // receive more target urls.
  //Send(new ViewMsg_UpdateTargetURL_ACK(GetRoutingID()));
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendUpdateTargetURLAck,
      io_weak_this_)
  );
}

void ApplicationWindowHost::DocumentAvailableInMainFrame(bool uses_temporary_zoom_level) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::DocumentAvailableInMainFrameImpl,
      weak_this_,
      uses_temporary_zoom_level)); 
}

void ApplicationWindowHost::DocumentAvailableInMainFrameImpl(bool uses_temporary_zoom_level) {
  //DLOG(INFO) << "ApplicationWindowHost::DocumentAvailableInMainFrame";
  
  // TODO: see if theres a better url to put this than here..
  // it needs to happen after the client BindApplicationWindow()

  //SetUpMojo();

  //remote_interfaces_->GetInterface(&widget_input_handler_);
  //DCHECK(widget_input_handler_);

  //common::mojom::WindowInputHandlerAssociatedPtr widget_handler;
  //common::mojom::WindowInputHandlerHostRequest host_request;
  //if (frame_input_handler_) {
  //common::mojom::WindowInputHandlerHostPtr host;
  //host_request = mojo::MakeRequest(&host);
  
  //widget_input_handler_->GetWindowInputHandler(
  //   mojo::MakeRequest(&widget_handler), std::move(host));
  //SetWindow(std::move(widget));
  //SetupInputRouter();
  
  ////DLOG(INFO) << "ApplicationWindowHost::OnProcessInit: SetWindowInputHandler()";
  //SetWindowInputHandler(std::move(widget_handler),
  //                      std::move(host_request));


  delegate_->DocumentAvailableInMainFrame(this);

  if (!uses_temporary_zoom_level)
    return;

// #if !defined(OS_ANDROID)
//   HostZoomMapImpl* host_zoom_map =
//       static_cast<HostZoomMapImpl*>(HostZoomMap::Get(GetSiteInstance()));
//   host_zoom_map->SetTemporaryZoomLevel(GetProcess()->GetID(),
//                                        GetRoutingID(),
//                                        host_zoom_map->GetDefaultZoomLevel());
// #endif  // !defined(OS_ANDROID)
}

void ApplicationWindowHost::DidContentsPreferredSizeChange(const gfx::Size& pref_size) {
  //DLOG(INFO) << "ApplicationWindowHost::DidContentsPreferredSizeChange";
  delegate_->UpdatePreferredSize(pref_size);
}

void ApplicationWindowHost::RouteCloseEvent() {
  //DLOG(INFO) << "ApplicationWindowHost::RouteCloseEvent";
  delegate_->RouteCloseEvent(this);
}

void ApplicationWindowHost::TakeFocus(bool reverse) {
  //DLOG(INFO) << "ApplicationWindowHost::TakeFocus";
  ApplicationWindowHostDelegateView* view = delegate_->GetDelegateView();
  if (view)
    view->TakeFocus(reverse);
}

void ApplicationWindowHost::GotFocus() {
  //DLOG(INFO) << "ApplicationWindowHost::GotFocus";
  Focus();
  
  ApplicationWindowHostDelegateView* view = delegate_->GetDelegateView();
  if (view)
    view->GotFocus(this);
  
  if (delegate_)
    delegate_->ApplicationWindowGotFocus(this);
}

void ApplicationWindowHost::LostFocus() {
  //DLOG(INFO) << "ApplicationWindowHost::LostFocus";
  Blur();
  
  ApplicationWindowHostDelegateView* view = delegate_->GetDelegateView();
  if (view)
    view->LostFocus(this);
  
  if (delegate_)
    delegate_->ApplicationWindowLostFocus(this);
}

void ApplicationWindowHost::ViewDestroyed() {
  //DLOG(INFO) << "ApplicationWindowHost::ViewDestroyed";
  CancelKeyboardLock();
  RejectMouseLockOrUnlockIfNecessary();

  // TODO(evanm): tracking this may no longer be necessary;
  // eliminate this function if so.
  SetView(nullptr);
}

void ApplicationWindowHost::ClosePageACK() {
  //DLOG(INFO) << "ApplicationWindowHost::ClosePageACK";
  ClosePageIgnoringUnloadEvents();
}

void ApplicationWindowHost::OnGpuSwapBuffersCompletedInternal(
      const ui::LatencyInfo& latency_info) {
//   // Note that a compromised renderer can send LatencyInfo to a
//   // ApplicationWindowHost other than its own. Be mindful of security
//   // implications of the code you add here.
//   //ui::LatencyInfo::LatencyComponent window_snapshot_component;
//   base::TimeTicks window_snapshot_component;
//   if (latency_info.FindLatency(ui::BROWSER_SNAPSHOT_FRAME_NUMBER_COMPONENT,
//                                //GetLatencyComponentId(),
//                                &window_snapshot_component)) {
//     int sequence_number = static_cast<int>(window_snapshot_component.sequence_number);
// #if defined(OS_MACOSX) || defined(OS_WIN)
//     // On Mac, when using CoreAnimation, or Win32 when using GDI, there is a
//     // delay between when content is drawn to the screen, and when the
//     // snapshot will actually pick up that content. Insert a manual delay of
//     // 1/6th of a second (to simulate 10 frames at 60 fps) before actually
//     // taking the snapshot.
//     base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
//         FROM_HERE,
//         base::Bind(&ApplicationWindowHost::WindowSnapshotReachedScreen,
//                    weak_this_, sequence_number),
//         TimeDelta::FromSecondsD(1. / 6));
// #else
//     WindowSnapshotReachedScreen(sequence_number);
// #endif
//   }

  latency_tracker_.OnGpuSwapBuffersCompleted(latency_info);
}

void ApplicationWindowHost::WindowSnapshotReachedScreen(int snapshot_id) {
  DCHECK(base::MessageLoopForUI::IsCurrent());

  if (!pending_surface_browser_snapshots_.empty()) {
    GetView()->CopyFromSurface(
        gfx::Rect(), gfx::Size(),
        base::BindOnce(&ApplicationWindowHost::OnSnapshotFromSurfaceReceived,
                       weak_this_, snapshot_id, 0));
  }

  if (!pending_browser_snapshots_.empty()) {
#if defined(OS_ANDROID)
    // On Android, call sites should pass in the bounds with correct offset
    // to capture the intended content area.
    gfx::Rect snapshot_bounds(GetView()->GetViewBounds());
    snapshot_bounds.Offset(0, GetView()->GetNativeView()->content_offset());
#else
    gfx::Rect snapshot_bounds(GetView()->GetViewBounds().size());
#endif

    gfx::Image image;
    if (ui::GrabViewSnapshot(GetView()->GetNativeView(), snapshot_bounds,
                             &image)) {
      OnSnapshotReceived(snapshot_id, image);
      return;
    }

    ui::GrabViewSnapshotAsync(
        GetView()->GetNativeView(), snapshot_bounds,
        base::Bind(&ApplicationWindowHost::OnSnapshotReceived,
                   weak_this_, snapshot_id));
  }
}

void ApplicationWindowHost::OnSnapshotFromSurfaceReceived(
    int snapshot_id,
    int retry_count,
    const SkBitmap& bitmap) {
  static constexpr int kMaxRetries = 5;
  if (bitmap.drawsNothing() && retry_count < kMaxRetries) {
    GetView()->CopyFromSurface(
        gfx::Rect(), gfx::Size(),
        base::BindOnce(&ApplicationWindowHost::OnSnapshotFromSurfaceReceived,
                       weak_this_, snapshot_id,
                       retry_count + 1));
    return;
  }
  // If all retries have failed, we return an empty image.
  gfx::Image image;
  if (!bitmap.drawsNothing())
    image = gfx::Image::CreateFrom1xBitmap(bitmap);
  // Any pending snapshots with a lower ID than the one received are considered
  // to be implicitly complete, and returned the same snapshot data.
  PendingSnapshotMap::iterator it = pending_surface_browser_snapshots_.begin();
  while (it != pending_surface_browser_snapshots_.end()) {
    if (it->first <= snapshot_id) {
      it->second.Run(image);
      pending_surface_browser_snapshots_.erase(it++);
    } else {
      ++it;
    }
  }
}

void ApplicationWindowHost::OnSnapshotReceived(int snapshot_id,
                                               gfx::Image image) {
  // Any pending snapshots with a lower ID than the one received are considered
  // to be implicitly complete, and returned the same snapshot data.
  PendingSnapshotMap::iterator it = pending_browser_snapshots_.begin();
  while (it != pending_browser_snapshots_.end()) {
    if (it->first <= snapshot_id) {
      it->second.Run(image);
      pending_browser_snapshots_.erase(it++);
    } else {
      ++it;
    }
  }
#if defined(OS_MACOSX)
  if (pending_browser_snapshots_.empty())
    GetWakeLock()->CancelWakeLock();
#endif
}

/*
 * ApplicationWindowHost section
 */

bool ApplicationWindowHost::IsApplicationWindowLive() const {
  return GetProcess()->HasConnection() && application_initialized();
}

void ApplicationWindowHost::DisableScrollbarsForThreshold(const gfx::Size& size) {
  //Send(new ViewMsg_DisableScrollbarsForSmallWindows(GetRoutingID(), size));
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendDisableScrollbarsForSmallWindows,
      io_weak_this_,
      size)
  );
}

void ApplicationWindowHost::EnablePreferredSizeMode() {
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendEnablePreferredSizeChangedMode,
      io_weak_this_));
}

void ApplicationWindowHost::ExecuteMediaPlayerActionAtLocation(
    const gfx::Point& location,
    const blink::WebMediaPlayerAction& action) {
  //Send(new ViewMsg_MediaPlayerActionAt(GetRoutingID(), location, action));
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendMediaPlayerActionAt,
      io_weak_this_,
      location, 
      action)
  );
}

void ApplicationWindowHost::NotifyMoveOrResizeStarted() {
  //DLOG(INFO) << "ApplicationWindowHost::NotifyMoveOrResizeStarted";
  //Send(new ViewMsg_MoveOrResizeStarted(GetRoutingID()));
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendMoveOrResizeStarted,
      io_weak_this_)
  );
}

void ApplicationWindowHost::DetachDelegate() {
  //DLOG(INFO) << "ApplicationWindowHost::DetachDelegate: " << this;
  delegate_ = nullptr;
  latency_tracker_.reset_delegate();
}

bool ApplicationWindowHost::GotResponseToLockMouseRequest(bool allowed) {
  if (!allowed) {
    RejectMouseLockOrUnlockIfNecessary();
    return false;
  }

  if (!pending_mouse_lock_request_) {
    // This is possible, e.g., the plugin sends us an unlock request before
    // the user allows to lock to mouse.
    return false;
  }

  pending_mouse_lock_request_ = false;
  if (!view_ || !view_->HasFocus()|| !view_->LockMouse()) {
    //Send(new ViewMsg_LockMouse_ACK(routing_id_, false));
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE, 
      base::BindOnce(
        &ApplicationWindowHost::SendLockMouseAck,
        io_weak_this_)
    );
    return false;
  }

  //Send(new ViewMsg_LockMouse_ACK(routing_id_, true));
  
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendLockMouseAck,
      io_weak_this_)
  );
  return true;
}

void ApplicationWindowHost::GotResponseToKeyboardLockRequest(bool allowed) {
  DCHECK(keyboard_lock_requested_);
  keyboard_lock_allowed_ = allowed;

  if (keyboard_lock_allowed_)
    LockKeyboard();
  else
    UnlockKeyboard();
}

void ApplicationWindowHost::CancelKeyboardLock() {
  if (delegate_)
    delegate_->CancelKeyboardLock(this);

  UnlockKeyboard();

  keyboard_lock_allowed_ = false;
  keyboard_lock_requested_ = false;
  keyboard_keys_to_lock_.reset();
}

void ApplicationWindowHost::SendLostMouseLock() {
  //Send(new ViewMsg_MouseLockLost(routing_id_));
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE,
    base::BindOnce(
      &ApplicationWindowHost::SendMouseLockLost,
      io_weak_this_)
  );
}

//void ApplicationWindowHost::SetWebUIProperty(const std::string& name,
//                      const std::string& value) {
//}

void ApplicationWindowHost::SyncRendererPrefs() {
  common::RendererPreferences renderer_preferences =
      delegate_->GetRendererPrefs();//GetProcess()->GetApplicationContents());
  GetPlatformSpecificPrefs(&renderer_preferences);
  //Send(new ViewMsg_SetRendererPrefs(GetRoutingID(), renderer_preferences));
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendRendererPrefs,
      io_weak_this_,
      base::Passed(std::move(renderer_preferences)))
  );
}

common::WebPreferences ApplicationWindowHost::GetWebkitPreferences() {
  return common::WebPreferences();
}

void ApplicationWindowHost::UpdateWebkitPreferences(const common::WebPreferences& prefs) {
  web_preferences_.reset(new common::WebPreferences(prefs));
  //Send(new ViewMsg_UpdateWebPreferences(GetRoutingID(), prefs));
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendUpdateWebPreferences,
      io_weak_this_,
      prefs)
  );
}

void ApplicationWindowHost::OnWebkitPreferencesChanged() {
  if (updating_web_preferences_)
    return;
  updating_web_preferences_ = true;
  UpdateWebkitPreferences(ComputeWebkitPrefs());
  updating_web_preferences_ = false;
}

void ApplicationWindowHost::SelectWordAroundCaret() {
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendSelectWordAroundCaret,
      io_weak_this_)
  );
}

void ApplicationWindowHost::ApplicationProcessReady(ApplicationProcessHost* host) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  //DLOG(INFO) << "ApplicationWindowHost::ApplicationProcessReady";
  io_weak_this_ = io_weak_factory_.GetWeakPtr();
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE,
    base::BindOnce(
      &ApplicationWindowHost::OnProcessInit, 
      weak_this_));
}
  
void ApplicationWindowHost::ApplicationProcessShutdownRequested(ApplicationProcessHost* host) {

}

void ApplicationWindowHost::ApplicationProcessWillExit(ApplicationProcessHost* host) {

}

void ApplicationWindowHost::ApplicationProcessExited(
  ApplicationProcessHost* host,
  const ChildProcessTerminationInfo& info) {
  //DLOG(INFO) << "ApplicationWindowHost::ApplicationProcessExited";
  if (!application_initialized())
    return;

  ApplicationExited(info.status, info.exit_code);
  if (delegate_) {
    delegate_->ApplicationWindowTerminated(this, info.status, info.exit_code);
  }
}

void ApplicationWindowHost::ApplicationProcessHostDestroyed(ApplicationProcessHost* host) {
  //DLOG(INFO) << "ApplicationWindowHost::ApplicationProcessHostDestroyed";
  
}

void ApplicationWindowHost::OnProcessInit() {
   // this is us ..
  //application_window_host_->SetFrameDepth(frame_tree_node_->depth());
  //application_window_host_->SetWindowInputHandler(std::move(widget_handler),
  //                                           std::move(host_request));
  //SetUpMojo();

  //SetFrameDepth(frame_tree_node_->depth());
  // common::mojom::WindowInputHandlerAssociatedPtr widget_handler;
  // common::mojom::WindowInputHandlerHostRequest host_request;
  // //if (frame_input_handler_) {
  // common::mojom::WindowInputHandlerHostPtr host;
  // host_request = mojo::MakeRequest(&host);
  // DCHECK(widget_input_handler_);
  // widget_input_handler_->GetWindowInputHandler(
  //    mojo::MakeRequest(&widget_handler), std::move(host));
  // //SetWindow(std::move(widget));
  //SetupInputRouter();
  
  // //DLOG(INFO) << "ApplicationWindowHost::OnProcessInit: SetWindowInputHandler()";
  // SetWindowInputHandler(std::move(widget_handler),
  //                       std::move(host_request));

  // New views may be created during RenderProcessHost::ProcessDied(), within a
  // brief window where the internal ChannelProxy is null. This ensures that the
  // ChannelProxy is re-initialized in such cases so that subsequent messages
  // make their way to the new renderer once its restarted.
  //GetProcess()->EnableSendQueue();

  if (!is_active_) {
    UpdatePriority();
  }

  //if (ResourceDispatcherHostImpl::Get()) {
  //  HostThread::PostTask(
  //      HostThread::IO, FROM_HERE,
  //      base::BindOnce(
  //          &ResourceDispatcherHostImpl::OnApplicationWindowHostCreated,
 //           base::Unretained(ResourceDispatcherHostImpl::Get()),
 //            GetProcess()->GetID(), GetRoutingID(),
 //           base::RetainedRef(
 //               GetProcess()->GetStoragePartition()->GetURLRequestContext())));
 // }
  
  // end ApplicationWindowHost contructor

  SetApplicationWindowCreated(true);
}

void ApplicationWindowHost::ApplicationExited(base::TerminationStatus status,
                                              int exit_code) {
  //DLOG(INFO) << "ApplicationWindowHost::ApplicationExited";
  if (!application_initialized_)
    return;

  // Clear this flag so that we can ask the next renderer for composition
  // updates.
  monitoring_composition_info_ = false;

  // Clearing this flag causes us to re-create the renderer when recovering
  // from a crashed renderer.
  application_initialized_ = false;

  waiting_for_screen_rects_ack_ = false;

  // Must reset these to ensure that keyboard events work with a new renderer.
  suppress_events_until_keydown_ = false;

  // Reset some fields in preparation for recovering from a crash.
  ResetSizeAndRepaintPendingFlags();
  current_size_.SetSize(0, 0);
  // After the renderer crashes, the view is destroyed and so the
  // ApplicationWindowHost cannot track its visibility anymore. We assume such
  // ApplicationWindowHost to be invisible for the sake of internal accounting - be
  // careful about changing this - see http://crbug.com/401859 and
  // http://crbug.com/522795.
  //
  // We need to at least make sure that the RenderProcessHost is notified about
  // the |is_hidden_| change, so that the renderer will have correct visibility
  // set when respawned.
  if (!is_hidden_) {
    is_hidden_ = true;
    //if (!destroyed_)
    //  process_->UpdateClientPriority(this);
  }

  // Reset this to ensure the hung renderer mechanism is working properly.
  in_flight_event_count_ = 0;
  StopHangMonitorTimeout();

  if (view_) {
    view_->ApplicationProcessGone(status, exit_code);
    view_.reset();  // The View should be deleted by RenderProcessGone.
  }

  // Reconstruct the input router to ensure that it has fresh state for a new
  // renderer. Otherwise it may be stuck waiting for the old renderer to ack an
  // event. (In particular, the above call to view_->RenderProcessGone will
  // destroy the aura window, which may dispatch a synthetic mouse move.)
  
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowHost::SetupInputRouter, io_weak_this_));//base::Unretained(this)));
  
  synthetic_gesture_controller_.reset();

  current_content_source_id_ = 0;

  frame_token_message_queue_->Reset();
}

void ApplicationWindowHost::SetupInputRouter() {
  in_flight_event_count_ = 0;
  StopHangMonitorTimeout();
  //associated_widget_input_handler_ = nullptr;
  //widget_input_handler_ = nullptr;

  input_router_.reset(
      new InputRouterImpl(this, this, GetInputRouterConfigForPlatform()));

  // input_router_ recreated, need to update the force_enable_zoom_ state.
  input_router_->SetForceEnableZoom(force_enable_zoom_);

  if (IsUseZoomForDSFEnabled()) {
    input_router_->SetDeviceScaleFactor(GetScaleFactorForView(view_.get()));
  }
}

void ApplicationWindowHost::IssueKeepAliveHandle(common::mojom::KeepAliveHandleRequest keep_alive_handle) {
  
}

void ApplicationWindowHost::StopHangMonitorTimeout() {
  if (hang_monitor_timeout_)
    hang_monitor_timeout_->Stop();

  if (!hang_monitor_start_time_.is_null()) {
    base::TimeDelta elapsed = clock_->NowTicks() - hang_monitor_start_time_;
    const base::TimeDelta kMinimumHangTimeToReport =
        base::TimeDelta::FromSeconds(5);
    if (elapsed >= kMinimumHangTimeToReport)
      UMA_HISTOGRAM_LONG_TIMES("Renderer.Hung.Duration", elapsed);

    hang_monitor_start_time_ = TimeTicks();
  }
  ApplicationIsResponsive();
}

bool ApplicationWindowHost::CreateApplicationWindow() {//bool launch_process) {
  //DLOG(INFO) << "ApplicationWindowHost::CreateApplicationWindow";
  
    //int opener_frame_route_id,
    //int proxy_route_id,
    //const base::UnguessableToken& devtools_frame_token,
    //const FrameReplicationState& replicated_frame_state,
    //bool window_was_created_with_opener) {
  // The process may (if we're sharing a process with another host that already
  // initialized it) or may not (we have our own process or the old process
  // crashed) have been initialized. Calling Init multiple times will be
  // ignored, so this is safe.
  //if (launch_process) {
  //  if (!GetProcess()->Init(base::UUID::generate()))
  //    return false;
  //}
  
  DCHECK(GetProcess()->HasConnection());
 // DCHECK(GetProcess()->GetApplicationContents());
  //CHECK(main_frame_routing_id_ != MSG_ROUTING_NONE ||
 //       proxy_route_id != MSG_ROUTING_NONE);

  // We should not set both main_frame_routing_id_ and proxy_route_id.  Log
  // cases that this happens (without crashing) to track down
  // https://crbug.com/575245.
  // TODO(creis): Remove this once we've found the cause.
  //if (main_frame_routing_id_ != MSG_ROUTING_NONE &&
  //    proxy_route_id != MSG_ROUTING_NONE) {
  //  NOTREACHED() << "Don't set both main_frame_routing_id_ and proxy_route_id";
  //  base::debug::DumpWithoutCrashing();
  //}

  //RenderFrameHostImpl* main_rfh = nullptr;
  //if (main_frame_routing_id_ != MSG_ROUTING_NONE) {
  //  main_rfh = RenderFrameHostImpl::FromID(GetProcess()->GetID(),
  //                                         main_frame_routing_id_);
  //  DCHECK(main_rfh);
  //}

  set_application_initialized(true);

  // No need unless we need to expose another 'sub' interface
  // on a window host (like the relation View/Widget => RenderFrameHost)
  // that we dont have here as our WindowHost also have properties of the FrameHost

  //service_manager::mojom::InterfaceProviderPtr interface_provider;
  //BindInterfaceProviderRequest(mojo::MakeRequest(&interface_provider));
  //DLOG(INFO) << "ApplicationWindowHost::CreateApplicationWindow: this = " << this << " delegate = " << delegate_;
  DCHECK(delegate_);

  common::mojom::CreateNewWindowParamsPtr params = common::mojom::CreateNewWindowParams::New();
    params->renderer_preferences =
      delegate_->GetRendererPrefs();//GetProcess()->GetApplicationContents());
  GetPlatformSpecificPrefs(&params->renderer_preferences);
  params->web_preferences = GetWebkitPreferences();
  params->window_id = GetRoutingID();
  params->user_gesture = false;
  params->window_container_type = common::mojom::WindowContainerType::NORMAL;
  params->window_name = "untitled";
  params->opener_suppressed = false;
  params->disposition = WindowOpenDisposition::CURRENT_TAB;
  params->target_url = GURL("hello://world");
  params->referrer.url = GURL("parent://world");
  //params->main_frame_routing_id = main_frame_routing_id_;
  //if (main_rfh) {
  //  main_rfh->BindInterfaceProviderRequest(
  //      mojo::MakeRequest(&params->main_frame_interface_provider));
  //  ApplicationWindowHost* main_rwh = main_rfh->GetApplicationWindowHost();
  //  params->main_frame_widget_routing_id = main_rwh->GetRoutingID();
  //}
  //params->session_storage_namespace_id =
  //    delegate_->GetSessionStorageNamespace(instance_.get())->id();
  // Ensure the ApplicationWindow sets its opener correctly.
  //params->opener_frame_route_id = opener_frame_route_id;
  params->swapped_out = !is_active_;
  //params->replicated_frame_state = replicated_frame_state;
  //params->proxy_routing_id = proxy_route_id;
  params->hidden = is_active_ ? is_hidden()
                              : delegate()->IsHidden();
  params->never_visible = delegate_->IsNeverVisible();
  //params->window_was_created_with_opener = window_was_created_with_opener;
  //if (main_rfh) {
  //  params->has_committed_real_load =
  //      main_rfh->frame_tree_node()->has_committed_real_load();
  //}
  params->enable_auto_resize = auto_resize_enabled();
  params->min_size = min_size_for_auto_resize();
  params->max_size = max_size_for_auto_resize();
  params->page_zoom_level = delegate_->GetPendingPageZoomLevel();
  
  GetVisualProperties(&params->initial_size);
  SetInitialApplicationSizeParams(params->initial_size);

  params->features = blink::mojom::WindowFeatures::New();
  const gfx::Size& window_size = params->initial_size.new_size;      
  params->features->width = window_size.width();
  params->features->height = window_size.height();
  service_manager::mojom::InterfaceProviderPtrInfo
      main_frame_interface_provider_info;
  BindInterfaceProviderRequest(
      mojo::MakeRequest(&main_frame_interface_provider_info));
  params->interface_provider = std::move(main_frame_interface_provider_info);

  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendCreateApplicationWindowOnIO,
      io_weak_this_,
      base::Passed(std::move(params))));

  // Let our delegate know that we created a ApplicationWindow.
  DispatchApplicationWindowCreated();

  if (!GetView()) {
    ApplicationWindowHostView* rwhv =
      new ApplicationWindowHostViewAura(this);
    rwhv->Hide();
  }

  //if (proxy_routing_id != MSG_ROUTING_NONE) {
  //  RenderFrameProxyHost* proxy = RenderFrameProxyHost::FromID(
  //      GetProcess()->GetID(), proxy_routing_id);
    // We have also created a RenderFrameProxy in CreateFrame above, so
    // remember that.
  //  proxy->set_render_frame_proxy_created(true);
  //}

  // The renderer now has a RenderFrame for this RenderFrameHost.  Note that
  // this path is only used for out-of-process iframes.  Main frame RenderFrames
  // are created with their RenderView, and same-site iframes are created at the
  // time of OnCreateChildFrame.
  
  // NOTE: moved to after process signals it has started
  //SetApplicationWindowCreated(true);

  // Since this method can create the main RenderFrame in the renderer process,
  // set the proper state on its corresponding RenderFrameHost.
  //if (main_rfh)
  //  main_rfh->SetRenderFrameCreated(true);
  delegate()->SendScreenRects();

  PostApplicationWindowReady();

  return true;
}

void ApplicationWindowHost::SendCreateApplicationWindowOnIO(common::mojom::CreateNewWindowParamsPtr params) {
  DCHECK(HostThread::CurrentlyOn(HostThread::IO));

  // service_manager::mojom::InterfaceProviderPtr interface_provider;
  // auto interface_provider_request(mojo::MakeRequest(&interface_provider));
  // interface_provider.PassInterface().PassHandle();
  //common::mojom::RendererAudioOutputStreamFactoryPtr factory_ptr = CreateAudioOutputStreamFactoryBinding();
  //common::mojom::RendererAudioOutputStreamFactoryPtrInfo factory_info = factory_ptr.PassInterface();
  //params->audio_output_stream_factory = std::move(factory_info);
  
  GetProcess()->GetApplicationInterface()->CreateNewWindow(std::move(params));
}

// common::mojom::RendererAudioOutputStreamFactoryPtr ApplicationWindowHost::CreateAudioOutputStreamFactoryBinding() {
//   DCHECK(HostThread::CurrentlyOn(HostThread::IO));
//   if (!in_content_audio_output_stream_factory_) {
//     CreateAudioOutputStreamFactoryInternal();//std::move(request));
//   }
//   return in_content_audio_output_stream_factory_->CreateBinding();
// }

void ApplicationWindowHost::SetIsActive(bool is_active) {
  if (is_active_ == is_active)
    return;
  is_active_ = is_active;
  UpdatePriority();  
}

void ApplicationWindowHost::DispatchApplicationWindowCreated() {
  if (has_notified_about_creation_)
    return;

  // Only send ApplicationWindowCreated if there is a current or pending main frame
  // RenderFrameHost (current or pending).  Don't send notifications if this is
  // an inactive RVH that is either used by subframe RFHs or not used by any
  // RFHs at all (e.g., when created for the opener chain).
  //
  // While it would be nice to uniformly dispatch ApplicationWindowCreated for all
  // cases, some existing code (e.g., ExtensionViewHost) assumes it won't
  // hear ApplicationWindowCreated for a RVH created for an OOPIF.
  //
  // TODO(alexmos, creis): Revisit this as part of migrating ApplicationWindowCreated
  // usage to RenderFrameCreated.  See https://crbug.com/763548.
  //if (!GetMainFrame())
  //  return;

  delegate_->ApplicationWindowCreated(this);
  has_notified_about_creation_ = true;
}

void ApplicationWindowHost::ClosePage() {
  //DLOG(INFO) << "ApplicationWindowHost::ClosePage";
  is_waiting_for_close_ack_ = true;

  //bool is_javascript_dialog_showing = delegate_->IsJavaScriptDialogShowing();

  // If there is a JavaScript dialog up, don't bother sending the renderer the
  // close event because it is known unresponsive, waiting for the reply from
  // the dialog.
  if (IsApplicationWindowLive()) {// && !is_javascript_dialog_showing) {
    close_timeout_->Start(TimeDelta::FromMilliseconds(kUnloadTimeoutMS));

    // TODO(creis): Should this be moved to Shutdown?  It may not be called for
    // ApplicationWindowHosts that have been swapped out.
#if !defined(OS_ANDROID)
    HostZoomMap::Get()
        ->WillCloseApplicationWindow(GetProcess()->GetID(), GetRoutingID());
#endif

    //Send(new ViewMsg_ClosePage(GetRoutingID()));
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE, 
      base::BindOnce(
        &ApplicationWindowHost::SendClosePage,
        io_weak_this_)
    );
  } else {
    // This ApplicationWindowHost doesn't have a live renderer, so just skip the close
    // event and close the page.
    ClosePageIgnoringUnloadEvents();
  }
}

void ApplicationWindowHost::ClosePageIgnoringUnloadEvents() {
  close_timeout_->Stop();
  is_waiting_for_close_ack_ = false;

  sudden_termination_allowed_ = true;
  delegate_->Close(this);
}

// Tells the renderer view to focus the first (last if reverse is true) node.
void ApplicationWindowHost::SetInitialFocus(bool reverse) {
  //Send(new ViewMsg_SetInitialFocus(GetRoutingID(), reverse));
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendSetInitialFocus,
      io_weak_this_,
      reverse)
  );
}

void ApplicationWindowHost::SetInitialApplicationSizeParams(
    const common::VisualProperties& visual_properties) {
  resize_ack_pending_ = visual_properties.needs_resize_ack;

  old_visual_properties_ =
      std::make_unique<common::VisualProperties>(visual_properties);
}

bool ApplicationWindowHost::SuddenTerminationAllowed() const {
  return sudden_termination_allowed_ ||
      GetProcess()->SuddenTerminationAllowed();
}

void ApplicationWindowHost::ShutdownAndDestroy() {
  // We can't release the SessionStorageNamespace until our peer
  // in the renderer has wound down.
  if (GetProcess()->HasConnection()) {
    //RenderProcessHostImpl::ReleaseOnCloseACK(
    ApplicationProcessHost::ReleaseOnCloseACK(
        GetProcess(),
       // delegate_->GetSessionStorageNamespaceMap(),
        GetRoutingID());
  }

  // GetWidget()->ShutdownAndDestroyWindow(false);
  ShutdownAndDestroyWindow(false);
  delete this;
}

void ApplicationWindowHost::ShutdownAndDestroyWindow(bool also_delete) {
  CancelKeyboardLock();
  RejectMouseLockOrUnlockIfNecessary();

  if (process_->HasConnection() && GetApplicationWindowInterface()) {
    // Tell the renderer object to close.
    //bool rv = Send(new ViewMsg_Close(routing_id_));
    //DCHECK(rv);
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE, 
      base::BindOnce(
        &ApplicationWindowHost::SendClose,
        io_weak_this_)
    );
  }

  Destroy(also_delete);
}

void ApplicationWindowHost::Destroy(bool also_delete) {
  
  DCHECK(!destroyed_);
  destroyed_ = true;

  in_content_audio_input_stream_factory_.reset();
  in_content_audio_output_stream_factory_.reset();
  if (audio_service_audio_output_stream_factory_) {
    audio_service_audio_output_stream_factory_.reset();
  }
  if (audio_service_audio_input_stream_factory_) {
    audio_service_audio_input_stream_factory_.reset();
  }

  media_stream_dispatcher_host_.reset();
  media_interface_proxy_.reset();

  input_device_change_observer_.reset();

  renderer_compositor_frame_sink_.reset();

  mouse_event_callbacks_.clear();

  key_press_event_callbacks_.clear();

  for (auto& observer : observers_)
    observer.ApplicationWindowHostDestroyed(this);
  NotificationService::current()->Notify(
      NOTIFICATION_RENDER_WIDGET_HOST_DESTROYED, Source<ApplicationWindowHost>(this),
      NotificationService::NoDetails());

  // Tell the view to die.
  // Note that in the process of the view shutting down, it can call a ton
  // of other messages on us.  So if you do any other deinitialization here,
  // do it after this call to view_->Destroy().
  if (view_) {
    view_->Destroy();
    view_.reset();
  }

  // The display compositor has ownership of shared memory for each
  // SharedBitmapId that has been reported from the client. Since the client is
  // gone that memory can be freed. If we don't then it would leak.
  for (const auto& id : owned_bitmaps_)
    viz::ServerSharedBitmapManager::current()->ChildDeletedSharedBitmap(id);

  process_->RemoveWindow(this);
  process_->RemoveRoute(routing_id_);
  g_routing_id_window_map.Get().erase(
      ApplicationWindowHostID(process_->GetID(), routing_id_));

  if (delegate_)
    delegate_->ApplicationWindowDeleted(this);

  if (also_delete) {
    //CHECK(!owner_delegate_);
    delete this;
  }
}

void ApplicationWindowHost::DestroyOnIO() {
  //application_window_interface_.reset();
  //application_window_host_binding_.reset();
  //compositor_frame_sink_binding_.reset();
  associated_widget_input_handler_.reset();
  widget_input_handler_.reset();
  input_target_client_.reset();
  //application_window_interface_.reset();
  application_window_host_binding_.Close();
  application_window_interface_.reset();

  io_weak_factory_.InvalidateWeakPtrs();
}

// Creates a new ApplicationWindow with the given route id.  |popup_type| indicates
// if this widget is a popup and what kind of popup it is (select, autofill).
void ApplicationWindowHost::CreateNewWindow(int32_t route_id,
                     //mojom::WidgetPtr widget,
                     blink::WebPopupType popup_type) {
  //DLOG(INFO) << "ApplicationWindowHost::CreateNewWindow";
  delegate_->CreateNewWindow(GetProcess()->GetID(), route_id, popup_type);//, std::move(widget),
                             //popup_type);
}

// Creates a full screen ApplicationWindow.
void ApplicationWindowHost::CreateNewFullscreenWindow(int32_t route_id) {//, mojom::WidgetPtr widget) {
  //DLOG(INFO) << "ApplicationWindowHost::CreateNewFullscreenWindow";
  delegate_->CreateNewFullscreenWindow(GetProcess()->GetID(), route_id);//,
                                       //std::move(widget));
}

// Send ApplicationWindowReady to observers once the process is launched, but not
// re-entrantly.
void ApplicationWindowHost::PostApplicationWindowReady() {
  GetProcess()->PostTaskWhenProcessIsReady(
    base::BindOnce(
      &ApplicationWindowHost::ApplicationWindowReady, 
      weak_factory_.GetWeakPtr()));
}

void ApplicationWindowHost::ApplicationWindowReady() {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  delegate_->ApplicationWindowReady(this);
  BeginNavigation(delegate_->GetURL().spec());
}

void ApplicationWindowHost::ApplicationWindowDidInit() {
  //DLOG(INFO) << "ApplicationWindowHost::ApplicationWindowDidInit";
  PostApplicationWindowReady();
}

void ApplicationWindowHost::SetIsLoading(bool is_loading) {
  //DLOG(INFO) << "ApplicationWindowHost::SetIsLoading " << is_loading;
  is_loading_ = is_loading;
  if (view_)
    view_->SetIsLoading(is_loading);
}

//void ApplicationWindowHost::ApplicationWindowWillSetIsLoading(bool is_loading) {
  // if (ResourceDispatcherHostImpl::Get()) {
  //   HostThread::PostTask(
  //       HostThread::IO, FROM_HERE,
  //       base::BindOnce(
  //           &ResourceDispatcherHostImpl::OnApplicationWindowHostSetIsLoading,
  //           base::Unretained(ResourceDispatcherHostImpl::Get()),
  //           GetProcess()->GetID(), GetRoutingID(), is_loading));
  // }
//}

//void ApplicationWindowHost::ApplicationWindowGotFocus() {
//  ApplicationWindowHostDelegateView* view = delegate_->GetDelegateView();
//  if (view)
//    view->GotFocus(this); // GetWidget());
//}

//void ApplicationWindowHost::ApplicationWindowLostFocus() {
//  ApplicationWindowHostDelegateView* view = delegate_->GetDelegateView();
//  if (view)
//    view->LostFocus(this);//GetWidget());
//}

//void ApplicationWindowHost::ApplicationWindowDidForwardMouseEvent(
//    const blink::WebMouseEvent& mouse_event) {
//  if (mouse_event.GetType() == WebInputEvent::kMouseWheel && ignore_input_events()) {
//    delegate_->OnIgnoredUIEvent();
//  }  
//}

// bool ApplicationWindowHost::MayApplicationWindowForwardKeyboardEvent(
//     const NativeWebKeyboardEvent& key_event) {
//   if (ignore_input_events()) {
//     if (key_event.GetType() == WebInputEvent::kRawKeyDown)
//       delegate_->OnIgnoredUIEvent();
//     return false;
//   }
//   return true;
// }

bool ApplicationWindowHost::ShouldContributePriorityToProcess() {
  return is_active_;
}

void ApplicationWindowHost::ClosePageTimeout() {
  if (delegate_->ShouldIgnoreUnresponsiveApplication())
    return;

  ClosePageIgnoringUnloadEvents();
}

// void ApplicationWindowHost::OnShowView(int route_id,
//                 WindowOpenDisposition disposition,
//                 const gfx::Rect& initial_rect,
//                 bool user_gesture) {

// }

/*
 * end of ApplicationWindowHost section
 */

void ApplicationWindowHost::OnKeyboardEventAck(const NativeWebKeyboardEventWithLatencyInfo& event,
                                               common::InputEventAckSource ack_source,
                                               common::InputEventAckState ack_result) {
  // HostThread::PostTask(
  //   HostThread::UI, 
  //   FROM_HERE, 
  //   base::BindOnce(
  //     &ApplicationWindowHost::OnKeyboardEventAckImpl,
  //     base::Unretained(this),
  //     event,
  //     ack_source,
  //     ack_result));
  OnKeyboardEventAckImpl(event, ack_source, ack_result);
}

void ApplicationWindowHost::OnKeyboardEventAckImpl(const NativeWebKeyboardEventWithLatencyInfo& event,
                                                   common::InputEventAckSource ack_source,
                                                   common::InputEventAckState ack_result) {
  latency_tracker_.OnInputEventAck(event.event, &event.latency, ack_result);
  for (auto& input_event_observer : input_event_observers_)
    input_event_observer.OnInputEventAck(ack_source, ack_result, event.event);

  const bool processed = (common::INPUT_EVENT_ACK_STATE_CONSUMED == ack_result);

  // We only send unprocessed key event upwards if we are not hidden,
  // because the user has moved away from us and no longer expect any effect
  // of this key event.
  if (delegate_ && !processed && !is_hidden() && !event.event.skip_in_browser) {
    delegate_->HandleKeyboardEvent(event.event);

    // WARNING: This RenderWidgetHostImpl can be deallocated at this point
    // (i.e.  in the case of Ctrl+W, where the call to
    // HandleKeyboardEvent destroys this RenderWidgetHostImpl).
  }
}

void ApplicationWindowHost::OnMouseEventAck(const common::MouseEventWithLatencyInfo& mouse_event,
                                            common::InputEventAckSource ack_source,
                                            common::InputEventAckState ack_result) {
  // HostThread::PostTask(
  //   HostThread::UI,
  //   FROM_HERE, 
  //   base::BindOnce(
  //     &ApplicationWindowHost::OnMouseEventAckImpl,
  //     base::Unretained(this),
  //     mouse_event,
  //     ack_source,
  //     ack_result));
  OnMouseEventAckImpl(mouse_event, ack_source, ack_result);
}

void ApplicationWindowHost::OnMouseEventAckImpl(const common::MouseEventWithLatencyInfo& mouse_event,
                                                common::InputEventAckSource ack_source,
                                                common::InputEventAckState ack_result) {
  latency_tracker_.OnInputEventAck(mouse_event.event, &mouse_event.latency,
                                   ack_result);
  for (auto& input_event_observer : input_event_observers_)
    input_event_observer.OnInputEventAck(ack_source, ack_result,
                                         mouse_event.event);
}

void ApplicationWindowHost::OnWheelEventAck(const common::MouseWheelEventWithLatencyInfo& wheel_event,
                                            common::InputEventAckSource ack_source,
                                            common::InputEventAckState ack_result) {
  // HostThread::PostTask(
  //   HostThread::UI, 
  //   FROM_HERE, 
  //   base::BindOnce(
  //     &ApplicationWindowHost::OnWheelEventAckImpl,
  //     base::Unretained(this),
  //     wheel_event,
  //     ack_source,
  //     ack_result));
  OnWheelEventAckImpl(wheel_event, ack_source, ack_result);
}

void ApplicationWindowHost::OnWheelEventAckImpl(const common::MouseWheelEventWithLatencyInfo& wheel_event,
                                                common::InputEventAckSource ack_source,
                                                common::InputEventAckState ack_result) {
  latency_tracker_.OnInputEventAck(wheel_event.event, &wheel_event.latency,
                                   ack_result);
  for (auto& input_event_observer : input_event_observers_)
    input_event_observer.OnInputEventAck(ack_source, ack_result,
                                         wheel_event.event);

  if (!is_hidden() && view_) {
    if (ack_result != common::INPUT_EVENT_ACK_STATE_CONSUMED &&
        delegate_ && delegate_->HandleWheelEvent(wheel_event.event)) {
      ack_result = common::INPUT_EVENT_ACK_STATE_CONSUMED;
    }
    view_->WheelEventAck(wheel_event.event, ack_result);
  }
}

void ApplicationWindowHost::OnTouchEventAck(const common::TouchEventWithLatencyInfo& event,
                                            common::InputEventAckSource ack_source,
                                            common::InputEventAckState ack_result) {
  // HostThread::PostTask(
  //   HostThread::UI, 
  //   FROM_HERE, 
  //   base::BindOnce(
  //     &ApplicationWindowHost::OnTouchEventAckImpl,
  //     base::Unretained(this),
  //     event,
  //     ack_source,
  //     ack_result));
  OnTouchEventAckImpl(event, ack_source, ack_result);
}

void ApplicationWindowHost::OnTouchEventAckImpl(const common::TouchEventWithLatencyInfo& event,
                                            common::InputEventAckSource ack_source,
                                            common::InputEventAckState ack_result) {
  latency_tracker_.OnInputEventAck(event.event, &event.latency, ack_result);
  for (auto& input_event_observer : input_event_observers_)
    input_event_observer.OnInputEventAck(ack_source, ack_result, event.event);

  if (touch_emulator_ &&
      touch_emulator_->HandleTouchEventAck(event.event, ack_result)) {
    return;
  }

  if (view_)
    view_->ProcessAckedTouchEvent(event, ack_result);
}

void ApplicationWindowHost::OnGestureEventAck(const common::GestureEventWithLatencyInfo& event,
                                              common::InputEventAckSource ack_source,
                                              common::InputEventAckState ack_result) {
  // HostThread::PostTask(
  //   HostThread::UI, 
  //   FROM_HERE, 
  //   base::BindOnce(
  //     &ApplicationWindowHost::OnGestureEventAckImpl,
  //     base::Unretained(this),
  //     event,
  //     ack_source,
  //     ack_result));
  OnGestureEventAckImpl(event, ack_source, ack_result);
}

void ApplicationWindowHost::OnGestureEventAckImpl(const common::GestureEventWithLatencyInfo& event,
                                              common::InputEventAckSource ack_source,
                                              common::InputEventAckState ack_result) {
  latency_tracker_.OnInputEventAck(event.event, &event.latency, ack_result);
  for (auto& input_event_observer : input_event_observers_)
    input_event_observer.OnInputEventAck(ack_source, ack_result, event.event);

  if (touch_emulator_)
    touch_emulator_->OnGestureEventAck(event.event);

  if (view_)
    view_->GestureEventAck(event.event, ack_result);
}

void ApplicationWindowHost::OnUnexpectedEventAck(UnexpectedEventAckType type) {
  if (type == BAD_ACK_MESSAGE) {
    bad_message::ReceivedBadMessage(process_, bad_message::RWH_BAD_ACK_MESSAGE);
  } else if (type == UNEXPECTED_EVENT_TYPE) {
    suppress_events_until_keydown_ = false;
  }
}

// RenderFrameHost

void ApplicationWindowHost::CopyImageAt(int x, int y) {
  gfx::PointF point_in_view =
      GetView()->TransformRootPointToViewCoordSpace(gfx::PointF(x, y));
  //Send(new FrameMsg_CopyImageAt(routing_id_, point_in_view.x(),
  //                              point_in_view.y()));
  
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendCopyImageAt,
      io_weak_this_,
      point_in_view.x(),
      point_in_view.y())
  );
}

void ApplicationWindowHost::SaveImageAt(int x, int y) {
  gfx::PointF point_in_view =
      GetView()->TransformRootPointToViewCoordSpace(gfx::PointF(x, y));
  //Send(new FrameMsg_SaveImageAt(routing_id_, point_in_view.x(),
  //                              point_in_view.y()));
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendSaveImageAt,
      io_weak_this_,
      point_in_view.x(),
      point_in_view.y())
  );
}

void ApplicationWindowHost::ApplicationIsUnresponsive() {
  //DLOG(INFO) << "ApplicationWindowHost::ApplicationIsUnresponsive";
  NotificationService::current()->Notify(
      NOTIFICATION_RENDER_WIDGET_HOST_HANG,
      Source<ApplicationWindowHost>(this),
      NotificationService::NoDetails());
  is_unresponsive_ = true;

  if (delegate_)
    delegate_->ApplicationUnresponsive(this);

  // Do not add code after this since the Delegate may delete this
  // RenderWidgetHostImpl in RendererUnresponsive.
}

void ApplicationWindowHost::ApplicationIsResponsive() {
  if (is_unresponsive_) {
    is_unresponsive_ = false;
    if (delegate_)
      delegate_->ApplicationResponsive(this);
  }
}

void ApplicationWindowHost::ClearDisplayedGraphics() {
  //DLOG(INFO) << "ApplicationWindowHost::ClearDisplayedGraphics";
  //NotifyNewContentRenderingTimeoutForTesting();
  if (view_)
    view_->ClearCompositorFrame();
}

bool ApplicationWindowHost::HasSelection() {
  return has_selection_;
}

// code from RenderFrameHost
void ApplicationWindowHost::GetInterface(
    const std::string& interface_name,
    mojo::ScopedMessagePipeHandle interface_pipe) {
  // Requests are serviced on |document_scoped_interface_provider_binding_|. It
  // is therefore safe to assume that every incoming interface request is coming
  // from the currently active document in the corresponding RenderFrame.
  if (!registry_ ||
      !registry_->TryBindInterface(interface_name, &interface_pipe)) {
    delegate_->OnInterfaceRequest(this, interface_name, &interface_pipe);
    //TryBindFrameInterface(interface_name, &interface_pipe, this);
    //if (interface_pipe.is_valid() &&
    //    !TryBindFrameInterface(interface_name, &interface_pipe, this)) {
    //  GetContentClient()->browser()->BindInterfaceRequestFromFrame(
    //      this, interface_name, std::move(interface_pipe));
    //}
  }
}

// bool ApplicationWindowHost::CreateRenderFrame(int proxy_routing_id,
//                          int opener_routing_id,
//                          int parent_routing_id,
//                          int previous_sibling_routing_id) {
//   TRACE_EVENT0("navigation", "RenderFrameHostImpl::CreateRenderFrame");
//   //DCHECK(!IsRenderFrameLive()) << "Creating frame twice";

//   // The process may (if we're sharing a process with another host that already
//   // initialized it) or may not (we have our own process or the old process
//   // crashed) have been initialized. Calling Init multiple times will be
//   // ignored, so this is safe.
//   if (!GetProcess()->Init(base::UUID::generate()))
//     return false;

//   DCHECK(GetProcess()->HasConnection());

//   service_manager::mojom::InterfaceProviderPtr interface_provider;
//   BindInterfaceProviderRequest(mojo::MakeRequest(&interface_provider));

//   mojom::CreateFrameParamsPtr params = mojom::CreateFrameParams::New();
//   params->interface_provider = interface_provider.PassInterface();
//   params->routing_id = routing_id_;
//   params->proxy_routing_id = proxy_routing_id;
//   params->opener_routing_id = opener_routing_id;
//   params->parent_routing_id = parent_routing_id;
//   params->previous_sibling_routing_id = previous_sibling_routing_id;
//   //params->replication_state = frame_tree_node()->current_replication_state();
//   //params->devtools_frame_token = frame_tree_node()->devtools_frame_token();

//   // Normally, the replication state contains effective frame policy, excluding
//   // sandbox flags and feature policy attributes that were updated but have not
//   // taken effect. However, a new RenderFrame should use the pending frame
//   // policy, since it is being created as part of the navigation that will
//   // commit it. (I.e., the RenderFrame needs to know the policy to use when
//   // initializing the new document once it commits).
//   //params->replication_state.frame_policy =
//   //    frame_tree_node()->pending_frame_policy();

//   //params->frame_owner_properties =
//   //    FrameOwnerProperties(frame_tree_node()->frame_owner_properties());

//   //params->has_committed_real_load =
//   //    frame_tree_node()->has_committed_real_load();

//   params->widget_params = mojom::CreateFrameWidgetParams::New();
//   if (application_window_host_) {
//     params->widget_params->routing_id = application_window_host_->GetRoutingID();
//     params->widget_params->hidden = application_window_host_->is_hidden();
//   } else {
//     // MSG_ROUTING_NONE will prevent a new RenderWidget from being created in
//     // the renderer process.
//     params->widget_params->routing_id = MSG_ROUTING_NONE;
//     params->widget_params->hidden = true;
//   }

//   //GetProcess()->GetRendererInterface()->CreateFrame(std::move(params));
//   GetProcess()->GetApplicationInterface()->CreateFrame(std::move(params));

//   // The ApplicationWindowHost takes ownership of its view. It is tied to the
//   // lifetime of the current RenderProcessHost for this RenderFrameHost.
//   // TODO(avi): This will need to change to initialize a
//   // ApplicationWindowHostViewAura for the main frame once RenderViewHostImpl has-a
//   // ApplicationWindowHost. https://crbug.com/545684
//   if (parent_routing_id != MSG_ROUTING_NONE && application_window_host_) {
//     ApplicationWindowHostView* rwhv =
//         ApplicationWindowHostViewChildFrame::Create(application_window_host_);
//     rwhv->Hide();
//   }

//   //if (proxy_routing_id != MSG_ROUTING_NONE) {
//   //  RenderFrameProxyHost* proxy = RenderFrameProxyHost::FromID(
//   //      GetProcess()->GetID(), proxy_routing_id);
//     // We have also created a RenderFrameProxy in CreateFrame above, so
//     // remember that.
//   //  proxy->set_render_frame_proxy_created(true);
//   //}

//   // The renderer now has a RenderFrame for this RenderFrameHost.  Note that
//   // this path is only used for out-of-process iframes.  Main frame RenderFrames
//   // are created with their RenderView, and same-site iframes are created at the
//   // time of OnCreateChildFrame.
//   SetRenderFrameCreated(true);

//   return true;
// }

void ApplicationWindowHost::SetApplicationWindowCreated(bool created) {
  // We should not create new RenderFrames while our delegate is being destroyed
  // (e.g., via a WebContentsObserver during WebContents shutdown).  This seems
  // to have caused crashes in https://crbug.com/717650.
//  if (created && delegate_)
//    CHECK(!delegate_->IsBeingDestroyed());

  bool was_created = application_window_created_;
  //application_window_created_ = created;

  // If the current status is different than the new status, the delegate
  // needs to be notified.
  if (delegate_ && (created != was_created)) {
    if (created) {
      // Theres no need.. as we already are the instantiated interface
      // theres no need for a second child interface as in Widget=>Frame
      // relationship
      if (HostThread::CurrentlyOn(HostThread::IO)) {
        HostThread::PostTask(
          HostThread::UI, 
          FROM_HERE, 
          base::BindOnce(
            &ApplicationWindowHostDelegate::ApplicationWindowCreated, 
            base::Unretained(delegate_),
            base::Unretained(this)));
      } else {
        delegate_->ApplicationWindowCreated(this);
      }
    } else {
      if (HostThread::CurrentlyOn(HostThread::IO)) {
        HostThread::PostTask(
          HostThread::UI, 
          FROM_HERE, 
          base::BindOnce(
            &ApplicationWindowHostDelegate::ApplicationWindowDeleted, 
            base::Unretained(delegate_),
            base::Unretained(this)));
      } else {
        delegate_->ApplicationWindowDeleted(this);
      }
    }
  }

  if (created) {
    
    // this is done on application process host..
    // no need to do this here again

    //remote_interfaces_->GetInterface(&application_window_interface_);

    if (widget_input_handler_) {
      common::mojom::WindowInputHandlerAssociatedPtr widget_handler;
      common::mojom::WindowInputHandlerHostPtr host;
      common::mojom::WindowInputHandlerHostRequest host_request =
          mojo::MakeRequest(&host);
      widget_input_handler_->GetWindowInputHandler(
          mojo::MakeRequest(&widget_handler), std::move(host));
      //DLOG(INFO) << "ApplicationWindowHost::SetApplicationWindowCreated: SetWindowInputHandler()";
      SetWindowInputHandler(std::move(widget_handler),
                            std::move(host_request));
    }
    //application_window_host_->input_router()->SetFrameTreeNodeId(
    //    frame_tree_node_->frame_tree_node_id());
    
    //viz::mojom::InputTargetClientPtr input_target_client;
    //remote_interfaces_->GetInterface(&input_target_client);
    //SetInputTargetClient(std::move(input_target_client));
    HostThread::PostTask(
      HostThread::IO,
      FROM_HERE,
      base::BindOnce(&ApplicationWindowHost::SetInputTargetClientOnIO,
        io_weak_this_));
    
    application_initialized_ = true;
    if (HostThread::CurrentlyOn(HostThread::IO)) {  
      HostThread::PostTask(
        HostThread::UI, 
        FROM_HERE, 
        base::BindOnce(
          &ApplicationWindowHost::OnApplicationWindowInit, 
          weak_this_)); 
    } else {
      OnApplicationWindowInit();
    }
  }

  //if (enabled_bindings_ && created) {
  //  if (!frame_bindings_control_)
  //    GetRemoteAssociatedInterfaces()->GetInterface(&frame_bindings_control_);
  //  frame_bindings_control_->AllowBindings(enabled_bindings_);
  //}
}

void ApplicationWindowHost::SetInputTargetClientOnIO() {
  viz::mojom::InputTargetClientPtr input_target_client;
  remote_interfaces_->GetInterface(&input_target_client);
  SetInputTargetClient(std::move(input_target_client));
}

void ApplicationWindowHost::OnApplicationWindowInit() {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));
  if (view_) {
    view_->OnApplicationWindowInit();
  }

  if (!CreateApplicationWindow()) {
    //DLOG(ERROR) << "ApplicationWindowHost::WindowCreatedAck: CreateApplicationWindow() failed";
    return;
  }
}

void ApplicationWindowHost::SetInputTargetClient(
    viz::mojom::InputTargetClientPtr input_target_client) {
  input_target_client_ = std::move(input_target_client);
}

void ApplicationWindowHost::OnAudibleStateChanged(bool is_audible) {
  if (is_audible_ == is_audible)
    return;
  if (is_audible)
    GetProcess()->OnMediaStreamAdded();
  else
    GetProcess()->OnMediaStreamRemoved();
  is_audible_ = is_audible;

  GetFrameResourceCoordinator()->SetAudibility(is_audible_);
}

void ApplicationWindowHost::SwapOut(ApplicationFrame* proxy, bool is_loading) {
  //DLOG(INFO) << "ApplicationWindowHost::SwapOut";
  // The end of this event is in OnSwapOutACK when the RenderFrame has completed
  // the operation and sends back an IPC message.
  // The trace event may not end properly if the ACK times out.  We expect this
  // to be fixed when RenderViewHostImpl::OnSwapOut moves to RenderFrameHost.
  //TRACE_EVENT_ASYNC_BEGIN1("navigation", "RenderFrameHostImpl::SwapOut", this,
  //                         "frame_tree_node",
  //                         frame_tree_node_->frame_tree_node_id());

  // If this RenderFrameHost is already pending deletion, it must have already
  // gone through this, therefore just return.
  if (!is_active()) {
    NOTREACHED() << "RFH should be in default state when calling SwapOut.";
    return;
  }

  if (swapout_event_monitor_timeout_) {
    swapout_event_monitor_timeout_->Start(base::TimeDelta::FromMilliseconds(
       kUnloadTimeoutMS));
  }

  // There should always be a proxy to replace the old RenderFrameHost.  If
  // there are no remaining active views in the process, the proxy will be
  // short-lived and will be deleted when the SwapOut ACK is received.
  DCHECK(proxy);

  if (IsApplicationWindowLive()) {
    //FrameReplicationState replication_state =
        //proxy->frame_tree_node()->current_replication_state();
    //Send(new FrameMsg_SwapOut(routing_id_, proxy->GetRoutingID(), is_loading,
    //                          replication_state));
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE, 
      base::BindOnce(
        &ApplicationWindowHost::SendSwapOut,
        io_weak_this_,
        proxy->routing_id(),
        is_loading)
    );
  }

  //if (web_ui())
  //  web_ui()->RenderFrameHostSwappingOut();

  // TODO(nasko): If the frame is not live, the RFH should just be deleted by
  // simulating the receipt of swap out ack.
  is_waiting_for_swapout_ack_ = true;
  //if (frame_tree_node_->IsMainFrame())
  SetIsActive(false);
}

void ApplicationWindowHost::SwapOutAck() {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE,
    base::BindOnce(&ApplicationWindowHost::OnSwappedOut, 
    weak_this_));
}

void ApplicationWindowHost::OnSwappedOut() {
  
  // Ignore spurious swap out ack.
  if (!is_waiting_for_swapout_ack_) {
    return;
  }

  TRACE_EVENT_ASYNC_END0("navigation", "RenderFrameHostImpl::SwapOut", this);
  if (swapout_event_monitor_timeout_)
    swapout_event_monitor_timeout_->Stop();

  //ClearAllWebUI();

  // If this is a main frame RFH that's about to be deleted, update its RVH's
  // swapped-out state here. https://crbug.com/505887.  This should only be
  // done if the RVH hasn't been already reused and marked as active by another
  // navigation.  See https://crbug.com/823567.
  //if (frame_tree_node_->IsMainFrame() && !application_window_host_->is_active())
  if (!is_active())
    set_is_swapped_out(true);

  //bool deleted = DeleteFromPendingList(this);
  DeleteFromPendingList(this);
      //frame_tree_node_->render_manager()->DeleteFromPendingList(this);
  //DCHECK(deleted);
}

bool ApplicationWindowHost::DeleteFromPendingList(
    ApplicationWindowHost* app_window_host) {
  for (auto iter = pending_delete_frames_.begin(); 
       iter != pending_delete_frames_.end();
       iter++) {
    if ((*iter)->GetWindow() == app_window_host) {
      pending_delete_frames_.erase(iter);
      return true;
    }
  }
  return false;
}

void ApplicationWindowHost::SetFocusedFrame() {
  if (!GetApplicationWindowInterface()) {
    return;
  }
  //DLOG(INFO) << "ApplicationWindowHost::SetFocusedFrame";
  //Send(new FrameMsg_SetFocusedFrame(routing_id_));
  //GetApplicationWindowInterface()->SetFocusedFrame();
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendSetFocusedWindow,
      io_weak_this_)
  );
}
//void ApplicationWindowHost::OnDetach() {
//  frame_tree_->RemoveFrame(frame_tree_node_);
//}

//void ApplicationWindowHost::OnFrameFocused() {
//  delegate_->SetFocusedFrame(frame_tree_node_, GetSiteInstance());
//}

void ApplicationWindowHost::OnApplicationProcessGone(int status, int error_code) {
  //DLOG(INFO) << "ApplicationWindowHost::OnApplicationProcessGone";
  //if (frame_tree_node_->IsMainFrame()) {
    // Keep the termination status so we can get at it later when we
    // need to know why it died.
    app_window_termination_status_ =
        static_cast<base::TerminationStatus>(status);
    //application_window_host_->render_view_termination_status_ =
    //    static_cast<base::TerminationStatus>(status);
  //}

  // Reset frame tree state associated with this process.  This must happen
  // before RenderViewTerminated because observers expect the subframes of any
  // affected frames to be cleared first.
  //frame_tree_node_->ResetForNewProcess();

  // Reset state for the current RenderFrameHost once the FrameTreeNode has been
  // reset.
  SetApplicationWindowCreated(false);
  //InvalidateMojoConnection();
  document_scoped_interface_provider_binding_.Close();
  //SetLastCommittedUrl(GURL());

  // Execute any pending AX tree snapshot callbacks with an empty response,
  // since we're never going to get a response from this renderer.
  //for (auto& iter : ax_tree_snapshot_callbacks_)
  //  std::move(iter.second).Run(ui::AXTreeUpdate());

#if defined(OS_ANDROID)
  // Execute any pending Samsung smart clip callbacks.
  for (base::IDMap<std::unique_ptr<ExtractSmartClipDataCallback>>::iterator
           iter(&smart_clip_callbacks_);
       !iter.IsAtEnd(); iter.Advance()) {
    std::move(*iter.GetCurrentValue()).Run(base::string16(), base::string16());
  }
  smart_clip_callbacks_.Clear();
#endif  // defined(OS_ANDROID)

//  ax_tree_snapshot_callbacks_.clear();
  //javascript_callbacks_.clear();
  //visual_state_callbacks_.clear();

  // Ensure that future remote interface requests are associated with the new
  // process's channel.
  remote_associated_interfaces_.reset();

  // Any termination disablers in content loaded by the new process will
  // be sent again.
  //sudden_termination_disabler_types_enabled_ = 0;

  if (!is_active()) {
    // If the process has died, we don't need to wait for the swap out ack from
    // this RenderFrame if it is pending deletion.  Complete the swap out to
    // destroy it.
    OnSwappedOut();
  } else {
    // If this was the current pending or speculative RFH dying, cancel and
    // destroy it.
    //frame_tree_node_->render_manager()->CancelPendingIfNecessary(this);
    CancelPendingIfNecessary();
  }

  // Note: don't add any more code at this point in the function because
  // |this| may be deleted. Any additional cleanup should happen before
  // the last block of code here.
}

void ApplicationWindowHost::OnVisualStateResponse(uint64_t id) {
  //DLOG(INFO) << " \n\n ** ApplicationWindowHost::OnVisualStateResponse ** \n\n";
  VisualStateResponse(id); 
}

//void ApplicationWindowHost::OnTextSurroundingSelectionResponse(const base::string16& content,
//                                        uint32_t start_offset,
//                                        uint32_t end_offset) {
//
//}

void ApplicationWindowHost::OnUpdateTitle(
  const base::string16& title,
  blink::WebTextDirection title_direction) {
  if (title.length() > kMaxTitleChars) {
    LOG(ERROR) << "Application sent too many characters in title.";
    return;
  }

  delegate_->UpdateTitle(
      this, title, WebTextDirectionToChromeTextDirection(title_direction));
}

void ApplicationWindowHost::OnEnterFullscreen(const blink::WebFullscreenOptions& options) {
  //DLOG(INFO) << "ApplicationWindowHost::OnEnterFullscreen";
  delegate_->EnterFullscreenMode();//GetLastCommittedURL().GetOrigin());

  // The previous call might change the fullscreen state. We need to make sure
  // the renderer is aware of that, which is done via the resize message.
  // Typically, this will be sent as part of the call on the |delegate_| above
  // when resizing the native windows, but sometimes fullscreen can be entered
  // without causing a resize, so we need to ensure that the resize message is
  // sent in that case. We always send this to the main frame's widget, and if
  // there are any OOPIF widgets, this will also trigger them to resize via
  // frameRectsChanged.
  SynchronizeVisualProperties();
}

void ApplicationWindowHost::OnExitFullscreen() {
  //DLOG(INFO) << "ApplicationWindowHost::OnExitFullscreen";
  delegate_->ExitFullscreenMode(/* will_cause_resize */ true);

  // The previous call might change the fullscreen state. We need to make sure
  // the renderer is aware of that, which is done via the resize message.
  // Typically, this will be sent as part of the call on the |delegate_| above
  // when resizing the native windows, but sometimes fullscreen can be entered
  // without causing a resize, so we need to ensure that the resize message is
  // sent in that case. We always send this to the main frame's widget, and if
  // there are any OOPIF widgets, this will also trigger them to resize via
  // frameRectsChanged.
  SynchronizeVisualProperties();
}

void ApplicationWindowHost::OnShowCreatedWindow(
  Application* application,
  int pending_widget_routing_id,
  WindowOpenDisposition disposition,
  const gfx::Rect& initial_rect,
  bool user_gesture) {
  //DLOG(INFO) << "ApplicationWindowHost::OnShowCreatedWindow";
  delegate_->ShowCreatedWindow(
    application,
    GetProcess()->GetID(), 
    pending_widget_routing_id,
    disposition, 
    initial_rect, 
    user_gesture);
}

// mojom::FrameHost:
void ApplicationWindowHost::CreateNewWindowOnHost(
  common::mojom::CreateNewWindowParamsPtr params,
  CreateNewWindowOnHostCallback callback) {
  //DLOG(INFO) << "ApplicationWindowHost::CreateNewWindowOnHost";
  DCHECK(IsApplicationWindowLive());

  int app_window_route_id = params->window_id;

  delegate_->CreateNewWindow(this, delegate_->GetDomain(), delegate_->GetApplication(), GetProcess()->GetID(), false, true, *params);

  //if (main_frame_route_id == MSG_ROUTING_NONE) {
    // Opener suppressed or Javascript access disabled. Never tell the renderer
    // about the new window.
  //  std::move(callback).Run(mojom::CreateNewWindowStatus::kIgnore, nullptr);
  //  return;
  //}

  bool succeeded =
      ApplicationWindowHost::FromID(GetProcess()->GetID(), app_window_route_id) !=
      nullptr;
  if (!succeeded) {
    // If we did not create a WebContents to host the renderer-created
    // RenderFrame/RenderView/RenderWidget objects, signal failure to the
    // renderer.
    //DCHECK(!RenderFrameHost::FromID(render_process_id, main_frame_route_id));
    //DCHECK(!RenderViewHost::FromID(render_process_id, render_view_route_id));
    std::move(callback).Run(common::mojom::CreateNewWindowStatus::kIgnore, nullptr);
    return;
  }

  // The view, widget, and frame should all be routable now.
  //DCHECK(RenderViewHost::FromID(render_process_id, render_view_route_id));
  ApplicationWindowHost* rfh =
      ApplicationWindowHost::FromID(GetProcess()->GetID(), app_window_route_id);
  DCHECK(rfh);

  service_manager::mojom::InterfaceProviderPtrInfo
      main_frame_interface_provider_info;
  rfh->BindInterfaceProviderRequest(
      mojo::MakeRequest(&main_frame_interface_provider_info));

  common::mojom::CreateNewWindowReplyPtr reply = common::mojom::CreateNewWindowReply::New(
      GetProcess()->GetID(), 
      app_window_route_id,
      std::move(main_frame_interface_provider_info));
  std::move(callback).Run(common::mojom::CreateNewWindowStatus::kSuccess,
                          std::move(reply));
}

void ApplicationWindowHost::BindInterfaceProviderRequest(
    service_manager::mojom::InterfaceProviderRequest
        interface_provider_request) {
  //TODO: this is not working

  DCHECK(!document_scoped_interface_provider_binding_.is_bound());
  DCHECK(interface_provider_request.is_pending());
  document_scoped_interface_provider_binding_.Bind(
      FilterRendererExposedInterfaces(common::mojom::kNavigation_FrameSpec,
                                      GetProcess()->GetID(),
                                      std::move(interface_provider_request)));
}

void ApplicationWindowHost::DidCommitProvisionalLoad(
    common::mojom::DidCommitProvisionalLoadParamsPtr validated_params,
    service_manager::mojom::InterfaceProviderRequest
        interface_provider_request) {

  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE,
    base::BindOnce(&ApplicationWindowHost::DidCommitProvisionalLoadImpl,
                   weak_this_,
                   base::Passed(std::move(validated_params)),
                   base::Passed(std::move(interface_provider_request))));
}

void ApplicationWindowHost::DidCommitProvisionalLoadImpl(
    common::mojom::DidCommitProvisionalLoadParamsPtr validated_params,
    service_manager::mojom::InterfaceProviderRequest
        interface_provider_request) {
  //DLOG(INFO) << "ApplicationWindowHost::DidCommitProvisionalLoad";
  // DidCommitProvisionalLoad IPC should be associated with the URL being
  // committed (not with the *last* committed URL that most other IPCs are
  // associated with).
 // ScopedActiveURL scoped_active_url(
 //     validated_params->url);//,
  //    frame_tree_node()->frame_tree()->root()->current_origin());

  //ScopedCommitStateResetter commit_state_resetter(this);
  //ApplicationProcessHost* process = GetProcess();

  //TRACE_EVENT2("navigation", "RenderFrameHostImpl::DidCommitProvisionalLoad",
  //             "frame_tree_node", frame_tree_node_->frame_tree_node_id(), "url",
  //             validated_params->url.possibly_invalid_spec());

  // Notify the resource scheduler of the navigation committing.
  //NotifyResourceSchedulerOfNavigation(process->GetID(), *validated_params);

  // If we're waiting for a cross-site beforeunload ack from this renderer and
  // we receive a Navigate message from the main frame, then the renderer was
  // navigating already and sent it before hearing the FrameMsg_Stop message.
  // Treat this as an implicit beforeunload ack to allow the pending navigation
  // to continue.
  //DLOG(INFO) << "is_waiting_for_beforeunload_ack_ (" << is_waiting_for_beforeunload_ack_ << ") && unload_ack_is_for_navigation_(" << unload_ack_is_for_navigation_ << ")";
  if (is_waiting_for_beforeunload_ack_ && unload_ack_is_for_navigation_) { //&&
      //!GetParent()) {
    base::TimeTicks approx_renderer_start_time = send_before_unload_start_time_;
    //DLOG(INFO) << "calling BeforeUnloadAck";
    BeforeUnloadAck(true, approx_renderer_start_time, base::TimeTicks::Now());
  }

  // If we're waiting for an unload ack from this frame and we receive a commit
  // message, then the frame was navigating before it received the unload
  // request.  It will either respond to the unload request soon or our timer
  // will expire.  Either way, we should ignore this message, because we have
  // already committed to destroying this RenderFrameHost.  Note that we
  // intentionally do not ignore commits that happen while the current tab is
  // being closed - see https://crbug.com/805705.
  if (is_waiting_for_swapout_ack_) {
    //DLOG(INFO) << "ApplicationWindowHost::DidCommitProvisionalLoad: is_waiting_for_swapout_ack_ = TRUE. cancelling";
    return;
  }

  // Retroactive sanity check:
  // - If this is the first real load committing in this frame, then by this
  //   time the RenderFrameHost's InterfaceProvider implementation should have
  //   already been bound to a message pipe whose client end is used to service
  //   interface requests from the initial empty document.
  // - Otherwise, the InterfaceProvider implementation should at this point be
  //   bound to an interface connection servicing interface requests coming from
  //   the document of the previously committed navigation.
  DCHECK(document_scoped_interface_provider_binding_.is_bound());

  if (interface_provider_request.is_pending()) {
    // As a general rule, expect the RenderFrame to have supplied the
    // request end of a new InterfaceProvider connection that will be used by
    // the new document to issue interface requests to access RenderFrameHost
    // services.
    auto interface_provider_request_of_previous_document =
        document_scoped_interface_provider_binding_.Unbind();
  //  dropped_interface_request_logger_ =
  //      std::make_unique<DroppedInterfaceRequestLogger>(
  //          std::move(interface_provider_request_of_previous_document));
    BindInterfaceProviderRequest(std::move(interface_provider_request));
  } //else {
    // If there had already been a real load committed in the frame, and this is
    // not a same-document navigation, then both the active document as well as
    // the global object was replaced in this browsing context. The RenderFrame
    // should have rebound its InterfaceProvider to a new pipe, but failed to do
    // so. Kill the renderer, and close the old binding to ensure that any
    // pending interface requests originating from the previous document, hence
    // possibly from a different security origin, will no longer dispatched.
    //if (frame_tree_node_->has_committed_real_load()) {
    //  document_scoped_interface_provider_binding_.Close();
    //  bad_message::ReceivedBadMessage(
    //      process, bad_message::RFH_INTERFACE_PROVIDER_MISSING);
    //  return;
    //}

    // Otherwise, it is the first real load commited, for which the RenderFrame
    // is allowed to, and will re-use the existing InterfaceProvider connection
    // if the new document is same-origin with the initial empty document, and
    // therefore the global object is not replaced.
  //}

  if (!DidCommitNavigationInternal(*validated_params.get(),
                                   false /* is_same_document_navigation */)) {
    //DLOG(INFO) << "ApplicationWindowHost::DidCommitProvisionalLoad: DidCommitNavigationInternal() = false. cancelling";
    return;
  }

  // Since we didn't early return, it's safe to keep the commit state.
  //commit_state_resetter.disable();

  // For a top-level frame, there are potential security concerns associated
  // with displaying graphics from a previously loaded page after the URL in
  // the omnibar has been changed. It is unappealing to clear the page
  // immediately, but if the renderer is taking a long time to issue any
  // compositor output (possibly because of script deliberately creating this
  // situation) then we clear it after a while anyway.
  // See https://crbug.com/497588.
  //if (frame_tree_node_->IsMainFrame() && GetView()) {
    //RenderWidgetHostImpl::From(GetView()->GetRenderWidgetHost())
    //    ->DidNavigate(validated_params->content_source_id);
  //}
  
  did_receive_first_frame_after_navigation_ = false;

  if (enable_surface_synchronization_) {
    //DLOG(INFO) << "ApplicationWindowHost::DidCommitProvisionalLoad: enable_surface_synchronization_ = true. calling view_->DidNavigate()";
    // Resize messages before navigation are not acked, so reset
    // |visual_properties_ack_pending_| and make sure the next resize will be
    // acked if the last resize before navigation was supposed to be acked.
    visual_properties_ack_pending_ = false;
    if (view_) {
      view_->DidNavigate();
    }
  }
}

void ApplicationWindowHost::DidNavigate(
    const common::mojom::DidCommitProvisionalLoadParams& params,
    bool is_same_document_navigation) {
  //DLOG(INFO) << "ApplicationWindowHost::DidNavigate: theres nothing here really";
  // Keep track of the last committed URL and origin in the RenderFrameHost
  // itself.  These allow GetLastCommittedURL and GetLastCommittedOrigin to
  // stay correct even if the render_frame_host later becomes pending deletion.
  // The URL is set regardless of whether it's for a net error or not.
  //frame_tree_node_->SetCurrentURL(params.url);
  //SetLastCommittedOrigin(params.origin);

  // Separately, update the frame's last successful URL except for net error
  // pages, since those do not end up in the correct process after transfers
  // (see https://crbug.com/560511).  Instead, the next cross-process navigation
  // or transfer should decide whether to swap as if the net error had not
  // occurred.
  // TODO(creis): Remove this block and always set the URL once transfers handle
  // network errors or PlzNavigate is enabled.  See https://crbug.com/588314.
  //if (!params.url_is_unreachable)
  //  last_successful_url_ = params.url;

  // After setting the last committed origin, reset the feature policy and
  // sandbox flags in the RenderFrameHost to a blank policy based on the parent
  // frame.
  //if (!is_same_document_navigation) {
  //  ResetFeaturePolicy();
  //  active_sandbox_flags_ = frame_tree_node()->active_sandbox_flags();
  //}
}

bool ApplicationWindowHost::DidCommitNavigationInternal(
    const common::mojom::DidCommitProvisionalLoadParams& params,
    bool is_same_document_navigation) {
  //DLOG(INFO) << "ApplicationWindowHost::DidCommitNavigationInternal";
  // Sanity-check the page transition for frame type.
  //DCHECK_EQ(ui::PageTransitionIsMainFrame(validated_params->transition),
  //          !GetParent());

  //UMACommitReport(validated_params->report_type,
  //                validated_params->ui_timestamp);

  //if (!ValidateDidCommitParams(validated_params))
  //  return false;

  //if (!navigation_request_) {
    // The browser has not been notified about the start of the
    // load in this renderer yet (e.g., for same-document navigations that start
    // in the renderer). Do it now.
    // TODO(ahemery): This should never be true for cross-document navigation
    // apart from race conditions. Move to same navigation specific code when
    // the full mojo interface is in url.
    // (https://bugs.chromium.org/p/chromium/issues/detail?id=784904)
    if (!IsLoading()) {
      //bool was_loading = IsLoading();
      //is_loading_ = true;
      DidStartLoading(!is_same_document_navigation);
    }
  //}

  //if (navigation_request_)
  //  was_discarded_ = navigation_request_->request_params().was_discarded;

  // Find the appropriate NavigationHandle for this navigation.
  //std::unique_ptr<NavigationHandleImpl> navigation_handle;

  //if (is_same_document_navigation)
  //  navigation_handle =
  //      TakeNavigationHandleForSameDocumentCommit(*validated_params);
  //else
  //  navigation_handle = TakeNavigationHandleForCommit(*validated_params);
  //DCHECK(navigation_handle);

  //UpdateSiteURL(validated_params->url, validated_params->url_is_unreachable);

  //accessibility_reset_count_ = 0;
  //frame_tree_node()->navigator()->DidNavigate(this, *validated_params,
  //                                            std::move(navigation_handle),
  //                                            is_same_document_navigation);
  DidNavigate(params, is_same_document_navigation);
  //if (ui::PageTransitionIsMainFrame(params.transition)) {
    if (delegate_) {
      // When overscroll navigation gesture is enabled, a screenshot of the page
      // in its current state is taken so that it can be used during the
      // nav-gesture. It is necessary to take the screenshot here, before
      // calling RenderFrameHostManager::DidNavigateMainFrame, because that can
      // change WebContents::GetRenderViewHost to return the new host, instead
      // of the one that may have just been swapped out.
      //if (delegate_->CanOverscrollContent()) {
        // Don't take screenshots if we are staying on the same document. We
        // want same-document navigations to be super fast, and taking a
        // screenshot currently blocks GPU for a longer time than we are willing
        // to tolerate in this use case.
        //if (!is_same_document_navigation)
        //  controller_->TakeScreenshot();
      //}

      // Run tasks that must execute just before the commit.
      delegate_->DidNavigateMainFramePreCommit(is_same_document_navigation);
    }
  //}

  // DidNavigateFrame() must be called before replicating the new origin and
  // other properties to proxies.  This is because it destroys the subframes of
  // the frame we're navigating from, which might trigger those subframes to
  // run unload handlers.  Those unload handlers should still see the old
  // frame's origin.  See https://crbug.com/825283.
  //frame_tree_node->render_manager()->DidNavigateFrame(
  //    render_frame_host, params.gesture == NavigationGestureUser);
  //DLOG(INFO) << "ApplicationWindowHost::DidCommitNavigationInternal: calling CommitPendingIfNecessary..";
  DCHECK(application_frame_);
  CommitPendingIfNecessary(
    application_frame_.get(), /* we are not using this right now, but we will need it for later*/
    false);//params->gesture == NavigationGestureUser);
  // Make sure any dynamic changes to this frame's sandbox flags and feature
  // policy that were made prior to navigation take effect.
  //CommitPendingFramePolicy();

  // Save the new page's origin and other properties, and replicate them to
  // proxies, including the proxy created in DidNavigateFrame() to replace the
  // old frame in cross-process navigation cases.
  //frame_tree_node->SetCurrentOrigin(
  //    params.origin, params.has_potentially_trustworthy_unique_origin);
  //frame_tree_node->SetInsecureRequestPolicy(params.insecure_request_policy);
  //frame_tree_node->SetInsecureNavigationsSet(params.insecure_navigations_set);

  // Navigating to a new location means a new, fresh set of http headers and/or
  // <meta> elements - we need to reset CSP and Feature Policy.
  //if (!is_same_document_navigation) {
    //render_frame_host->ResetContentSecurityPolicies();
  //  frame_tree_node->ResetForNavigation();
  //}

  // Update the site of the SiteInstance if it doesn't have one yet, unless
  // assigning a site is not necessary for this URL. In that case, the
  // SiteInstance can still be considered unused until a navigation to a real
  // page.
  //SiteInstanceImpl* site_instance = render_frame_host->GetSiteInstance();
  //if (!site_instance->HasSite() &&
  //    SiteInstanceImpl::ShouldAssignSiteForURL(params.url)) {
  //  site_instance->SetSite(params.url);
  //}

  // Need to update MIME type here because it's referred to in
  // UpdateNavigationCommands() called by RendererDidNavigate() to
  // determine whether or not to enable the encoding menu.
  // It's updated only for the main frame. For a subframe,
  // RenderView::UpdateURL does not set params.contents_mime_type.
  // (see http://code.google.com/p/chromium/issues/detail?id=2929 )
  // TODO(jungshik): Add a test for the encoding menu to avoid
  // regressing it again.
  // TODO(nasko): Verify the correctness of the above comment, since some of the
  // code doesn't exist anymore. Also, move this code in the
  // PageTransitionIsMainFrame code block above.
  //if (ui::PageTransitionIsMainFrame(params.transition) && delegate_)
  //  delegate_->SetMainFrameMimeType(params.contents_mime_type);

  //int old_entry_count = controller_->GetEntryCount();
  //LoadCommittedDetails details;
  //details.is_main_frame = true;
  
  // TODO: fix
  bool is_main_frame = true;
  bool did_navigate = true;
  //bool did_navigate = controller_->RendererDidNavigate(
  //    render_frame_host, params, &details, is_same_document_navigation,
  //    navigation_handle.get());

  // If the history length and/or offset changed, update other renderers in the
  // FrameTree.
  //if (old_entry_count != controller_->GetEntryCount() ||
  //    details.previous_entry_index !=
  //        controller_->GetLastCommittedEntryIndex()) {
  //  frame_tree->root()->render_manager()->SendPageMessage(
  //      new PageMsg_SetHistoryOffsetAndLength(
  //          MSG_ROUTING_NONE, controller_->GetLastCommittedEntryIndex(),
  //          controller_->GetEntryCount()),
  //      site_instance);
  //}

  // TODO: implement ApplicationDidNavigate() as in controller_->RendererDidNavigate()

  //DidNavigate(params, is_same_document_navigation);

  // Send notification about committed provisional loads. This notification is
  // different from the NAV_ENTRY_COMMITTED notification which doesn't include
  // the actual URL navigated to and isn't sent for AUTO_SUBFRAME navigations.
  //if (details.type != NAVIGATION_TYPE_NAV_IGNORE && delegate_) {
  //  DCHECK_EQ(!render_frame_host->GetParent(),
  //            did_navigate ? details.is_main_frame : false);
  //  navigation_handle->DidCommitNavigation(
  //      params, did_navigate, details.did_replace_entry, details.previous_url,
  //      details.type, render_frame_host);
  //  navigation_handle.reset();
  //}

  if (!did_navigate)
    return false;  // No navigation happened.

  // DO NOT ADD MORE STUFF TO THIS FUNCTION! Your component should either listen
  // for the appropriate notification (best) or you can add it to
  // DidNavigateMainFramePostCommit / DidNavigateAnyFramePostCommit (only if
  // necessary, please).

  // TODO(carlosk): Move this out when PlzNavigate implementation properly calls
  // the observer methods.
  //RecordNavigationMetrics(details, params, site_instance);

  // Run post-commit tasks.
  if (delegate_) {
    if (is_main_frame) {
      delegate_->DidNavigateMainFramePostCommit(application_frame_.get(), params);
    }

    delegate_->DidNavigateAnyFramePostCommit(application_frame_.get(), params);
  }

  return true;
}

void ApplicationWindowHost::CommitPendingIfNecessary(
    ApplicationFrame* app_frame_state,
    bool was_caused_by_user_gesture) {
  if (!speculative_application_frame_) {
    // There's no speculative RenderFrameHost so it must be that the current
    // renderer process completed a navigation.

    // We should only hear this from our current renderer.
    //DCHECK_EQ(render_frame_host_.get(), render_frame_host);

    // If the current RenderFrameHost has a pending WebUI it must be committed.
    // Note: When one tries to move same-site commit logic into RenderFrameHost
    // itself, mind that the focus setting logic inside CommitPending also needs
    // to be moved there.
    //if (render_frame_host_->pending_web_ui())
    //  CommitPendingWebUI();
    //DLOG(INFO) << "CommitPendingIfNecessary: theres no speculative_application_frame_ cancelling..";
    return;
  }

  if (app_frame_state == speculative_application_frame_.get()) {
    // A cross-process navigation completed, so show the new renderer. If a
    // same-process navigation is also ongoing, it will be canceled when the
    // speculative RenderFrameHost replaces the current one in the commit call
    // below.
    //DLOG(INFO) << "CommitPendingIfNecessary: speculative_application_frame_ == given frame. Commiting..";
    //DLOG(INFO) << "ApplicationWindowHost::CommitPendingIfNecessary: calling CommitPending";
    CommitPending();
    //frame_tree_node_->ResetNavigationRequest(false, true);
   } else if (app_frame_state == application_frame_.get()) {
    //DLOG(INFO) << "CommitPendingIfNecessary: given frame == application_frame_. doing nothing.";
    
    // A same-process navigation committed while a simultaneous cross-process
    // navigation is still ongoing.

    // If the current RenderFrameHost has a pending WebUI it must be committed.
    //if (render_frame_host_->pending_web_ui())
    //  CommitPendingWebUI();

    // A navigation in the original page has taken url. Cancel the speculative
    // one. Only do it for user gesture originated navigations to prevent page
    // doing any shenanigans to prevent user from navigating.  See
    // https://code.google.com/p/chromium/issues/detail?id=75195
    // if (was_caused_by_user_gesture) {
    //  frame_tree_node_->ResetNavigationRequest(false, true);
    //  CleanUpNavigation();
    //}
   } else {
    //DLOG(INFO) << "CommitPendingIfNecessary: else branch reached. doing nothing.";
    // No one else should be sending us DidNavigate in this state.
     //NOTREACHED();
   }
}

std::unique_ptr<ApplicationFrame> ApplicationWindowHost::SetApplicationFrameState(
    std::unique_ptr<ApplicationFrame> app_frame_state) {
  // Swap the two.
  std::unique_ptr<ApplicationFrame> old_app_frame_state =
      std::move(application_frame_);
  application_frame_ = std::move(app_frame_state);

  // if (frame_tree_node_->IsMainFrame()) {
  //   // Update the count of top-level frames using this SiteInstance.  All
  //   // subframes are in the same BrowsingInstance as the main frame, so we only
  //   // count top-level ones.  This makes the value easier for consumers to
  //   // interpret.
  //   if (render_frame_host_) {
  //     render_frame_host_->Get`SiteInstance()->
  //         IncrementRelatedActiveContentsCount();
  //   }
  //   if (old_render_frame_host) {
  //     old_render_frame_host->GetSiteInstance()->
  //         DecrementRelatedActiveContentsCount();
  //   }
  // }

  return old_app_frame_state;
}


void ApplicationWindowHost::CommitPending() {
  //DLOG(INFO) << "ApplicationWindowHost::CommitPending";
  //TRACE_EVENT1("navigation", "RenderFrameHostManager::CommitPending",
  //             "FrameTreeNode id", frame_tree_node_->frame_tree_node_id());
  DCHECK(speculative_application_frame_);

#if defined(OS_MACOSX)
  // The old RenderWidgetHostView will be hidden before the new
  // RenderWidgetHostView takes its contents. Ensure that Cocoa sees this as
  // a single transaction.
  // https://crbug.com/829523
  // TODO(ccameron): This can be removed when the RenderWidgetHostViewMac uses
  // the same ui::Compositor as MacViews.
  // https://crbug.com/331669
  gfx::ScopedCocoaDisableScreenUpdates disabler;
#endif  // defined(OS_MACOSX)

  bool is_main_frame = true;//frame_tree_node_->IsMainFrame();

  // First check whether we're going to want to focus the location bar after
  // this commit.  We do this now because the navigation hasn't formally
  // committed yet, so if we've already cleared the pending WebUI the call chain
  // this triggers won't be able to figure out what's going on.  Note that
  // subframe commits should not be allowed to steal focus from the main frame
  // by focusing the location bar (see https://crbug.com/700124).
  //bool will_focus_location_bar =
  //    is_main_frame && delegate_->FocusLocationBarByDefault();

  // Remember if the page was focused so we can focus the new renderer in
  // that case.
  bool focus_render_view = //!will_focus_location_bar &&
                            application_frame_->GetView() &&
                            application_frame_->GetView()->HasFocus();

  // While the old frame is still current, remove its children from the tree.
  //frame_tree_node_->ResetForNewProcess();

  // Swap in the pending or speculative frame and make it active. Also ensure
  // the FrameTree stays in sync.
  std::unique_ptr<ApplicationFrame> old_application_frame;
  DCHECK(speculative_application_frame_);
  old_application_frame =
      SetApplicationFrameState(std::move(speculative_application_frame_));

  // For top-level frames, also hide the old RenderViewHost's view.
  // TODO(creis): As long as show/hide are on RVH, we don't want to hide on
  // subframe navigations or we will interfere with the top-level frame.
  if (is_main_frame &&
      old_application_frame->GetView()) {
    old_application_frame->GetView()->Hide();
  }

  // Make sure the size is up to date.  (Fix for bug 1079768.)
  delegate_->UpdateApplicationWindowSize(is_main_frame);

  //if (will_focus_location_bar) {
  //  delegate_->SetFocusToLocationBar(false);
  //} else if (focus_render_view && render_frame_host_->GetView()) {
  if (focus_render_view && GetView()) {
    if (is_main_frame) {
      GetView()->Focus();
    } //else {
      // The current tab has page-level focus, so we need to propagate
      // page-level focus to the subframe's renderer. Before doing that, also
      // tell the new renderer what the focused frame is if that frame is not
      // in its process, so that Blink's page-level focus logic won't try to
      // reset frame focus to the main frame.  See https://crbug.com/802156.
      // FrameTreeNode* focused_frame =
      //     frame_tree_node_->frame_tree()->GetFocusedFrame();
      // if (focused_frame && !focused_frame->IsMainFrame() &&
      //     focused_frame->current_frame_host()->GetSiteInstance() !=
      //         render_frame_host_->GetSiteInstance()) {
      //   focused_frame->render_manager()
      //       ->GetRenderFrameProxyHost(render_frame_host_->GetSiteInstance())
      //       ->SetFocusedFrame();
      // }
      // frame_tree_node_->frame_tree()->SetPageFocus(
      //     render_frame_host_->GetSiteInstance(), true);
    //}
  }

  // Notify that we've swapped RenderFrameHosts. We do this before shutting down
  // the RFH so that we can clean up RendererResources related to the RFH first.
  delegate_->NotifySwapped(//FromRenderManager(
      old_application_frame.get(),
      application_frame_.get(), 
      //render_frame_host_.get(), 
      is_main_frame);

  // Make the new view show the contents of old view until it has something
  // useful to show.
  if (is_main_frame && old_application_frame->GetView() && application_frame_->GetView()) {
    application_frame_->GetView()->TakeFallbackContentFrom(
        old_application_frame->GetView());
  }

  // The RenderViewHost keeps track of the main RenderFrameHost routing id.
  // If this is committing a main frame navigation, update it and set the
  // routing id in the RenderViewHost associated with the old RenderFrameHost
  // to MSG_ROUTING_NONE.
  if (is_main_frame) {
    ApplicationWindowHost* awh = application_frame_->GetWindow();
    //awh->set_main_frame_routing_id(application_frame_->routing_id());

    // If the RenderViewHost is transitioning from swapped out to active state,
    // it was reused, so dispatch a RenderViewReady event.  For example, this
    // is necessary to hide the sad tab if one is currently displayed.  See
    // https://crbug.com/591984.
    //
    // TODO(alexmos):  Remove this and move RenderViewReady consumers to use
    // the main frame's RenderFrameCreated instead.
    if (!awh->is_active()) {
      awh->PostApplicationWindowReady();
    }

    awh->SetIsActive(true);
    awh->set_is_swapped_out(false);
    //old_application_frame->set_main_frame_routing_id(
    //    MSG_ROUTING_NONE);
  }

  // Store the old_application_frame's current frame size so that it can be used
  // to initialize the child RWHV.
  //base::Optional<gfx::Size> old_size = old_application_frame->size();

  // Swap out the old frame now that the new one is visible.
  // This will swap it out and schedule it for deletion when the swap out ack
  // arrives (or immediately if the process isn't live).
  SwapOutOldFrame(std::move(old_application_frame));

  // Since the new RenderFrameHost is now committed, there must be no proxies
  // for its SiteInstance. Delete any existing ones.
  DeleteApplicationProxyState(application_frame_->routing_id());//render_frame_host_->GetSiteInstance());

  // If this is a subframe, it should have a CrossProcessFrameConnector
  // created already.  Use it to link the new RFH's view to the proxy that
  // belongs to the parent frame's SiteInstance. If this navigation causes
  // an out-of-process frame to return to the same process as its parent, the
  // proxy would have been removed from proxy_hosts_ above.
  // Note: We do this after swapping out the old RFH because that may create
  // the proxy we're looking for.
  //RenderFrameProxyHost* proxy_to_parent = GetProxyToParent();
  //if (proxy_to_parent) {
  //  proxy_to_parent->SetChildRWHView(render_frame_host_->GetView(),
  //                                   old_size ? &*old_size : nullptr);
  //}

  // Show the new view (or a sad tab) if necessary.
  bool new_rfh_has_view = !!application_frame_->GetView();
  if (!delegate_->IsHidden() && new_rfh_has_view) {
    // if (!is_main_frame &&
    //     !application_frame_->application_window_host->is_active()) {
    //   // Ensure that page visibility in the subframe's process is set to shown.
    //   // This is important if the subframe is using a RenderView which
    //   // started out as active and later became swapped-out, which also updates
    //   // page visibility to hidden.  Without updating page visibility the
    //   // subframe would not be able to generate compositor frames.  See
    //   // https://crbug.com/638375.
    //   //
    //   // TODO(alexmos,dcheng,lfg): This workaround should be cleaned up as part
    //   // of the view/widget split.  We should decouple page visibility from
    //   // widget visibility.
    //   ApplicationFrame* proxy =
    //       frame_tree_node_->frame_tree()
    //           ->root()
    //           ->render_manager()
    //           ->GetRenderFrameProxyHost(render_frame_host_->GetSiteInstance());
    //   // The proxy should always exist since the RenderViewHost is not active.
    //   proxy->Send(new PageMsg_WasShown(proxy->GetRoutingID()));
    // }

    // In most cases, we need to show the new view.
    application_frame_->GetView()->Show();
  }
  // The process will no longer try to exit, so we can decrement the count.
  //application_frame_->GetProcess()->RemovePendingWindow();

  if (!new_rfh_has_view) {
    // If the view is gone, then this RenderViewHost died while it was hidden.
    // We ignored the RenderProcessGone call at the time, so we should send it
    // now to make sure the sad tab shows up, etc.
    //DCHECK(!render_frame_host_->IsRenderFrameLive());
    //DCHECK(!render_frame_host_->render_view_host()->IsRenderViewLive());
    application_frame_->GetWindow()->ResetLoadingState();
    ApplicationProcessGoneForFrame();
  }

  // After all is done, there must never be a proxy in the list which has the
  // same SiteInstance as the current RenderFrameHost.
  //CHECK(!GetRenderFrameProxyHost(render_frame_host_->GetSiteInstance()));
}

void ApplicationWindowHost::ApplicationProcessGoneForFrame() {
  ResetLoadingState();
  if (is_audible_)
    GetProcess()->OnMediaStreamRemoved();
}

void ApplicationWindowHost::DeleteApplicationProxyState(int routing_id) {
  proxy_frames_.erase(routing_id);
}

void ApplicationWindowHost::SwapOutOldFrame(
    std::unique_ptr<ApplicationFrame> old_application_frame) {
  //DLOG(INFO) << "ApplicationWindowHost::SwapOutOldFrame";
  //TRACE_EVENT1("navigation", "RenderFrameHostManager::SwapOutOldFrame",
  //             "FrameTreeNode id", frame_tree_node_->frame_tree_node_id());

  // Tell the renderer to suppress any further modal dialogs so that we can swap
  // it out.  This must be done before canceling any current dialog, in case
  // there is a loop creating additional dialogs.
  //old_application_frame->SuppressFurtherDialogs();

  // Now close any modal dialogs that would prevent us from swapping out.  This
  // must be done separately from SwapOut, so that the ScopedPageLoadDeferrer is
  // no longer on the stack when we send the SwapOut message.
  delegate_->CancelModalDialogs();

  // If the old RFH is not live, just return as there is no further work to do.
  // It will be deleted and there will be no proxy created.
  if (!old_application_frame->is_live()) {
    //DLOG(INFO) << "ApplicationWindowHost::SwapOutOldFrame: old_application_frame->live = FALSE. returning early";
    return;
  }

  // Create a replacement proxy for the old RenderFrameHost. (There should not
  // be one yet.)  This is done even if there are no active frames besides this
  // one to simplify cleanup logic on the renderer side (see
  // https://crbug.com/568836 for motivation).
  std::unique_ptr<ApplicationFrame> owned_proxy = 
  std::make_unique<ApplicationFrame>(
    old_application_frame->GetWindow()->GetWeakPtr(),
    old_application_frame->routing_id(),
    true,
    old_application_frame->is_live(),
    old_application_frame->is_main_frame());
  
  ApplicationFrame* proxy = owned_proxy.get();
  proxy_frames_.emplace(std::make_pair(old_application_frame->routing_id(), std::move(owned_proxy)));

  // Reset any NavigationRequest in the RenderFrameHost. A swapped out
  // RenderFrameHost should not be trying to commit a navigation.
  //old_application_frame->GetWindow()->ResetNavigationRequests();

  // Tell the old RenderFrameHost to swap out and be replaced by the proxy.
  old_application_frame->GetWindow()->SwapOut(proxy, true);

  // SwapOut creates a RenderFrameProxy, so set the proxy to be initialized.
  //proxy->GetWindow()->set_render_frame_proxy_created(true);

  // |old_application_frame| will be deleted when its SwapOut ACK is received,
  // or when the timer times out, or when the RFHM itself is deleted (whichever
  // comes first).
  pending_delete_frames_.push_back(std::move(old_application_frame));
}

void ApplicationWindowHost::DidCommitSameDocumentNavigation(common::mojom::DidCommitProvisionalLoadParamsPtr params) {
  //DLOG(INFO) << "ApplicationWindowHost::DidCommitSameDocumentNavigation";
  //ScopedActiveURL scoped_active_url(
  //    params->url);//,
      //frame_tree_node()->frame_tree()->root()->current_origin());
  //ScopedCommitStateResetter commit_state_resetter(this);

  // If we're waiting for an unload ack from this frame and we receive a commit
  // message, then the frame was navigating before it received the unload
  // request.  It will either respond to the unload request soon or our timer
  // will expire.  Either way, we should ignore this message, because we have
  // already committed to destroying this RenderFrameHost.  Note that we
  // intentionally do not ignore commits that happen while the current tab is
  // being closed - see https://crbug.com/805705.
  // TODO(ahemery): Investigate to see if this can be removed when the
  // NavigationClient interface is implemented.
  if (is_waiting_for_swapout_ack_)
    return;

  //TRACE_EVENT2("navigation",
  //             "RenderFrameHostImpl::DidCommitSameDocumentNavigation",
  //             "frame_tree_node", frame_tree_node_->frame_tree_node_id(), "url",
  //             validated_params->url.possibly_invalid_spec());

  if (!DidCommitNavigationInternal(*params.get(),
                                   true /* is_same_document_navigation*/))
    return;

  // Since we didn't early return, it's safe to keep the commit state.
  //commit_state_resetter.disable(); 
}

service_manager::InterfaceProvider* ApplicationWindowHost::GetRemoteInterfaces() {
 return remote_interfaces_.get();
}

blink::AssociatedInterfaceProvider* ApplicationWindowHost::GetRemoteAssociatedInterfaces() {
  DCHECK(process_);
  if (!remote_associated_interfaces_) {
    common::mojom::AssociatedInterfaceProviderAssociatedPtr remote_interfaces;
    IPC::ChannelProxy* channel = GetProcess()->GetChannelProxy();
    if (channel) {
      ApplicationProcessHost* process = GetProcess();
      process->GetRemoteRouteProvider()->GetRoute(
          GetRoutingID(), mojo::MakeRequest(&remote_interfaces));
    } else {
      // The channel may not be initialized in some tests environments. In this
      // case we set up a dummy interface provider.
      mojo::MakeRequestAssociatedWithDedicatedPipe(&remote_interfaces);
    }
    remote_associated_interfaces_.reset(new common::AssociatedInterfaceProviderImpl(
        std::move(remote_interfaces)));
  }
  return remote_associated_interfaces_.get();
}

bool ApplicationWindowHost::LockKeyboard() {
  if (!keyboard_lock_allowed_ || !is_focused_ || !view_)
    return false;

  // KeyboardLock can be activated and deactivated several times per request,
  // for example when a fullscreen tab loses and gains focus multiple times,
  // so we need to retain a copy of the keys requested.
  base::Optional<base::flat_set<int>> copy_of_keys = keyboard_keys_to_lock_;
  return view_->LockKeyboard(std::move(copy_of_keys));
}

bool ApplicationWindowHost::IsMouseLocked() const {
  return view_ ? view_->IsMouseLocked() : false;
}

bool ApplicationWindowHost::IsKeyboardLocked() const {
  return view_ ? view_->IsKeyboardLocked() : false;
}

void ApplicationWindowHost::UnlockKeyboard() {
  if (IsKeyboardLocked())
    view_->UnlockKeyboard();
}

bool ApplicationWindowHost::GetVisualProperties(
    common::VisualProperties* visual_properties) {
  *visual_properties = common::VisualProperties();

  GetScreenInfo(&visual_properties->screen_info);

  if (delegate_) {
    visual_properties->is_fullscreen_granted =
      delegate_->IsFullscreen();
        //delegate_->IsFullscreenForCurrentTab();
    visual_properties->display_mode = delegate_->GetDisplayMode(this);
  } else {
    visual_properties->is_fullscreen_granted = false;
    visual_properties->display_mode = blink::kWebDisplayModeBrowser;
  }

  visual_properties->auto_resize_enabled = auto_resize_enabled_;
  visual_properties->min_size_for_auto_resize = min_size_for_auto_resize_;
  visual_properties->max_size_for_auto_resize = max_size_for_auto_resize_;

  if (view_) {
    visual_properties->new_size = view_->GetRequestedApplicationSize();
    visual_properties->capture_sequence_number =
        view_->GetCaptureSequenceNumber();
    visual_properties->compositor_viewport_pixel_size =
        view_->GetCompositorViewportPixelSize();
    visual_properties->top_controls_height = view_->GetTopControlsHeight();
    visual_properties->bottom_controls_height =
        view_->GetBottomControlsHeight();
    if (IsUseZoomForDSFEnabled()) {
      float device_scale = visual_properties->screen_info.device_scale_factor;
      visual_properties->top_controls_height *= device_scale;
      visual_properties->bottom_controls_height *= device_scale;
    }
    visual_properties->browser_controls_shrink_blink_size =
        view_->DoBrowserControlsShrinkBlinkSize();
    visual_properties->visible_viewport_size = view_->GetVisibleViewportSize();
    // TODO(ccameron): GetLocalSurfaceId is not synchronized with the device
    // scale factor of the surface. Fix this.
    viz::LocalSurfaceId local_surface_id = view_->GetLocalSurfaceId();
    if (local_surface_id.is_valid())
      visual_properties->local_surface_id = local_surface_id;
  }

  visual_properties->content_source_id = current_content_source_id_;

  if (screen_orientation_type_for_testing_) {
    visual_properties->screen_info.orientation_type =
        *screen_orientation_type_for_testing_;
  }

  if (screen_orientation_angle_for_testing_) {
    visual_properties->screen_info.orientation_angle =
        *screen_orientation_angle_for_testing_;
  }

  const bool size_changed =
      !old_visual_properties_ ||
      old_visual_properties_->auto_resize_enabled !=
          visual_properties->auto_resize_enabled ||
      (old_visual_properties_->auto_resize_enabled &&
       (old_visual_properties_->min_size_for_auto_resize !=
            visual_properties->min_size_for_auto_resize ||
        old_visual_properties_->max_size_for_auto_resize !=
            visual_properties->max_size_for_auto_resize)) ||
      (!old_visual_properties_->auto_resize_enabled &&
       (old_visual_properties_->new_size != visual_properties->new_size ||
        (old_visual_properties_->compositor_viewport_pixel_size.IsEmpty() &&
         !visual_properties->compositor_viewport_pixel_size.IsEmpty())));

  bool dirty =
      size_changed ||
      old_visual_properties_->screen_info != visual_properties->screen_info ||
      old_visual_properties_->compositor_viewport_pixel_size !=
          visual_properties->compositor_viewport_pixel_size ||
      old_visual_properties_->is_fullscreen_granted !=
          visual_properties->is_fullscreen_granted ||
      old_visual_properties_->display_mode != visual_properties->display_mode ||
      old_visual_properties_->top_controls_height !=
          visual_properties->top_controls_height ||
      old_visual_properties_->browser_controls_shrink_blink_size !=
          visual_properties->browser_controls_shrink_blink_size ||
      old_visual_properties_->bottom_controls_height !=
          visual_properties->bottom_controls_height ||
      old_visual_properties_->visible_viewport_size !=
          visual_properties->visible_viewport_size ||
      (enable_surface_synchronization_ &&
       old_visual_properties_->content_source_id !=
           visual_properties->content_source_id) ||
      (enable_surface_synchronization_ &&
       old_visual_properties_->local_surface_id !=
           visual_properties->local_surface_id) ||
      old_visual_properties_->capture_sequence_number !=
          visual_properties->capture_sequence_number;

  // We don't expect to receive an ACK when the requested size or the physical
  // backing size is empty, or when the main viewport size didn't change.
  visual_properties->needs_resize_ack =
      !auto_resize_enabled_ && g_check_for_pending_resize_ack &&
      !visual_properties->new_size.IsEmpty() &&
      !visual_properties->compositor_viewport_pixel_size.IsEmpty() &&
      (size_changed || next_resize_needs_resize_ack_) &&
      (!enable_surface_synchronization_ ||
       (visual_properties->local_surface_id.has_value() &&
        visual_properties->local_surface_id->is_valid()));

  return dirty;
}

// TODO(ericrk): On Android, with surface synchronization enabled,  we need to
// request a new surface ID when things like top/bottom control height or
// selection handles change. This will be enabled by child surface id
// generation. For now ignore these mismatches.  Remove this function when this
// issue is resolved: https://crbug.com/789259 and https://crbug.com/801350
bool ApplicationWindowHost::SurfacePropertiesMismatch(
    const common::ApplicationWindowSurfaceProperties& first,
    const common::ApplicationWindowSurfaceProperties& second) const {
#ifdef OS_ANDROID
  if (enable_surface_synchronization_) {
    // To make this comparison resistant to changes in
    // RenderWidgetSurfaceProperties, create new properties which are forced to
    // match only for those categories we want to ignore.
    common::ApplicationWindowSurfaceProperties second_reduced = second;
    second_reduced.top_controls_height = first.top_controls_height;
    second_reduced.top_controls_shown_ratio = first.top_controls_shown_ratio;
    second_reduced.bottom_controls_height = first.bottom_controls_height;
    second_reduced.bottom_controls_shown_ratio =
        first.bottom_controls_shown_ratio;
    second_reduced.selection = first.selection;

    return first != second_reduced;
  }
#endif

  // For non-Android or when surface synchronization is not enabled, just use a
  // basic comparison.
  return first != second;
}

void ApplicationWindowHost::SelectWordAroundCaretAck(bool did_select, int32_t start, int32_t end) {
  //DLOG(INFO) << "ApplicationWindowHost::SelectWordAroundCaretAck: doing nothing";
}

void ApplicationWindowHost::ResetLoadingState() {
  if (IsLoading()) {
    // When pending deletion, just set the loading state to not loading.
    // Otherwise, OnDidStopLoading will take care of that, as well as sending
    // notification to the FrameTreeNode about the change in loading state.
    if (!is_active())
      is_loading_ = false;
    else
      DidStopLoading();
  }
}

void ApplicationWindowHost::Detach(int32_t id) {
  //DLOG(INFO) << "ApplicationWindowHost::Detach";
  //frame_tree_->RemoveFrame(frame_tree_node_);
}

void ApplicationWindowHost::FrameFocused() {
  //DLOG(INFO) << "ApplicationWindowHost::FrameFocused";
  //delegate_->SetFocusedFrame();//frame_tree_node_);
}

void ApplicationWindowHost::RequestOverlayRoutingToken() {
  GetOverlayRoutingToken();
  if (GetApplicationWindowInterface())
    GetApplicationWindowInterface()->SetOverlayRoutingToken(*overlay_routing_token_);
  //Send(new FrameMsg_SetOverlayRoutingToken(routing_id_,
  //                                         *overlay_routing_token_));
}

void ApplicationWindowHost::DidStartProvisionalLoad(const GURL& url, const std::vector<GURL>& redirect_chain, base::TimeTicks navigation_start) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowHost::DidStartProvisionalLoadImpl, 
      weak_this_, 
      url, 
      redirect_chain, 
      navigation_start));
}

void ApplicationWindowHost::DidStartProvisionalLoadImpl(const GURL& url, const std::vector<GURL>& redirect_chain, base::TimeTicks navigation_start) {
  //DLOG(INFO) << "ApplicationWindowHost::DidStartProvisionalLoad: active? " << is_active() << " url =" << url;
  // TODO(clamy): Check if other navigation methods (OpenURL,
  // DidFailProvisionalLoad, ...) should also be ignored if the RFH is no longer
  // active.
  if (!is_active())
    return;

  //TRACE_EVENT2("navigation", "RenderFrameHostImpl::OnDidStartProvisionalLoad",
  //             "frame_tree_node", frame_tree_node_->frame_tree_node_id(), "url",
  //             url.possibly_invalid_spec());

  //frame_tree_node_->navigator()->DidStartProvisionalLoad(
  //    this, url, redirect_chain, navigation_start);
  //bool is_main_frame = render_frame_host->frame_tree_node()->IsMainFrame();
  //bool is_error_page = (url.spec() == kUnreachableWebDataURL);
  //GURL validated_url(url);
  //RenderProcessHost* render_process_host = render_frame_host->GetProcess();
  //render_process_host->FilterURL(false, &validated_url);

  // Do not allow browser plugin guests to navigate to non-web URLs, since they
  // cannot swap processes or grant bindings.
  //ChildProcessSecurityPolicyImpl* policy =
  //    ChildProcessSecurityPolicyImpl::GetInstance();
  //if (render_process_host->IsForGuestsOnly() &&
  //    !policy->IsWebSafeScheme(validated_url.scheme())) {
  //  validated_url = GURL(url::kAboutBlankURL);
  //}

  //if (is_main_frame && !is_error_page) {
  //if (!is_error_page) {
    DidStartMainFrameNavigation(url);//validated_url);//,
                                //render_frame_host->GetSiteInstance(),
                                //render_frame_host->GetNavigationHandle());
  //}
}

void ApplicationWindowHost::DidFailProvisionalLoadWithError(int32_t error_code, const base::string16& error_description, const GURL& url) {
  //DLOG(INFO) << "ApplicationWindowHost::DidFailProvisionalLoadWithError. code = " << error_code;
  // TRACE_EVENT2("navigation",
  //             "RenderFrameHostImpl::OnDidFailProvisionalLoadWithError",
  //             "frame_tree_node", frame_tree_node_->frame_tree_node_id(),
  //             "error", params.error_code);
  // TODO(clamy): Kill the renderer with RFH_FAIL_PROVISIONAL_LOAD_NO_HANDLE and
  // return early if navigation_handle_ is null, once we prevent that case from
  // happening in practice. See https://crbug.com/605289.

  // Update the error code in the NavigationHandle of the navigation.
  //if (GetNavigationHandle()) {
  //  GetNavigationHandle()->set_net_error_code(
   //     static_cast<net::Error>(params.error_code));
  //}

  // NOTE: There was almost nothing of value here
  //       so this method is doing nothing for now

  //frame_tree_node_->navigator()->DidFailProvisionalLoadWithError(this, params);
}

void ApplicationWindowHost::DidFinishDocumentLoad() {
  //DLOG(INFO) << "ApplicationWindowHost::DidFinishDocumentLoad";
}

void ApplicationWindowHost::DidFailLoadWithError(const GURL& url, int32_t error_code, const base::string16& error_description) {
  //DLOG(INFO) << "ApplicationWindowHost::DidFailLoadWithError: error = " << error_code;
 // TRACE_EVENT2("navigation",
 //              "RenderFrameHostImpl::OnDidFailProvisionalLoadWithError",
 //              "frame_tree_node", frame_tree_node_->frame_tree_node_id(),
 //              "error", error_code);

  //GURL validated_url(url);
  //GetProcess()->FilterURL(false, &validated_url);
  delegate_->DidFailLoadWithError(url, error_code, error_description);
}

void ApplicationWindowHost::DidStartLoading(bool to_different_document) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowHost::DidStartLoadingImpl, 
      weak_this_,
      to_different_document));
}

void ApplicationWindowHost::DidStartLoadingImpl(bool to_different_document) {
  //DLOG(INFO) << "ApplicationWindowHost::DidStartLoading";
  //TRACE_EVENT2("navigation", "RenderFrameHostImpl::OnDidStartLoading",
  //             "frame_tree_node", frame_tree_node_->frame_tree_node_id(),
  //             "to different document", to_different_document);

  //if (to_different_document) {
  //  bad_message::ReceivedBadMessage(GetProcess(),
  //                                  bad_message::RFH_UNEXPECTED_LOAD_START);
  //  return;
  //}
  bool was_previously_loading = IsLoading();//frame_tree_node_->frame_tree()->IsLoading();
  is_loading_ = true;

  // Only inform the FrameTreeNode of a change in load state if the load state
  // of this RenderFrameHost is being tracked.
  if (is_active()) {
    if (to_different_document)// && IsMainFrame())
      ResetLoadProgress();

    // Notify the WebContents.
    if (!was_previously_loading)
      delegate_->DidStartLoading(true, to_different_document);

    // Set initial load progress and update overall progress. This will notify
    // the WebContents of the load progress change.
    DidChangeLoadProgressInternal(kLoadingProgressMinimum);

    // keeping here for when we have FrameState and FrameProxyState
    //for (const auto& pair : proxy_hosts_) {
    //  pair.second->Send(
    //    new FrameMsg_DidStartLoading(pair.second->GetRoutingID()));
    //}
  }
}

void ApplicationWindowHost::DidStopLoading() {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowHost::DidStopLoadingImpl, 
                   weak_this_)); 
}

void ApplicationWindowHost::DidStopLoadingImpl() {
  //DLOG(INFO) << "ApplicationWindowHost::DidStopLoading";
  //TRACE_EVENT1("navigation", "RenderFrameHostImpl::OnDidStopLoading",
  //             "frame_tree_node", frame_tree_node_->frame_tree_node_id());

  // This method should never be called when the frame is not loading.
  // Unfortunately, it can happen if a history navigation happens during a
  // BeforeUnload or Unload event.
  // TODO(fdegans): Change this to a DCHECK after LoadEventProgress has been
  // refactored in Blink. See crbug.com/466089
  if (!is_loading_)
    return;

  //was_discarded_ = false;
  is_loading_ = false;
  //navigation_request_.reset();

  // Only inform the FrameTreeNode of a change in load state if the load state
  // of this RenderFrameHost is being tracked.
  if (is_active()) {
    // Set final load progress and update overall progress. This will notify
    // the WebContents of the load progress change.
    DidChangeLoadProgressInternal(kLoadingProgressDone);

    // Notify the WebContents.
    if (!IsLoading())
      delegate_->DidStopLoading();

    //for (const auto& pair : proxy_hosts_) {
    //  pair.second->Send(new FrameMsg_DidStopLoading(pair.second->GetRoutingID()));
    //}

    // Notify accessibility that the user is no longer trying to load or
    // reload a page.
    //BrowserAccessibilityManager* manager =
    //  current_frame_host()->browser_accessibility_manager();
    //if (manager)
    //  manager->DidStopLoading();
  }
}

void ApplicationWindowHost::UpdateState(::common::mojom::PageStatePtr state) {
  // TODO(creis): Verify the state's ISN matches the last committed FNE.

  // Without this check, the renderer can trick the browser into using
  // filenames it can't access in a future session restore.
  //if (!CanAccessFilesOfPageState(state)) {
  //  bad_message::ReceivedBadMessage(
  //      GetProcess(), bad_message::RFH_CAN_ACCESS_FILES_OF_PAGE_STATE);
  //  return;
  //}

  delegate_->UpdateStateForFrame(application_frame_.get(), *state);
}

void ApplicationWindowHost::DidChangeLoadProgress(double load_progress) {
  //DLOG(INFO) << "ApplicationWindowHost::DidChangeLoadProgress: " << load_progress;
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowHost::DidChangeLoadProgressInternal, 
      weak_this_,
      load_progress)); 
}

void ApplicationWindowHost::DidChangeLoadProgressInternal(double load_progress) {
  UpdateLoadProgress(load_progress);
}

void ApplicationWindowHost::OpenURL(const GURL& url) {
  //DLOG(INFO) << "ApplicationWindowHost::OpenURL: " << url;
  // OpenURLParams params(dest_url, referrer, frame_tree_node_id, disposition,
  //                      ui::PAGE_TRANSITION_LINK,
  //                      true /* is_renderer_initiated */);
  // params.uses_post = uses_post;
  // params.post_data = body;
  // params.extra_headers = extra_headers;
  // if (redirect_chain.size() > 0)
  //   params.redirect_chain = redirect_chain;
  // params.should_replace_current_entry = should_replace_current_entry;
  // params.user_gesture = user_gesture;
  // params.triggering_event_info = triggering_event_info;

  // // RequestOpenURL is used only for local frames, so we can get here only if
  // // the navigation is initiated by a frame in the same SiteInstance as this
  // // frame.  Note that navigations on RenderFrameProxies do not use
  // // RequestOpenURL and go through NavigateFromFrameProxy instead.
  // params.source_site_instance = current_site_instance;

  // params.source_render_frame_id = render_frame_host->GetRoutingID();
  // params.source_render_process_id = render_frame_host->GetProcess()->GetID();

  // if (render_frame_host->web_ui()) {
  //   // Note that we hide the referrer for Web UI pages. We don't really want
  //   // web sites to see a referrer of "chrome://blah" (and some chrome: URLs
  //   // might have search terms or other stuff we don't want to send to the
  //   // site), so we send no referrer.
  //   params.referrer = Referrer();

  //   // Navigations in Web UI pages count as browser-initiated navigations.
  //   params.is_renderer_initiated = false;
  // }

  // params.blob_url_loader_factory = std::move(blob_url_loader_factory);

  //if (delegate_)
  //  delegate_->OpenURL(params);

  delegate_->OpenURL(url);
}

void ApplicationWindowHost::DidFinishLoad(const GURL& url) {
  //DLOG(INFO) << "ApplicationWindowHost::DidFinishLoad: " << url;
}

void ApplicationWindowHost::DocumentOnLoadCompleted(base::TimeTicks timestamp) {
  //DLOG(INFO) << "ApplicationWindowHost::DocumentOnLoadCompleted";
  // This message is only sent for top-level frames. TODO(avi): when frame tree
  // mirroring works correctly, add a check here to enforce it.
  delegate_->DocumentOnLoadCompleted(application_frame_.get());
}

void ApplicationWindowHost::DidAccessInitialDocument() {
  //DLOG(INFO) << "ApplicationWindowHost::DidAccessInitialDocument";
  delegate_->DidAccessInitialDocument();
}

void ApplicationWindowHost::UpdateTitle(const base::string16& title, base::i18n::TextDirection direction) {
  HostThread::PostTask(
    HostThread::UI, 
    FROM_HERE, 
    base::BindOnce(&ApplicationWindowHost::UpdateTitleImpl, 
                   weak_this_,
                   title,
                   direction));
}

void ApplicationWindowHost::UpdateTitleImpl(const base::string16& title, base::i18n::TextDirection direction) {
  //DLOG(INFO) << "ApplicationWindowHost::UpdateTitle: " << title;
  //if (frame_tree_node_->parent())
 //   return;

  if (title.length() > kMaxTitleChars) {
    NOTREACHED() << "Renderer sent too many characters in title.";
    return;
  }

  delegate_->UpdateTitle(this, title, direction);
}

bool ApplicationWindowHost::ShouldDispatchBeforeUnload() const {
  return GetProcess()->HasConnection() && application_window_created_;
}

void ApplicationWindowHost::DispatchBeforeUnload(bool for_navigation,
                                                 bool is_reload) {
  DCHECK(for_navigation || !is_reload);

  // if (!for_navigation) {
  //   // Cancel any pending navigations, to avoid their navigation commit/fail
  //   // event from wiping out the is_waiting_for_beforeunload_ack_ state.
  //   if (frame_tree_node_->navigation_request() &&
  //       frame_tree_node_->navigation_request()->navigation_handle()) {
  //     frame_tree_node_->navigation_request()
  //         ->navigation_handle()
  //         ->set_net_error_code(net::ERR_ABORTED);
  //   }
  //   frame_tree_node_->ResetNavigationRequest(false, true);
  // }

  // TODO(creis): Support beforeunload on subframes.  For now just pretend that
  // the handler ran and allowed the navigation to proceed.
  if (!ShouldDispatchBeforeUnload()) {
    //DCHECK(!for_navigation);
    //frame_tree_node_->render_manager()->OnBeforeUnloadACK(
    //    true, base::TimeTicks::Now());
    //OnBeforeUnloadAck(true, base::TimeTicks::Now());
    ClosePage();
    return;
  }
  //TRACE_EVENT_ASYNC_BEGIN1("navigation", "RenderFrameHostImpl BeforeUnload",
  //                         this, "&RenderFrameHostImpl", (void*)this);

  // This may be called more than once (if the user clicks the tab close button
  // several times, or if they click the tab close button then the browser close
  // button), and we only send the message once.
  if (is_waiting_for_beforeunload_ack_) {
    // Some of our close messages could be for the tab, others for cross-site
    // transitions. We always want to think it's for closing the tab if any
    // of the messages were, since otherwise it might be impossible to close
    // (if there was a cross-site "close" request pending when the user clicked
    // the close button). We want to keep the "for cross site" flag only if
    // both the old and the new ones are also for cross site.
    unload_ack_is_for_navigation_ =
        unload_ack_is_for_navigation_ && for_navigation;
  } else {
    // Start the hang monitor in case the renderer hangs in the beforeunload
    // handler.
    is_waiting_for_beforeunload_ack_ = true;
    unload_ack_is_for_navigation_ = for_navigation;
    send_before_unload_start_time_ = base::TimeTicks::Now();
    if (beforeunload_timeout_) {
      beforeunload_timeout_->Start(
        TimeDelta::FromMilliseconds(kUnloadTimeoutMS));
    }
    //Send(new FrameMsg_BeforeUnload(routing_id_, is_reload));
    if (GetApplicationWindowInterface())
      GetApplicationWindowInterface()->BeforeUnload(is_reload);
  }
}

void ApplicationWindowHost::BeforeUnloadAck(bool proceed, base::TimeTicks application_before_unload_start_time, base::TimeTicks application_before_unload_end_time) {
  //DLOG(INFO) << "ApplicationWindowHost::BeforeUnloadAck";
  //TRACE_EVENT_ASYNC_END1("navigation", "RenderFrameHostImpl BeforeUnload", this,
  //                       "FrameTreeNode id",
  //                       frame_tree_node_->frame_tree_node_id());
  // If this renderer navigated while the beforeunload request was in flight, we
  // may have cleared this state in DidCommitProvisionalLoad, in which case we
  // can ignore this message.
  // However renderer might also be swapped out but we still want to proceed
  // with navigation, otherwise it would block future navigations. This can
  // happen when pending cross-site navigation is canceled by a second one just
  // before DidCommitProvisionalLoad while current RVH is waiting for commit
  // but second navigation is started from the beginning.
  if (!is_waiting_for_beforeunload_ack_) {
    return;
  }
  
  DCHECK(!send_before_unload_start_time_.is_null());

  // Sets a default value for before_unload_end_time so that the browser
  // survives a hacked renderer.
  base::TimeTicks before_unload_end_time = application_before_unload_end_time;
  if (!application_before_unload_start_time.is_null() &&
      !application_before_unload_end_time.is_null()) {
    base::TimeTicks receive_before_unload_ack_time = base::TimeTicks::Now();

    if (!base::TimeTicks::IsConsistentAcrossProcesses()) {
      // TimeTicks is not consistent across processes and we are passing
      // TimeTicks across process boundaries so we need to compensate for any
      // skew between the processes. Here we are converting the renderer's
      // notion of before_unload_end_time to TimeTicks in the browser process.
      // See comments in inter_process_time_ticks_converter.h for more.
      common::InterProcessTimeTicksConverter converter(
          common::LocalTimeTicks::FromTimeTicks(send_before_unload_start_time_),
          common::LocalTimeTicks::FromTimeTicks(receive_before_unload_ack_time),
          common::RemoteTimeTicks::FromTimeTicks(application_before_unload_start_time),
          common::RemoteTimeTicks::FromTimeTicks(application_before_unload_end_time));
      common::LocalTimeTicks browser_before_unload_end_time =
          converter.ToLocalTimeTicks(
              common::RemoteTimeTicks::FromTimeTicks(application_before_unload_end_time));
      before_unload_end_time = browser_before_unload_end_time.ToTimeTicks();
    }

    base::TimeDelta on_before_unload_overhead_time =
        (receive_before_unload_ack_time - send_before_unload_start_time_) -
        (application_before_unload_end_time - application_before_unload_start_time);
    UMA_HISTOGRAM_TIMES("Navigation.OnBeforeUnloadOverheadTime",
                        on_before_unload_overhead_time);

    //frame_tree_node_->navigator()->LogBeforeUnloadTime(
    //    application_before_unload_start_time, application_before_unload_end_time);
  }
  // Resets beforeunload waiting state.
  is_waiting_for_beforeunload_ack_ = false;
  if (beforeunload_timeout_)
    beforeunload_timeout_->Stop();
  send_before_unload_start_time_ = base::TimeTicks();

  // If the ACK is for a navigation, send it to the Navigator to have the
  // current navigation stop/proceed. Otherwise, send it to the
  // RenderFrameHostManager which handles closing.
  if (unload_ack_is_for_navigation_) {
    //frame_tree_node_->navigator()->OnBeforeUnloadACK(frame_tree_node_, proceed,
    //                                                 before_unload_end_time);
    DCHECK(false);
    //BeginNavigation(delegate_->GetURL().spec());
  } else {
    //frame_tree_node_->render_manager()->OnBeforeUnloadACK(
    //    proceed, before_unload_end_time);
    ClosePage();
  }

  // If canceled, notify the delegate to cancel its pending navigation entry.
  // This is usually redundant with the dialog closure code in WebContentsImpl's
  // OnDialogClosed, but there may be some cases that Blink returns !proceed
  // without showing the dialog. We also update the address bar here to be safe.
  if (!proceed)
    delegate_->DidCancelLoading();
}

void ApplicationWindowHost::SynchronizeVisualProperties(
  const viz::SurfaceId& surface_id, 
  const common::ScreenInfo& screen_info, 
  bool auto_resize_enabled, 
  const gfx::Size& min_size_for_auto_resize, 
  const gfx::Size& max_size_for_auto_resize, 
  const gfx::Rect& screen_space_rect, 
  const gfx::Size& local_frame_size, 
  int32_t capture_sequence_number) {
  //DLOG(INFO) << "\n\nRECEIVED ApplicationWindowHost::SynchronizeVisualProperties(SurfaceId, ScreenInfo, ...)\n\nsurface_id -> " << surface_id;
  // NOTE: this was assumed, as this kind of sync with props params doesnt exist
  //SynchronizeVisualProperties();
}

//void ApplicationWindowHost::UpdateViewportIntersection(const gfx::Rect& viewport_intersection, const gfx::Rect& compositor_visible_rect) {
  //DLOG(INFO) << "ApplicationWindowHost::UpdateViewportIntersection";
//}

void ApplicationWindowHost::VisibilityChanged(bool visible) {
  //DLOG(INFO) << "ApplicationWindowHost::VisibilityChanged: " << visible;
}

//void ApplicationWindowHost::UpdateRenderThrottlingStatus(bool is_throttled, bool subtree_throttled) {
  //DLOG(INFO) << "ApplicationWindowHost::UpdateRenderThrottlingStatus";
//}

void ApplicationWindowHost::SetHasReceivedUserGesture() {
  //DLOG(INFO) << "ApplicationWindowHost::SetHasReceivedUserGesture";
}

void ApplicationWindowHost::SetHasReceivedUserGestureBeforeNavigation(bool value) {
  //DLOG(INFO) << "ApplicationWindowHost::SetHasReceivedUserGestureBeforeNavigation";
}

void ApplicationWindowHost::ContextMenu() {
  //DLOG(INFO) << "ApplicationWindowHost::ContextMenu";
}

void ApplicationWindowHost::SelectionChanged(const base::string16& selection, uint32_t offset, const gfx::Range& range) {
  //DLOG(INFO) << "ApplicationWindowHost::SelectionChanged";
}

void ApplicationWindowHost::VisualStateResponse(uint64_t id) {
  //DLOG(INFO) << " \n\n ApplicationWindowHost::VisualStateResponse \n\n";
  auto it = visual_state_callbacks_.find(id);
  if (it != visual_state_callbacks_.end()) {
    //DLOG(INFO) << "ApplicationWindowHost::VisualStateResponse: running callback";
    it->second.Run(true);
    visual_state_callbacks_.erase(it);
  } else {
    NOTREACHED() << "Received script response for unknown request";
  }
}

void ApplicationWindowHost::InsertVisualStateCallback(
    const VisualStateCallback& callback) {
  //DLOG(INFO) << " \n\n ApplicationWindowHost::InsertVisualStateCallback \n\n";
  
  static uint64_t next_id = 1;
  uint64_t key = next_id++;
  //Send(new FrameMsg_VisualStateRequest(routing_id_, key));
  if (GetApplicationWindowInterface())
    GetApplicationWindowInterface()->VisualStateRequest(key);
  visual_state_callbacks_.insert(std::make_pair(key, callback));
}

void ApplicationWindowHost::GenerateRoutingID(GenerateRoutingIDCallback callback) {
  //DLOG(INFO) << "ApplicationWindowHost::GenerateRoutingID";
  std::move(callback).Run(process_->GetNextRoutingID());
}

void ApplicationWindowHost::EnterFullscreen() {
  //DLOG(INFO) << "ApplicationWindowHost::EnterFullscreen";
  // Entering fullscreen from a cross-process subframe also affects all
  // renderers for ancestor frames, which will need to apply fullscreen CSS to
  // appropriate ancestor <iframe> elements, fire fullscreenchange events, etc.
  // Thus, walk through the ancestor chain of this frame and for each (parent,
  // child) pair, send a message about the pending fullscreen change to the
  // child's proxy in parent's SiteInstance. The renderer process will use this
  // to find the <iframe> element in the parent frame that will need fullscreen
  // styles. This is done at most once per SiteInstance: for example, with a
  // A-B-A-B hierarchy, if the bottom frame goes fullscreen, this only needs to
  // notify its parent, and Blink-side logic will take care of applying
  // necessary changes to the other two ancestors.
  
  //std::set<SiteInstance*> notified_instances;
  //notified_instances.insert(GetSiteInstance());
  //for (FrameTreeNode* node = frame_tree_node_; node->parent();
  //     node = node->parent()) {
  //  SiteInstance* parent_site_instance =
  //      node->parent()->current_frame_host()->GetSiteInstance();
  //  if (ContainsKey(notified_instances, parent_site_instance))
  //    continue;
  //
  //  RenderFrameProxyHost* child_proxy =
  //      node->render_manager()->GetRenderFrameProxyHost(parent_site_instance);
  //  child_proxy->Send(
  //      new FrameMsg_WillEnterFullscreen(child_proxy->GetRoutingID()));
  //  notified_instances.insert(parent_site_instance);
  //}

  // TODO(alexmos): See if this can use the last committed origin instead.
  delegate_->EnterFullscreenMode();//GetLastCommittedURL().GetOrigin(), options);

  // The previous call might change the fullscreen state. We need to make sure
  // the renderer is aware of that, which is done via the resize message.
  // Typically, this will be sent as part of the call on the |delegate_| above
  // when resizing the native windows, but sometimes fullscreen can be entered
  // without causing a resize, so we need to ensure that the resize message is
  // sent in that case. We always send this to the main frame's widget, and if
  // there are any OOPIF widgets, this will also trigger them to resize via
  // frameRectsChanged.
  //render_view_host_->GetWidget()->SynchronizeVisualProperties();
  SynchronizeVisualProperties();
}

void ApplicationWindowHost::ExitFullscreen() {
  //DLOG(INFO) << "ApplicationWindowHost::ExitFullscreen";
  delegate_->ExitFullscreenMode(/* will_cause_resize */ true);

  // The previous call might change the fullscreen state. We need to make sure
  // the renderer is aware of that, which is done via the resize message.
  // Typically, this will be sent as part of the call on the |delegate_| above
  // when resizing the native windows, but sometimes fullscreen can be entered
  // without causing a resize, so we need to ensure that the resize message is
  // sent in that case. We always send this to the main frame's widget, and if
  // there are any OOPIF widgets, this will also trigger them to resize via
  // frameRectsChanged.
  //render_view_host_->GetWidget()->SynchronizeVisualProperties();
  SynchronizeVisualProperties();
}

void ApplicationWindowHost::DispatchLoad() {
  //DLOG(INFO) << "ApplicationWindowHost::DispatchLoad";
  //TRACE_EVENT1("navigation", "RenderFrameHostImpl::OnDispatchLoad",
  //             "frame_tree_node", frame_tree_node_->frame_tree_node_id());

  // Don't forward the load event if this RFH is pending deletion. This can
  // happen in a race where this RenderFrameHost finishes loading just after
  // the frame navigates away. See https://crbug.com/626802.
  //if (!is_active())
  //  return;

  // We should never be receiving this message from a speculative RFH.
  //DCHECK(IsCurrent());

  // Only frames with an out-of-process parent frame should be sending this
  // message.
  //RenderFrameProxyHost* proxy =
  //    frame_tree_node()->render_manager()->GetProxyToParent();
  //if (!proxy) {
  //  bad_message::ReceivedBadMessage(GetProcess(),
  //                                  bad_message::RFH_NO_PROXY_TO_PARENT);
  //  return;
  //}

  //proxy->Send(new FrameMsg_DispatchLoad(proxy->GetRoutingID()));
}

void ApplicationWindowHost::CheckCompleted() {
  //DLOG(INFO) << "ApplicationWindowHost::CheckCompleted";
}

void ApplicationWindowHost::UpdateFaviconURL(const std::vector<GURL>& favicons) {
  //DLOG(INFO) << "ApplicationWindowHost::UpdateFaviconURL";
}

const GURL& ApplicationWindowHost::GetLastCommittedURL() {
  return last_committed_url_;
}

const url::Origin& ApplicationWindowHost::GetLastCommittedOrigin() {
  return last_committed_origin_;
}

void ApplicationWindowHost::SetLastCommittedOrigin(const url::Origin& origin) {
  last_committed_origin_ = origin;
  //CSPContext::SetSelf(origin);
}

void ApplicationWindowHost::ScrollRectToVisibleInParentFrame(const gfx::Rect& rect_to_scroll) {
  //DLOG(INFO) << "ApplicationWindowHost::ScrollRectToVisibleInParentFrame";
  //RenderFrameProxyHost* proxy =
  //    frame_tree_node_->render_manager()->GetProxyToParent();
  //if (!proxy)
  //  return;
  //proxy->ScrollRectToVisible(rect_to_scroll, params);
}

void ApplicationWindowHost::FrameDidCallFocus() {
  //DLOG(INFO) << "ApplicationWindowHost::FrameDidCallFocus";
  delegate_->DidCallFocus();
}

void ApplicationWindowHost::TextSurroundingSelectionResponse(
    const base::string16& content,
    uint32_t start_offset, 
    uint32_t end_offset) {
  //DLOG(INFO) << "ApplicationWindowHost::TextSurroundingSelectionResponse";  
}

void ApplicationWindowHost::StartHangMonitorTimeout(TimeDelta delay) {
  if (!hang_monitor_timeout_)
    return;
  hang_monitor_timeout_->Start(delay);
  hang_monitor_start_time_ = clock_->NowTicks();
}

void ApplicationWindowHost::RestartHangMonitorTimeoutIfNecessary() {
  if (hang_monitor_timeout_ && in_flight_event_count_ > 0 && !is_hidden_)
    hang_monitor_timeout_->Restart(hung_renderer_delay_);
}

//void ApplicationWindowHost::RequestCompositorFrameSink(
//    viz::mojom::CompositorFrameSinkRequest compositor_frame_sink_request,
//    viz::mojom::CompositorFrameSinkClientPtr compositor_frame_sink_client,
//    common::mojom::RenderFrameMetadataObserverClientRequest
//        render_frame_metadata_observer_client_request,
//    common::mojom::RenderFrameMetadataObserverPtr render_frame_metadata_observer) {
      
  // auto callback = base::BindOnce(
  //     [](mojo::PendingReceiver<viz::mojom::CompositorFrameSink> receiver,
  //        mojo::PendingRemote<viz::mojom::CompositorFrameSinkClient> client,
  //        const viz::FrameSinkId& frame_sink_id) {
  //       GetHostFrameSinkManager()->CreateCompositorFrameSink(
  //           frame_sink_id, std::move(receiver), std::move(client));
  //     },
  //     std::move(compositor_frame_sink_receiver),
  //     std::move(compositor_frame_sink_client));
//  DCHECK(process_);
//  auto callback = base::BindOnce(
//      [](viz::mojom::CompositorFrameSinkRequest request,
//         viz::mojom::CompositorFrameSinkClientPtr client,
 //        const viz::FrameSinkId& frame_sink_id) {
 //       GetHostFrameSinkManager()->CreateCompositorFrameSink(
 //           frame_sink_id, std::move(request), std::move(client));
 //     },
 //     std::move(compositor_frame_sink_request),
 //     std::move(compositor_frame_sink_client));
//
//  if (view_)
//    std::move(callback).Run(view_->GetFrameSinkId());
//  else
//    create_frame_sink_callback_ = std::move(callback);
//}

void ApplicationWindowHost::RequestCompositorFrameSink(
    viz::mojom::CompositorFrameSinkRequest compositor_frame_sink_request,
    viz::mojom::CompositorFrameSinkClientPtr compositor_frame_sink_client) {
  if (enable_viz_) {
      // Connects the viz process end of CompositorFrameSink message pipes. The
      // renderer compositor may request a new CompositorFrameSink on context
      // loss, which will destroy the existing CompositorFrameSink.
      auto callback = base::BindOnce(
          [](viz::HostFrameSinkManager* manager,
             viz::mojom::CompositorFrameSinkRequest request,
             viz::mojom::CompositorFrameSinkClientPtr client,
             const viz::FrameSinkId& frame_sink_id) {
            manager->CreateCompositorFrameSink(
                frame_sink_id, std::move(request), std::move(client));
          },
          base::Unretained(GetHostFrameSinkManager()),
          std::move(compositor_frame_sink_request),
          std::move(compositor_frame_sink_client));

      if (view_) {
        std::move(callback).Run(view_->GetFrameSinkId());
      }
      else {
        create_frame_sink_callback_ = std::move(callback);
      }

      return;
  }

  if (compositor_frame_sink_binding_.is_bound()) {
    compositor_frame_sink_binding_.Close();
  }
  compositor_frame_sink_binding_.Bind(
      std::move(compositor_frame_sink_request),
      HostMainLoop::GetInstance()->GetResizeTaskRunner());
  if (view_) {      
    view_->DidCreateNewApplicationCompositorFrameSink(
        compositor_frame_sink_client.get());
  }
  renderer_compositor_frame_sink_ = std::move(compositor_frame_sink_client);
}

void ApplicationWindowHost::RegisterRenderFrameMetadataObserver(
    common::mojom::RenderFrameMetadataObserverClientRequest
        render_frame_metadata_observer_client_request,
    common::mojom::RenderFrameMetadataObserverPtr render_frame_metadata_observer) {
  //DLOG(INFO) << "ApplicationWindowHost::RegisterRenderFrameMetadataObserver";
  render_frame_metadata_provider_.Bind(
      std::move(render_frame_metadata_observer_client_request),
      std::move(render_frame_metadata_observer));
}

void ApplicationWindowHost::SetUpMojo() {
  //DLOG(INFO) << "\n\nApplicationWindowHost::SetUpMojo\n\n";
  if (registry_.get()) {
    //DLOG(INFO) << "ApplicationWindowHost::SetUpMojo: registry_ already created. cancelling.";
    return;
  }
  
  associated_registry_ = std::unique_ptr<common::AssociatedInterfaceRegistryImpl, HostThread::DeleteOnIOThread>(new common::AssociatedInterfaceRegistryImpl());
  registry_ = std::unique_ptr<service_manager::BinderRegistry, HostThread::DeleteOnIOThread>(new service_manager::BinderRegistry());

  auto make_binding = [](ApplicationWindowHost* window,
                         common::mojom::ApplicationWindowHostAssociatedRequest request) {
    window->application_window_host_binding_.Bind(std::move(request));
  };
  static_cast<blink::AssociatedInterfaceRegistry*>(associated_registry_.get())
      ->AddInterface(base::Bind(make_binding, base::Unretained(this)));
  
  RegisterMojoInterfaces();

  //HostThread::PostTask(
  //  HostThread::UI, 
  //  FROM_HERE, 
  //  base::BindOnce(&ApplicationWindowHost::RegisterMojoInterfaces, base::Unretained(this)));
  
  service_manager::mojom::InterfaceProviderPtr remote_interfaces;
  //frame_->GetInterfaceProvider(mojo::MakeRequest(&remote_interfaces));
  DCHECK(application_window_interface_);
  application_window_interface_->GetInterfaceProvider(mojo::MakeRequest(&remote_interfaces));
  remote_interfaces_.reset(new service_manager::InterfaceProvider);
  remote_interfaces_->Bind(std::move(remote_interfaces));
  //remote_interfaces_->GetInterface(&widget_input_handler_);
}

void ApplicationWindowHost::RegisterMojoInterfaces() {
  DCHECK(HostThread::CurrentlyOn(HostThread::IO));
  //DLOG(INFO) << "\n\nApplicationWindowHost::RegisterMojoInterfaces\n\n";
  registry_->AddInterface(
      base::Bind(&MediaSessionServiceImpl::Create, base::Unretained(this)));

  registry_->AddInterface<media::mojom::InterfaceFactory>(
      base::Bind(&ApplicationWindowHost::BindMediaInterfaceFactoryRequest,
                 base::Unretained(this)));

  registry_->AddInterface(base::BindRepeating(
      &ApplicationWindowHost::CreateWebSocket, base::Unretained(this)));

  registry_->AddInterface(
      base::BindRepeating(&ApplicationWindowHost::CreateAudioInputStreamFactory,
                          base::Unretained(this)));

  registry_->AddInterface(
      base::BindRepeating(&ApplicationWindowHost::CreateAudioOutputStreamFactory,
                          base::Unretained(this)));

  MediaStreamManager* media_stream_manager =
        HostMainLoop::GetInstance()->media_stream_manager();

  registry_->AddInterface(
      base::Bind(&MediaDevicesDispatcherHost::Create, GetProcess()->GetID(),
                 GetRoutingID(),
                 base::Unretained(media_stream_manager)),
      HostThread::GetTaskRunnerForThread(HostThread::IO));

  registry_->AddInterface(
      base::BindRepeating(
          &ApplicationWindowHost::CreateMediaStreamDispatcherHost,
          base::Unretained(this), base::Unretained(media_stream_manager)),
      HostThread::GetTaskRunnerForThread(HostThread::IO));

  registry_->AddInterface(base::Bind(&ImageCaptureImpl::Create));

}

/***/

void ApplicationWindowHost::BindMediaInterfaceFactoryRequest(
    media::mojom::InterfaceFactoryRequest request) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  DCHECK(!media_interface_proxy_);
  media_interface_proxy_.reset(new MediaInterfaceProxy(
      this, std::move(request),
      base::Bind(&ApplicationWindowHost::OnMediaInterfaceFactoryConnectionError,
                 io_weak_this_)));
}

void ApplicationWindowHost::CreateAudioInputStreamFactory(
    common::mojom::RendererAudioInputStreamFactoryRequest request) {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));
  HostMainLoop* host_main_loop = HostMainLoop::GetInstance();
  DCHECK(host_main_loop);
  //if (base::FeatureList::IsEnabled(features::kAudioServiceAudioStreams)) {
  //  scoped_refptr<AudioInputDeviceManager> aidm =
  //      host_main_loop->media_stream_manager()->audio_input_device_manager();
  //  audio_service_audio_input_stream_factory_.emplace(std::move(request),
  //                                                    std::move(aidm), this);
  //} else {


    in_content_audio_input_stream_factory_ =
        RenderFrameAudioInputStreamFactoryHandle::CreateFactory(
            base::BindRepeating(&AudioInputDelegateImpl::Create,
                                host_main_loop->audio_manager(),
                                AudioMirroringManager::GetInstance(),
                                host_main_loop->user_input_monitor(),
                                GetProcess()->GetID(), GetRoutingID()),
            host_main_loop->media_stream_manager(), GetProcess()->GetID(),
            GetRoutingID(), std::move(request));
  
  
  //}
  // audio_input_stream_factory_ =
  //     RenderFrameAudioInputStreamFactoryHandle::CreateFactory(
  //         base::BindRepeating(&AudioInputDelegateImpl::Create,
  //                             media::AudioManager::Get(),
  //                             AudioMirroringManager::GetInstance(),
  //                             host_main_loop->user_input_monitor(),
  //                             GetProcess()->GetID(), GetRoutingID()),
  //         host_main_loop->media_stream_manager(), GetProcess()->GetID(),
  //         GetRoutingID(), std::move(request));
}

// void ApplicationWindowHost::CreateAudioOutputStreamFactoryInternal() {
//     //common::mojom::RendererAudioOutputStreamFactoryRequest request) {
//   //DLOG(INFO) << "\n\nApplicationWindowHost::CreateAudioOutputStreamFactorInternal\n\n";
//   //RendererAudioOutputStreamFactoryContext* factory_context =
//   //    GetProcess()->GetRendererAudioOutputStreamFactoryContext();
//   //DCHECK(factory_context);
//   //audio_output_stream_factory_ =
//   //    RenderFrameAudioOutputStreamFactoryHandle::CreateFactory(
//   //        factory_context, GetRoutingID(), std::move(request));

//   //if (base::FeatureList::IsEnabled(features::kAudioServiceAudioStreams)) {
//   //  media::AudioSystem* audio_system =
//   //      HostMainLoop::GetInstance()->audio_system();
//   //  MediaStreamManager* media_stream_manager =
//   //      HostMainLoop::GetInstance()->media_stream_manager();
//   //  audio_service_audio_output_stream_factory_.emplace(
//   //      this, audio_system, media_stream_manager, std::move(request));
//   //} else {
//     RendererAudioOutputStreamFactoryContext* factory_context =
//         GetProcess()->GetRendererAudioOutputStreamFactoryContext();
//     DCHECK(factory_context);
//     in_content_audio_output_stream_factory_ =
//         RenderFrameAudioOutputStreamFactoryHandle::CreateFactory(
//             factory_context, GetRoutingID());//, std::move(request));
//   //}
// }

void ApplicationWindowHost::CreateAudioOutputStreamFactory(
    common::mojom::RendererAudioOutputStreamFactoryRequest request) {
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));
  //DLOG(INFO) << "\n\nApplicationWindowHost::CreateAudioOutputStreamFactory\n\n";
  //RendererAudioOutputStreamFactoryContext* factory_context =
  //    GetProcess()->GetRendererAudioOutputStreamFactoryContext();
  //DCHECK(factory_context);
  //audio_output_stream_factory_ =
  //    RenderFrameAudioOutputStreamFactoryHandle::CreateFactory(
  //        factory_context, GetRoutingID(), std::move(request));

  //if (base::FeatureList::IsEnabled(features::kAudioServiceAudioStreams)) {
  //  media::AudioSystem* audio_system =
  //      HostMainLoop::GetInstance()->audio_system();
  //  MediaStreamManager* media_stream_manager =
  //      HostMainLoop::GetInstance()->media_stream_manager();
  //  audio_service_audio_output_stream_factory_.emplace(
  //      this, audio_system, media_stream_manager, std::move(request));
  //} else {
    RendererAudioOutputStreamFactoryContext* factory_context =
        GetProcess()->GetRendererAudioOutputStreamFactoryContext();
    DCHECK(factory_context);
    in_content_audio_output_stream_factory_ =
        RenderFrameAudioOutputStreamFactoryHandle::CreateFactory(
            factory_context, GetRoutingID(), std::move(request));
  //}
}

void ApplicationWindowHost::CreateWebSocket(
    network::mojom::WebSocketRequest request) {
  // This is to support usage of WebSockets in cases in which there is an
  // associated RenderFrame. This is important for showing the correct security
  // state of the page and also honoring user override of bad certificates.
  WebSocketManager::CreateWebSocket(process_->GetID(), routing_id_,
                                    last_committed_origin_, std::move(request));
}

void ApplicationWindowHost::CreateMediaStreamDispatcherHost(
    MediaStreamManager* media_stream_manager,
    common::mojom::MediaStreamDispatcherHostRequest request) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  if (!media_stream_dispatcher_host_) {
    media_stream_dispatcher_host_.reset(new MediaStreamDispatcherHost(
        GetProcess()->GetID(), GetRoutingID(), media_stream_manager));
  }
  media_stream_dispatcher_host_->BindRequest(std::move(request));
}

void ApplicationWindowHost::OnMediaInterfaceFactoryConnectionError() {
  DCHECK(media_interface_proxy_);
  media_interface_proxy_.reset();
}

/***/

void ApplicationWindowHost::BindProcess(ApplicationProcessHost* process) {
  //process_ = process;
  process_->AddRoute(routing_id_, this);
  process_->AddWindow(this);
  process_->AddObserver(this);
  //DLOG(INFO) << "ApplicationWindowHost::AttachProcess: new FrameSinkId (" << process_->GetID() << ", " << routing_id_<< ")";
  //frame_sink_id_ = viz::FrameSinkId(
  //                  base::checked_cast<uint32_t>(process_->GetID()),
  //                  base::checked_cast<uint32_t>(routing_id_));
  std::pair<RoutingIDWindowMap::iterator, bool> result =
      g_routing_id_window_map.Get().insert(std::make_pair(
          ApplicationWindowHostID(process->GetID(), routing_id_), this));
  CHECK(result.second) << "Inserting a duplicate item!";
  //DLOG(INFO) << "\n  ** ApplicationWindowHost::BindProcess: initializing latency_tracker_ with routing_id: " << routing_id_ << " process_id: " << GetProcess()->GetID();
  latency_tracker_.Initialize(routing_id_, GetProcess()->GetID());
}

HostNetworkContext* ApplicationWindowHost::GetNetworkContext() const {
  return process_->GetNetworkContext();
}

void ApplicationWindowHost::DidStartMainFrameNavigation(const GURL& url) {//,
  //DLOG(INFO) << "ApplicationWindowHost::DidStartMainFrameNavigation";
    //SiteInstanceImpl* site_instance,
    //NavigationHandleImpl* navigation_handle) {
  // If there is no browser-initiated pending entry for this navigation and it
  // is not for the error URL, create a pending entry using the current
  // SiteInstance, and ensure the address bar updates accordingly.  We don't
  // know the referrer or extra headers at this point, but the referrer will
  // be set properly upon commit.
  // NavigationEntryImpl* pending_entry = controller_->GetPendingEntry();
  // bool has_browser_initiated_pending_entry =
  //     pending_entry && !pending_entry->is_renderer_initiated();

  // // A pending navigation entry is created in OnBeginNavigation(). The renderer
  // // sends a provisional load notification after that. We don't want to create
  // // a duplicate navigation entry here.
  // bool renderer_provisional_load_to_pending_url =
  //     pending_entry && pending_entry->is_renderer_initiated() &&
  //     (pending_entry->GetURL() == url);

  // // If there is a transient entry, creating a new pending entry will result
  // // in deleting it, which leads to inconsistent state.
  // bool has_transient_entry = !!controller_->GetTransientEntry();

  // if (!has_browser_initiated_pending_entry && !has_transient_entry &&
  //     !renderer_provisional_load_to_pending_url) {
  //   std::unique_ptr<NavigationEntryImpl> entry =
  //       NavigationEntryImpl::FromNavigationEntry(
  //           NavigationController::CreateNavigationEntry(
  //               url, content::Referrer(), ui::PAGE_TRANSITION_LINK,
  //               true /* is_renderer_initiated */, std::string(),
  //               controller_->GetApplicationContents(),
  //               nullptr /* blob_url_loader_factory */));
  //   entry->set_site_instance(site_instance);
  //   // TODO(creis): If there's a pending entry already, find a safe way to
  //   // update it instead of replacing it and copying over things like this.
  //   // That will allow us to skip the NavigationHandle update below as well.
  //   if (pending_entry) {
  //     entry->set_transferred_global_request_id(
  //         pending_entry->transferred_global_request_id());
  //     entry->set_should_replace_entry(pending_entry->should_replace_entry());
  //     entry->SetRedirectChain(pending_entry->GetRedirectChain());
  //   }

  //   controller_->SetPendingEntry(std::move(entry));
  //   if (delegate_)
  //     delegate_->NotifyChangedNavigationState(content::INVALIDATE_TYPE_URL);
  // }
}

void ApplicationWindowHost::CreateNetworkServiceDefaultFactory(
    network::mojom::URLLoaderFactoryRequest default_factory_request) {
  //DLOG(INFO) << "ApplicationWindowHost::CreateNetworkServiceDefaultFactory";
  // HostThread::PostTask(
  //   HostThread::UI,
  //   FROM_HERE,
  //   base::BindOnce(&ApplicationWindowHost::CreateNetworkServiceDefaultFactoryImpl,
  //     base::Unretained(this),
  //     base::Passed(std::move(default_factory_request))));
  CreateNetworkServiceDefaultFactoryImpl(std::move(default_factory_request));
}

void ApplicationWindowHost::CreateNetworkServiceDefaultFactoryImpl(
    network::mojom::URLLoaderFactoryRequest default_factory_request) {
  //DLOG(INFO) << "ApplicationWindowHost::CreateNetworkServiceDefaultFactoryImpl";
  //network::mojom::URLLoaderFactoryParamsPtr params =
  //    network::mojom::URLLoaderFactoryParams::New();
  //params->process_id = GetProcess()->GetID();
  //params->disable_web_security = true;
  //    base::CommandLine::ForCurrentProcess()->HasSwitch(
  //        switches::kDisableWebSecurity);
  //SiteIsolationPolicy::PopulateURLLoaderFactoryParamsPtrForCORB(params.get());
  //IOThread* io_thread = HostController::Instance()->io_thread();
  //io_thread->GetNetworkContext()->CreateURLLoaderFactory(
  //GetNetworkContext()->CreateURLLoaderFactory(
  //  std::move(default_factory_request), GetProcess()->GetID());//, std::move(params));
  NavigationEntry* entry = delegate_->GetNavigationController()->current();
  RouteController* controller = delegate_->GetRouteController();
  RouteEntry* url_entry = entry->route();//controller->GetCurrent();
  DCHECK(url_entry);
  HostRpcService* service = url_entry->service();
  DCHECK(service);
  std::unique_ptr<net::RpcMessageEncoder> encoder = service->BuildEncoder();

  GetNetworkContext()->CreateApplicationURLLoaderFactory(
    process_->loader_task_runner(),
    this,
    delegate_->GetDomain(),
    controller->registry(),
    std::move(encoder),
    std::move(default_factory_request));
}

void ApplicationWindowHost::CommitNavigation(
  NavigationEntry* entry, 
  bool keep_alive) {
  
  bool is_same_document = false;
  
  RouteController* controller = delegate_->GetRouteController();
  RouteEntry* url_entry = entry->route();//controller->GetCurrent();
  DCHECK(url_entry);
  HostRpcService* service = url_entry->service();
  DCHECK(service);
  std::unique_ptr<net::RpcMessageEncoder> encoder = service->BuildEncoder();

  scoped_refptr<ServiceWorkerContextWrapper> service_worker_context = delegate_->GetDomain()->GetServiceWorkerContext();
  entry->set_route_id(routing_id_);
  entry->InitServiceWorkerHandle(service_worker_context.get());

  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE,
    base::BindOnce(
      &ApplicationWindowHost::CommitNavigationOnIO, 
      io_weak_this_,
      base::Unretained(entry),
      keep_alive,
      is_same_document,
      base::Unretained(controller->registry()),
      base::Passed(std::move(encoder))));//base::Passed(std::move(controller_service_worker_info))));
  
  is_loading_ = true;
}

void ApplicationWindowHost::CommitNavigationOnIO(
  NavigationEntry* entry, 
  bool keep_alive,
  bool is_same_document,
  RouteRegistry* registry,
  std::unique_ptr<net::RpcMessageEncoder> encoder) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  std::string rpc_scheme = "rpc";//url.scheme();
  std::string ipc_scheme = "ipc";

  net::URLRequest* request = entry->request();
  network::mojom::RequestContextFrameType frame_type = network::mojom::RequestContextFrameType::kTopLevel;
        //info.is_main_frame ? network::mojom::RequestContextFrameType::kTopLevel
      //                   : network::mojom::RequestContextFrameType::kNested;

  storage::BlobStorageContext* blob_context = GetBlobStorageContext(
    delegate_->GetDomain()->GetBlobStorageContext());


  ServiceWorkerNavigationHandleCore* service_worker_handle_core = entry->service_worker_handle()->core();
  
  ServiceWorkerRequestHandler::InitializeForNavigation(
      request, 
      service_worker_handle_core, 
      blob_context,
      false,
      common::RESOURCE_TYPE_MAIN_FRAME,//resource_type,
      //common::REQUEST_CONTEXT_TYPE_HYPERLINK,//info.begin_params->request_context_type, 
      common::REQUEST_CONTEXT_TYPE_FRAME,
      frame_type,
      true, 
      nullptr,
      delegate_->GetDomain()->GetServiceWorkerProcessType(),
      delegate_->GetDomain()->GetServiceWorkerProcessId(GetProcess()->GetID()),
      base::Bind(&ApplicationContents::FromID,
        GetProcess()->GetID(), routing_id_));

  network::mojom::URLLoaderFactoryPtrInfo default_url_loader_factory;
  GetNetworkContext()->CreateURLLoaderFactory(
    mojo::MakeRequest(&default_url_loader_factory), 
    GetProcess()->GetID());
  
  // network::mojom::URLLoaderFactoryPtrInfo rpc_url_loader_factory;
  // GetNetworkContext()->CreateRpcURLLoaderFactory(
  //   process_->loader_task_runner(),
  //   this,
  //   registry,
  //   std::move(encoder),
  //   mojo::MakeRequest(&rpc_url_loader_factory));

  std::unique_ptr<common::URLLoaderFactoryBundleInfo> subresource_loader_factories = std::make_unique<common::URLLoaderFactoryBundleInfo>();
 
  // // rpc
  // subresource_loader_factories->factories_info().emplace(
  //   rpc_scheme, 
  //   std::move(rpc_url_loader_factory));


  // network::mojom::URLLoaderFactoryPtrInfo ipc_factory_info;
  // GetNetworkContext()->CreateIpcURLLoaderFactory(
  //   process_->loader_task_runner(),
  //   this,
  //   registry,
  //   mojo::MakeRequest(&ipc_factory_info));

  // // ipc
  // subresource_loader_factories->factories_info().emplace(
  //   ipc_scheme, 
  //   std::move(ipc_factory_info));


  network::mojom::URLLoaderFactoryPtrInfo application_factory_info;
  GetNetworkContext()->CreateApplicationURLLoaderFactory(
    process_->loader_task_runner(),
    this,
    delegate_->GetDomain(),
    registry,
    std::move(encoder),
    mojo::MakeRequest(&application_factory_info));

  // application
  //DLOG(INFO) << "\nApplicationWindowHost: creating url factory for '" << application_->name() << "'\n";
  subresource_loader_factories->factories_info().emplace(
    application_->name(), 
    std::move(application_factory_info));
  
    // Everyone gets a blob loader.
  network::mojom::URLLoaderFactoryPtrInfo blob_factory_info;
  delegate_->GetDomain()->GetBlobURLLoaderFactory()->HandleRequest(
    mojo::MakeRequest(&blob_factory_info));
  subresource_loader_factories->factories_info().emplace(
    url::kBlobScheme, std::move(blob_factory_info));

  if (entry->request()->url().SchemeIsFile()) {
    network::mojom::URLLoaderFactoryPtrInfo file_factory_info;
    delegate_->GetDomain()->GetFileURLLoaderFactory()->HandleRequest(
      mojo::MakeRequest(&file_factory_info));
    // Only file resources can load file subresources
    // non_network_url_loader_factories_.emplace(url::kFileScheme,
    //                                           std::move(file_factory));
    subresource_loader_factories->factories_info().emplace(
     url::kFileScheme, std::move(file_factory_info));
  }

  // network::mojom::URLLoaderFactoryPtrInfo default_factory_info = url_loader_factory.PassInterface();  
  subresource_loader_factories->default_factory_info() = std::move(default_url_loader_factory);
  
  common::mojom::CommitNavigationParamsPtr params = common::mojom::CommitNavigationParams::New();
  params->url = entry->request()->url().spec();
  params->keep_alive = keep_alive;
  params->route_id = entry->route_id();

  ServiceWorkerRequestHandler* request_handler = ServiceWorkerRequestHandler::GetHandler(entry->request());
  if (request_handler) {
    //FIXME: MaybeCreateLoader() here might be not what we want here, but we need it for now
    // todo: make a elegant, better implementation for this
    network::ResourceRequest resource_request;
    resource_request.url = request->url();
    resource_request.method = "GET";
    request_handler->MaybeCreateLoader(
        resource_request, 
        delegate_->GetDomain()->GetResourceContext(),
        base::BindOnce(&ApplicationWindowHost::MaybeStartLoader,
                        //weak_factory_.GetWeakPtr(),
                        io_weak_this_,
                        base::Unretained(request_handler),
                        base::Passed(std::move(params)), 
                        base::Passed(std::move(subresource_loader_factories)), 
                        is_same_document));
  } else {
    CommitNavigationImpl(std::move(params), std::move(subresource_loader_factories), nullptr, is_same_document);
  }
  
}

void ApplicationWindowHost::MaybeStartLoader(
  NavigationLoaderInterceptor* navigation_loader_interceptor, 
  common::mojom::CommitNavigationParamsPtr params,
  std::unique_ptr<common::URLLoaderFactoryBundleInfo> subresource_loader_factories,
  bool is_same_document,
  common::SingleRequestURLLoaderFactory::RequestHandler single_request_handler) {
  DCHECK_CURRENTLY_ON(HostThread::IO);
  
  if (single_request_handler) {
    //DLOG(INFO) << "ApplicationWindowHost::MaybeStartLoader: single_request_handler is not null";
  }
  
  common::mojom::ControllerServiceWorkerInfoPtr controller_service_worker_info;
  base::Optional<common::SubresourceLoaderParams> subresource_loader_params = navigation_loader_interceptor->MaybeCreateSubresourceLoaderParams();
  if (subresource_loader_params) {
    controller_service_worker_info =
      std::move(subresource_loader_params->controller_service_worker_info);
  }
  CommitNavigationImpl(std::move(params), std::move(subresource_loader_factories), std::move(controller_service_worker_info), is_same_document);
}

void ApplicationWindowHost::CommitNavigationImpl(
  common::mojom::CommitNavigationParamsPtr params,
  std::unique_ptr<common::URLLoaderFactoryBundleInfo> subresource_loader_factories,
  common::mojom::ControllerServiceWorkerInfoPtr controller_service_worker,
  bool is_same_document) {
  DCHECK_CURRENTLY_ON(HostThread::IO);

  if (!GetApplicationWindowInterface()) {
    return;
  }

  NavigationEntry* entry = delegate_->GetNavigationController()->current();
  //DCHECK(entry->provider_id() != common::kInvalidServiceWorkerProviderId);
  params->provider_id = entry->provider_id();

  if (is_same_document) {
    GetApplicationWindowInterface()->CommitSameDocumentNavigation(
         std::move(params),
         std::move(subresource_loader_factories),
         controller_service_worker ? std::move(controller_service_worker) : nullptr,
         base::BindOnce(&ApplicationWindowHost::OnSameDocumentCommitProcessed,
                        io_weak_this_));
  } else {
     GetApplicationWindowInterface()->CommitNavigation( 
       std::move(params),
       std::move(subresource_loader_factories),
       controller_service_worker ? std::move(controller_service_worker) : nullptr);
  }

}

void ApplicationWindowHost::UpdateLoadProgress(double progress) {
  if (progress <= load_progress_)
    return;
  load_progress_ = progress;

  // Notify the ApplicationContents.
  delegate_->DidChangeLoadProgress();
}

void ApplicationWindowHost::ResetLoadProgress() {
  load_progress_ = 0.0;
}

void ApplicationWindowHost::OnSameDocumentCommitProcessed(blink::mojom::CommitResult result) {
  //DLOG(INFO) << "ApplicationWindowHost::OnSameDocumentCommitProcessed: " << result;
}


/*
 *
 *
 *
 *
 */

void ApplicationWindowHost::UpdateWindowScreenRect(const gfx::Rect& rect) {
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendUpdateWindowScreenRect,
      io_weak_this_,
      rect)
  );
}

void ApplicationWindowHost::SendUpdateWindowScreenRect(const gfx::Rect& rect) {
  if (auto* window = GetApplicationWindowInterface()) {
    window->UpdateWindowScreenRect(rect);
  }
}

void ApplicationWindowHost::UpdateScreenInfo(const common::ScreenInfo& screen_info) {
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendUpdateScreenInfo,
      io_weak_this_,
      screen_info)
  );
}

void ApplicationWindowHost::SendUpdateScreenInfo(const common::ScreenInfo& screen_info) {
  if (auto* window = GetApplicationWindowInterface()) {
    window->UpdateScreenInfo(screen_info);
  }
}

void ApplicationWindowHost::PausePageScheduledTasks(bool paused) {
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendPausePageScheduledTasks,
      io_weak_this_,
      paused)
  );
}

void ApplicationWindowHost::PageWasShown() {
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendPageWasShown,
      io_weak_this_)
  );
}

void ApplicationWindowHost::PageWasHidden() {
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendPageWasHidden,
      io_weak_this_)
  );
}

void ApplicationWindowHost::SetPageScale(float scale) {
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendSetPageScale,
      io_weak_this_,
      scale)
  );
}

void ApplicationWindowHost::SendPausePageScheduledTasks(bool paused) {
  if (auto* window = GetApplicationWindowInterface()) {
    window->PausePageScheduledTasks(paused);
  }
}

void ApplicationWindowHost::SendPageWasShown() {
  if (auto* window = GetApplicationWindowInterface()) {
    window->PageWasShown();
  }
} 

void ApplicationWindowHost::SendPageWasHidden() {
  if (auto* window = GetApplicationWindowInterface()) {
    window->PageWasHidden();
  }
}

void ApplicationWindowHost::SendSetPageScale(float scale) {
  if (auto* window = GetApplicationWindowInterface()) {
    window->SetPageScale(scale);
  }
}

void ApplicationWindowHost::UpdateViewportIntersection(
    const gfx::Rect& viewport_intersection,
    const gfx::Rect& compositor_visible_rect) {
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendUpdateViewportIntersection,
      io_weak_this_,
      viewport_intersection,
      compositor_visible_rect)
  );
}

void ApplicationWindowHost::SendUpdateViewportIntersection(
  const gfx::Rect& viewport_intersection,
  const gfx::Rect& compositor_visible_rect) {
  //DLOG(INFO) << "ApplicationWindowHost::SendUpdateViewportIntersection";
  if (auto* window = GetApplicationWindowInterface()) {
    window->SetViewportIntersection(viewport_intersection, compositor_visible_rect);
  }
}

void ApplicationWindowHost::SetIsInert(bool inert) {
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendSetIsInert,
      io_weak_this_,
      inert)
  );
}

void ApplicationWindowHost::SendSetIsInert(bool inert) {
  if (auto* window = GetApplicationWindowInterface()) {
    window->SetIsInert(inert);
  }
}

void ApplicationWindowHost::UpdateRenderThrottlingStatus(bool throttling, bool subtree_throttling) {
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendUpdateRenderThrottlingStatus,
      io_weak_this_,
      throttling,
      subtree_throttling)
  );
}

void ApplicationWindowHost::SendUpdateRenderThrottlingStatus(bool throttling, bool subtree_throttling) {
  if (auto* window = GetApplicationWindowInterface()) {
    window->UpdateRenderThrottlingStatus(throttling, subtree_throttling);
  }
}

void ApplicationWindowHost::SetZoomLevel(double level) {
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendSetZoomLevel,
      io_weak_this_,
      level)
  );
}

void ApplicationWindowHost::SendSetZoomLevel(double level) {
  //DLOG(INFO) << "ApplicationWindowHost::SendSetZoomLevel";
  if (auto* app_window = GetApplicationWindowInterface()) {
    app_window->SetZoomLevel(level);
  }
}

void ApplicationWindowHost::AudioStateChanged(bool is_audible) {
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendAudioStateChanged,
      io_weak_this_,
      is_audible)
  );
}

void ApplicationWindowHost::SendAudioStateChanged(bool is_audible) {
  //DLOG(INFO) << "ApplicationWindowHost::SendAudioStateChanged";
  if (auto* app_window = GetApplicationWindowInterface()) {
    app_window->AudioStateChanged(is_audible);
  }
}

void ApplicationWindowHost::SendUpdateScreenRects(const gfx::Rect& view_rect, const gfx::Rect& window_rect) {
  //DLOG(INFO) << "ApplicationWindowHost::SendUpdateScreenRects";
  if (auto* app_window = GetApplicationWindowInterface()) {
    app_window->UpdateScreenRects(view_rect, window_rect);
  }
}

void ApplicationWindowHost::SendSetFocus(bool focused) {
  //DLOG(INFO) << "ApplicationWindowHost::SendSetFocus";
  if (auto* input_handler = GetWindowInputHandler()) {
    input_handler->SetFocus(focused);
  }
}

void ApplicationWindowHost::SendSetTextDirection(blink::WebTextDirection text_direction) {
  //DLOG(INFO) << "ApplicationWindowHost::SendSetTextDirection";
  if (auto* app_window = GetApplicationWindowInterface()) {
    app_window->SetTextDirection(FromWebTextDirection(text_direction));
  }
}

void ApplicationWindowHost::SendImeSetComposition(
    const base::string16& text,
    const std::vector<ui::ImeTextSpan>& ime_text_spans,
    const gfx::Range& replacement_range,
    int selection_start,
    int selection_end) {
  //DLOG(INFO) << "ApplicationWindowHost::SendImeSetComposition";
  if (auto* input_handler = GetWindowInputHandler()) {
    input_handler->ImeSetComposition(text, ime_text_spans, replacement_range, selection_start, selection_end);
  }
}

void ApplicationWindowHost::SendImeCommitText(
  const base::string16& text,
  const std::vector<ui::ImeTextSpan>& ime_text_spans,
  const gfx::Range& replacement_range,
  int relative_cursor_pos) {
  //DLOG(INFO) << "ApplicationWindowHost::SendImeCommitText";
  if (auto* input_handler = GetWindowInputHandler()) {
    input_handler->ImeCommitText(text, ime_text_spans, replacement_range, relative_cursor_pos);
  }
}

void ApplicationWindowHost::SendImeFinishComposingText(bool keep_selection) {
  //DLOG(INFO) << "ApplicationWindowHost::SendImeFinishComposingText";
  if (auto* input_handler = GetWindowInputHandler()) {
    input_handler->ImeFinishComposingText(keep_selection);
  }
}

void ApplicationWindowHost::SendImeCancelComposition() {
  //DLOG(INFO) << "ApplicationWindowHost::SendImeCancelComposition";
  if (auto* input_handler = GetWindowInputHandler()) {
    input_handler->ImeSetComposition(
      base::string16(), 
      std::vector<ui::ImeTextSpan>(),
      gfx::Range::InvalidRange(), 
      0, 
      0);
  }
}

void ApplicationWindowHost::SendShowContextMenuAtPoint(
    common::mojom::MenuSourceType source_type,
    const gfx::Point& point) {
  //DLOG(INFO) << "ApplicationWindowHost::SendShowContextMenuAtPoint";
  if (auto* app_window = GetApplicationWindowInterface()) {
    app_window->ShowContextMenu(source_type, point);
  }
}

void ApplicationWindowHost::SendRequestCompositionUpdates(
  bool immediate_request,
  bool monitor_updates) {
  //DLOG(INFO) << "ApplicationWindowHost::SendRequestCompositionUpdates";
  if (auto* input_handler = GetWindowInputHandler()) {
    input_handler->RequestCompositionUpdates(immediate_request, monitor_updates);
  }
}

void ApplicationWindowHost::SendSetEditCommandsForNextKeyEvent(const std::vector<common::EditCommand>& commands) {
   //DLOG(INFO) << "ApplicationWindowHost::SendSetEditCommandsForNextKeyEvent";
   if (auto* input_handler = GetWindowInputHandler()) {
     input_handler->SetEditCommandsForNextKeyEvent(commands);
   }
}

void ApplicationWindowHost::SendWasShown(const ui::LatencyInfo& latency_info, bool needs_repainting) {
  if (auto* app_window = GetApplicationWindowInterface()) {
    app_window->WasShown(needs_repainting, latency_info);
  }
}

void ApplicationWindowHost::SendCursorVisibilityChanged(bool is_visible) {
  if (auto* input_handler = GetWindowInputHandler()) {
    input_handler->CursorVisibilityChanged(is_visible);
  }
}

void ApplicationWindowHost::SendSynchronizeVisualProperties(common::VisualProperties properties) {
  if (auto* app_window = GetApplicationWindowInterface()) {
    app_window->SynchronizeVisualProperties(properties);
  }
}

void ApplicationWindowHost::SendWasHidden() {
  if (auto* app_window = GetApplicationWindowInterface()) {
    app_window->WasHidden();
  }
}

void ApplicationWindowHost::SendSetBackgroundOpaque(bool opaque) {
  if (auto* app_window = GetApplicationWindowInterface()) {
    app_window->SetBackgroundOpaque(opaque);
  }
}

void ApplicationWindowHost::SendMouseCaptureLost() {
  if (auto* input_handler = GetWindowInputHandler()) {
    input_handler->MouseCaptureLost();
  }
}

void ApplicationWindowHost::SendDragTargetDragOver(
  const gfx::PointF& client_pt,
  const gfx::PointF& screen_pt,
  blink::WebDragOperationsMask operations_allowed,
  int key_modifiers) {
  if (auto* app_window = GetApplicationWindowInterface()) {
    app_window->DragTargetDragOver(client_pt, screen_pt, operations_allowed, key_modifiers);
  }
}

void ApplicationWindowHost::SendDragTargetDragLeave(
  const gfx::PointF& client_point,
  const gfx::PointF& screen_point) {
  if (auto* app_window = GetApplicationWindowInterface()) {
    app_window->DragTargetDragLeave(client_point, screen_point);
  }
}

void ApplicationWindowHost::SendDragTargetDrop(
  const common::DropData& drop_data,
  const gfx::PointF& client_pt,
  const gfx::PointF& screen_pt,
  int key_modifiers) {
  if (auto* app_window = GetApplicationWindowInterface()) {
    app_window->DragTargetDrop(drop_data, client_pt, screen_pt, key_modifiers);
  }
}

void ApplicationWindowHost::SendDragSourceEnded(
  const gfx::PointF& client_pt,
  const gfx::PointF& screen_pt,
  blink::WebDragOperation operation) {
  if (auto* app_window = GetApplicationWindowInterface()) {
    app_window->DragSourceEnded(client_pt, screen_pt, operation);
  }
}

void ApplicationWindowHost::SendDragSourceSystemDragEnded() {
  if (auto* app_window = GetApplicationWindowInterface()) {
    app_window->DragSourceSystemDragEnded();
  }
}

void ApplicationWindowHost::MoveAck() {
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendMoveAck,
      io_weak_this_)
  );
}

void ApplicationWindowHost::SendMoveAck() {
  if (auto* app_window = GetApplicationWindowInterface()) {
    app_window->MoveAck();
  }
}

void ApplicationWindowHost::SendLockMouseAck() {
  if (auto* window = GetApplicationWindowInterface()) {
    window->LockMouseAck(false);
  }
}

void ApplicationWindowHost::SendUpdateTargetURLAck() {
  if (auto* app_window = GetApplicationWindowInterface()) {
    app_window->UpdateTargetURLAck();
  }
}

void ApplicationWindowHost::SendDisableScrollbarsForSmallWindows(const gfx::Size& size) {
  if (auto* window = GetApplicationWindowInterface()) {
    window->DisableScrollbarsForSmallWindows(size);
  }
}

void ApplicationWindowHost::SendEnablePreferredSizeChangedMode() {
  if (auto* window = GetApplicationWindowInterface()) {
    window->EnablePreferredSizeChangedMode();
  }
}

void ApplicationWindowHost::SendMediaPlayerActionAt(
    const gfx::Point& location,
    const blink::WebMediaPlayerAction& action) {
  if (auto* window = GetApplicationWindowInterface()) {
    window->MediaPlayerActionAt(location, action);
  }
}

void ApplicationWindowHost::SendMoveOrResizeStarted() {
  if (auto* window = GetApplicationWindowInterface()) {
    window->MoveOrResizeStarted();
  }
}

void ApplicationWindowHost::SendMouseLockLost() {
  if (auto* window = GetApplicationWindowInterface()) {
    window->MouseLockLost();
  }
}

void ApplicationWindowHost::SendRendererPrefs(common::RendererPreferences prefs) {
  if (auto* window = GetApplicationWindowInterface()) {
    window->SetRendererPrefs(std::move(prefs));
  }
}

void ApplicationWindowHost::SendUpdateWebPreferences(const common::WebPreferences& prefs) {
  if (auto* window = GetApplicationWindowInterface()) {
    window->UpdateWebPreferences(prefs);
  }
}

void ApplicationWindowHost::SendSelectWordAroundCaret() {
  if (auto* window = GetApplicationWindowInterface()) {
    window->SelectWordAroundCaret();
  }
}

void ApplicationWindowHost::SendClosePage() {
  if (auto* window = GetApplicationWindowInterface()) {
    window->ClosePage();
  }
}

void ApplicationWindowHost::SendSetInitialFocus(bool reverse) {
  if (auto* window = GetApplicationWindowInterface()) {
    window->SetInitialFocus(reverse);
  }
}

void ApplicationWindowHost::SendCloseFromContents() {
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &ApplicationWindowHost::SendClose,
      io_weak_this_)
  );
}

void ApplicationWindowHost::SendClose() {
  if (auto* window = GetApplicationWindowInterface()) {
    window->Close();
  }
}

void ApplicationWindowHost::SendCopyImageAt(int x, int y) {
  if (auto* window = GetApplicationWindowInterface()) {
    window->CopyImageAt(x, y);
  }
}

void ApplicationWindowHost::SendSaveImageAt(int x, int y) {
  if (auto* window = GetApplicationWindowInterface()) {
    window->SaveImageAt(x, y);
  }
}

void ApplicationWindowHost::SendSwapOut(int routing_id, bool is_loading) {
  if (auto* window = GetApplicationWindowInterface()) {
    window->SwapOut(routing_id, is_loading);
  }
}

void ApplicationWindowHost::SendSetFocusedWindow() {
  if (auto* window = GetApplicationWindowInterface()) {
    window->SetFocusedWindow();
  }
}

void ApplicationWindowHost::SendSetActive(bool active) {
  if (auto* app_window = GetApplicationWindowInterface()) {
    app_window->SetActive(active);
  }
}

}
