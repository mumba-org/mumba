// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_APPLICATION_WINDOW_HOST_H_
#define MUMBA_HOST_APPLICATION_APPLICATION_WINDOW_HOST_H_

#include <vector>

#include "base/macros.h"
#include <stddef.h>
#include <stdint.h>

#include <list>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/callback.h"
#include "base/containers/flat_set.h"
#include "base/containers/queue.h"
#include "base/macros.h"
#include "base/memory/shared_memory_handle.h"
#include "base/memory/weak_ptr.h"
#include "base/observer_list.h"
#include "base/optional.h"
#include "base/process/kill.h"
#include "base/strings/string16.h"
#include "base/time/tick_clock.h"
#include "base/time/time.h"
#include "base/timer/elapsed_timer.h"
#include "build/build_config.h"
#include "ui/base/ui_base_types.h"
#include "ui/latency/latency_info.h"
#include "media/mojo/interfaces/interface_factory.mojom.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "mojo/public/cpp/bindings/associated_binding_set.h"
#include "mojo/public/cpp/bindings/interface_ptr.h"
#include "components/viz/common/quads/shared_bitmap.h"
#include "components/viz/common/surfaces/frame_sink_id.h"
#include "core/host/application/event_with_latency_info.h"
#include "core/host/application/frame_token_message_queue.h"
#include "core/host/application/input/input_disposition_handler.h"
#include "core/host/application/input/input_device_change_observer.h"
#include "core/host/application/input/input_router_impl.h"
#include "core/host/application/input/application_window_host_latency_tracker.h"
#include "core/host/application/input/synthetic_gesture.h"
#include "core/host/application/input/synthetic_gesture_controller.h"
#include "core/host/application/input/touch_emulator_client.h"
#include "core/host/application/render_frame_metadata_provider.h"
#include "core/host/application/application_process_host.h"
#include "core/host/application/application_process_host_observer.h"
#include "core/host/application/application_window_host_delegate.h"
#include "core/host/application/application_window_host_view.h"
#include "core/host/application/application_window_host_owner_delegate.h"
#include "core/host/application/application_window_host_observer.h"
#include "core/host/application/application_window_host_iterator.h"
#include "core/host/application/application_frame.h"
#include "core/host/application/native_web_keyboard_event.h"
#include "core/host/application/media/render_frame_audio_input_stream_factory.h"
#include "core/host/application/media/render_frame_audio_output_stream_factory.h"
#include "core/host/loader/navigation_loader_interceptor.h"
#include "core/shared/common/drop_data.h"
#include "core/shared/common/drag_event_source_info.h"
#include "core/shared/common/input/input_handler.mojom.h"
#include "core/shared/common/render_frame_metadata.mojom.h"
#include "core/shared/common/application_window_surface_properties.h"
#include "core/shared/common/view_message_enums.h"
#include "core/shared/common/mojom/application.mojom.h"
#include "core/shared/common/media/media_stream.mojom.h"
#include "core/shared/common/input_event_ack_state.h"
#include "core/shared/common/input_event_ack_source.h"
#include "core/shared/common/page_zoom.h"
#include "core/shared/common/frame_messages.h"
#include "core/shared/common/navigation_subresource_loader_params.h"
#include "core/shared/common/service_worker/controller_service_worker.mojom.h"
#include "core/host/host_controller.h"
#include "ipc/ipc_listener.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "services/device/public/cpp/device_features.h"
#include "services/network/public/mojom/websocket.mojom.h"
#include "services/network/public/cpp/features.h"
#include "services/viz/public/interfaces/compositing/compositor_frame_sink.mojom.h"
#include "services/viz/public/interfaces/hit_test/input_target_client.mojom.h"
#include "services/device/public/cpp/device_features.h"
#include "services/device/public/mojom/sensor_provider.mojom.h"
#include "services/device/public/mojom/wake_lock.mojom.h"
#include "services/device/public/mojom/wake_lock_context.mojom.h"
//#include "services/network/public/cpp/wrapper_shared_url_loader_factory.h"
#include "services/network/public/mojom/network_service.mojom.h"
#include "services/resource_coordinator/public/cpp/frame_resource_coordinator.h"
#include "services/resource_coordinator/public/cpp/resource_coordinator_features.h"
#include "services/service_manager/public/cpp/connector.h"
#include "services/service_manager/public/cpp/interface_provider.h"
#include "services/network/public/mojom/network_service.mojom.h"
#include "third_party/blink/public/platform/web_display_mode.h"
#include "third_party/blink/public/platform/web_drag_operation.h"
#include "third_party/blink/public/platform/web_gesture_event.h"
#include "third_party/blink/public/platform/web_input_event.h"
#include "third_party/blink/public/web/web_media_player_action.h"
#include "third_party/blink/public/web/web_text_direction.h"
#include "third_party/blink/public/web/web_fullscreen_options.h"
#include "ui/base/ime/text_input_mode.h"
#include "ui/base/ime/text_input_type.h"
#include "ui/base/ui_base_types.h"
#include "ui/surface/transport_dib.h"
#include "ui/gfx/native_widget_types.h"
#include "ui/latency/latency_info.h"

#if defined(OS_ANDROID)
#include "core/host/android/child_process_importance.h"
#endif

#if defined(OS_MACOSX)
#include "services/device/public/mojom/wake_lock.mojom.h"
#endif

class SkBitmap;
//struct FrameHostMsg_HittestData_Params;
//struct ViewHostMsg_SelectionBounds_Params;
//struct ViewHostMsg_ResizeOrRepaint_ACK_Params;
//struct FrameHostMsg_DidCommitProvisionalLoad_Params;

namespace blink {
class WebInputEvent;
class WebMouseEvent;
class WebMouseWheelEvent;
struct WebMediaPlayerAction;
class AssociatedInterfaceProvider;
}

namespace cc {
struct BeginFrameAck;
}  // namespace cc

namespace gfx {
class Image;
class Range;
class Vector2dF;
}

namespace service_manager {
class InterfaceProvider;
}

namespace resource_coordinator {
class FrameResourceCoordinator;
}

namespace common {
class AssociatedInterfaceProviderImpl;  
}

namespace net {
class RpcMessageEncoder;
}

namespace host {
class GpuHostCompositorOutputSurface;
class InProcessDisplayClient;
class OffscreenHostCompositorOutputSurface;
class SoftwareHostCompositorOutputSurface;
class ApplicationWindowHostDelegate;
class Application;
class ApplicationProcessHost;
class Domain;
class TouchEmulator;
class TimeoutMonitor;
class MediaStreamDispatcherHost;
class MediaInterfaceProxy;
class RouteRegistry;
class HostNetworkContext;
class ServiceWorkerNavigationHandle;
class NavigationEntry;

typedef base::Callback<void(bool)> VisualStateCallback;

/*
 * If the application has a window, this is its equivalent pair
 * on the host process side
 */
class ApplicationWindowHost : public common::mojom::ApplicationWindowHost,
                              public ApplicationProcessHostObserver,    
                              public viz::mojom::CompositorFrameSink,
                              public FrameTokenMessageQueue::Client,
                              public service_manager::mojom::InterfaceProvider,
                              public InputDispositionHandler,
                              public InputRouterImplClient,
                              // TODO: probably unnecessary give we use mojo here
                              public IPC::Listener,
                              public IPC::Sender {
public:
  using KeyPressEventCallback = base::Callback<bool(const NativeWebKeyboardEvent&)>;
  using MouseEventCallback = base::Callback<bool(const blink::WebMouseEvent&)>;
  using GetSnapshotFromHostCallback = base::Callback<void(const gfx::Image&)>;
  
  class InputEventObserver {
   public:
    virtual ~InputEventObserver() {}

    virtual void OnInputEvent(const blink::WebInputEvent&) {}
    virtual void OnInputEventAck(common::InputEventAckSource source,
                                 common::InputEventAckState state,
                                 const blink::WebInputEvent&) {}
  };
  // Returns the ApplicationWindowHost given its ID and the ID of its application process.
  // Returns nullptr if the IDs do not correspond to a live ApplicationWindowHost.
  static ApplicationWindowHost* FromID(int32_t process_id, int32_t routing_id);
  static ApplicationWindowHost* FromOverlayRoutingToken(const base::UnguessableToken& token);
  static std::unique_ptr<ApplicationWindowHostIterator> GetApplicationWindowHosts();
  static std::unique_ptr<ApplicationWindowHostIterator> GetAllApplicationWindowHosts();

  ApplicationWindowHost(ApplicationWindowHostDelegate* delegate,
                        Application* application, 
                        ApplicationProcessHost* process,
                        int32_t routing_id,
                        //mojom::WindowPtr widget_interface,
                        bool hidden);

  ~ApplicationWindowHost() override;

  void ShutdownAndDestroy();

  int routing_id() const {
    return routing_id_;
  }
  
  ApplicationFrame* current_application_frame() const {
    return application_frame_.get();
  }

  void GetInterface(
    const std::string& interface_name,
    mojo::ScopedMessagePipeHandle interface_pipe) override;

  ApplicationContents* application_contents() const;

  // Returns the viz::FrameSinkId that this object uses to put things on screen.
  // This value is constant throughout the lifetime of this object. Note that
  // until a ApplicationWindowHostView is created, initialized, and assigned to this
  // object, viz may not be aware of this FrameSinkId.
  const viz::FrameSinkId& GetFrameSinkId() const;

  void AddBinding(common::mojom::ApplicationWindowHostAssociatedRequest request);

  // ApplicationWindowHost implementation.
  void UpdateTextDirection(blink::WebTextDirection direction);
  void NotifyTextDirection();
  void DoFocus();
  void Blur();
  void SetActive(bool active);
  void ForwardMouseEvent(const blink::WebMouseEvent& mouse_event);
  void ForwardWheelEvent(const blink::WebMouseWheelEvent& wheel_event);
  void ForwardKeyboardEvent(const NativeWebKeyboardEvent& key_event);
  void ForwardGestureEvent(
      const blink::WebGestureEvent& gesture_event);
  ApplicationProcessHost* GetProcess() const;
  Application* GetApplication() const;
  int GetRoutingID() const;
  ApplicationWindowHostView* GetView() const;
  bool IsLoading() const;
  void ResetLoadingState();
  void StartHangMonitorTimeout(base::TimeDelta delay);
  void RestartHangMonitorTimeoutIfNecessary();
  bool IsCurrentlyUnresponsive() const;
  void SetIgnoreInputEvents(bool ignore_input_events);
  void SynchronizeVisualProperties();
  void AddKeyPressEventCallback(const KeyPressEventCallback& callback);
  void RemoveKeyPressEventCallback(
      const KeyPressEventCallback& callback);
  void AddMouseEventCallback(const MouseEventCallback& callback);
  void RemoveMouseEventCallback(const MouseEventCallback& callback);
  void AddInputEventObserver(
      InputEventObserver* observer);
  void RemoveInputEventObserver(
      InputEventObserver* observer);
  void AddObserver(ApplicationWindowHostObserver* observer);
  void RemoveObserver(ApplicationWindowHostObserver* observer);
  void GetScreenInfo(common::ScreenInfo* result);
  void InsertVisualStateCallback(const VisualStateCallback& callback);
  // |drop_data| must have been filtered. The embedder should call
  // FilterDropData before passing the drop data to RWHI.
  void DragTargetDragEnter(const common::DropData& drop_data,
                           const gfx::PointF& client_pt,
                           const gfx::PointF& screen_pt,
                           blink::WebDragOperationsMask operations_allowed,
                           int key_modifiers);
  void DragTargetDragEnterWithMetaData(
      std::vector<common::DropDataMetadata> metadata,
      const gfx::PointF& client_pt,
      const gfx::PointF& screen_pt,
      blink::WebDragOperationsMask operations_allowed,
      int key_modifiers);
  void DragTargetDragOver(const gfx::PointF& client_pt,
                          const gfx::PointF& screen_pt,
                          blink::WebDragOperationsMask operations_allowed,
                          int key_modifiers);
  void DragTargetDragLeave(const gfx::PointF& client_point,
                           const gfx::PointF& screen_point);
  // |drop_data| must have been filtered. The embedder should call
  // FilterDropData before passing the drop data to RWHI.
  void DragTargetDrop(const common::DropData& drop_data,
                      const gfx::PointF& client_pt,
                      const gfx::PointF& screen_pt,
                      int key_modifiers);
  void DragSourceEndedAt(const gfx::PointF& client_pt,
                         const gfx::PointF& screen_pt,
                         blink::WebDragOperation operation);
  void DragSourceSystemDragEnded();
  void FilterDropData(common::DropData* drop_data);
  //void SetCursor(const CursorInfo& cursor_info);
  // Notification that the screen info has changed.
  void NotifyScreenInfoChanged();

  void IssueKeepAliveHandle(common::mojom::KeepAliveHandleRequest keep_alive_handle) override;
  void BeginNavigation(const std::string& url) override;
  void DidChangeName(const std::string& name,
                     const std::string& unique_name) override;
  void FrameSizeChanged(const gfx::Size& frame_size) override;
  void OnUpdatePictureInPictureSurfaceId(
      const viz::SurfaceId& surface_id,
      const gfx::Size& natural_size) override;
  void OnExitPictureInPicture() override;
  void LayerTreeFrameSinkInitialized() override;
  void RequestOverlayRoutingToken() override;

  void BeginNavigationImpl(const GURL& url);

  resource_coordinator::FrameResourceCoordinator* GetFrameResourceCoordinator();

  void SetView(ApplicationWindowHostView* view);

  ApplicationWindowHostDelegate* delegate() const { return delegate_; }

  bool empty() const { return current_size_.IsEmpty(); }

  // Called when a renderer object already been created for this host, and we
  // just need to be attached to it. Used for window.open, <select> dropdown
  // menus, and other times when the renderer initiates creating an object.
  void Init();

  const base::UnguessableToken& GetOverlayRoutingToken();

  HostNetworkContext* GetNetworkContext() const;

  void SetFrameDepth(unsigned int depth);
  void UpdatePriority();

  void ShutdownAndDestroyWindow(bool also_delete);

  // Indicates if the page has finished loading.
  void SetIsLoading(bool is_loading);

  // Called to notify the ApplicationWindow that it has been hidden or restored from
  // having been hidden.
  void WasHidden();
  void WasShown(const ui::LatencyInfo& latency_info);

  // Returns true if the ApplicationWindow is hidden.
  bool is_hidden() const { return is_hidden_; }

  // Called to notify the ApplicationWindow that its associated native window
  // got/lost focused.
  void GotFocus();
  void LostFocus();
  void LostCapture();

  // Indicates whether the ApplicationWindowHost thinks it is focused.
  // This is different from ApplicationWindowHostView::HasFocus() in the sense that
  // it reflects what the renderer process knows: it saves the state that is
  // sent/received.
  // ApplicationWindowHostView::HasFocus() is checking whether the view is focused so
  // it is possible in some edge cases that a view was requested to be focused
  // but it failed, thus HasFocus() returns false.
  bool is_focused() const { return is_focused_; }

  // Support for focus tracking on multi-WebContents cases. This will notify all
  // renderers involved in a page about a page-level focus update. Users other
  // than WebContents and ApplicationWindowHost should use Focus()/Blur().
  void SetPageFocus(bool focused);

  // Called to notify the ApplicationWindow that it has lost the mouse lock.
  void LostMouseLock();

  // Notifies the ApplicationWindow that it lost the mouse lock.
  void SendLostMouseLock();

  // Noifies the ApplicationWindow of the current mouse cursor visibility state.
  void SendCursorVisibilityState(bool is_visible);

  // Notifies the ApplicationWindowHost that the View was destroyed.
  void ViewDestroyed();

  bool is_in_touchscreen_gesture_scroll() const {
    return is_in_gesture_scroll_[blink::kWebGestureDeviceTouchscreen];
  }

#if defined(OS_MACOSX)
  // Pause for a moment to wait for pending repaint or resize messages sent to
  // the renderer to arrive. If pending resize messages are for an old window
  // size, then also pump through a new resize message if there is time.
  void PauseForPendingResizeOrRepaints();
#endif

  // GPU accelerated version of GetBackingStore function. This will
  // trigger a re-composite to the view. It may fail if a resize is pending, or
  // if a composite has already been requested and not acked yet.
  bool ScheduleComposite();

  // Called by the RenderProcessHost to handle the case when the process
  // changed its state of ignoring input events.
  void ProcessIgnoreInputEventsChanged(bool ignore_input_events);

  // InputRouterImplClient
  common::InputEventAckState FilterInputEvent(
    const blink::WebInputEvent& input_event,
    const ui::LatencyInfo& latency_info) override;
  void IncrementInFlightEventCount() override;
  void DecrementInFlightEventCount(common::InputEventAckSource ack_source) override;
  void OnHasTouchEventHandlers(bool has_handlers) override;
  void DidOverscroll(const ui::DidOverscrollParams& params) override;
  void OnSetWhiteListedTouchAction(cc::TouchAction touch_action) override;
  void DidStopFlinging() override;
  void DidStartScrollingViewport() override;
  void SetNeedsBeginFrameForFlingProgress() override;
  void OnImeCancelComposition() override;
  void OnImeCompositionRangeChanged(
      const gfx::Range& range,
      const std::vector<gfx::Rect>& bounds) override;

  // Forwards the keyboard event with optional commands to the renderer. If
  // |key_event| is not forwarded for any reason, then |commands| are ignored.
  // |update_event| (if non-null) is set to indicate whether the underlying
  // event in |key_event| should be updated. |update_event| is only used on
  // aura.
  void ForwardKeyboardEventWithCommands(
      const NativeWebKeyboardEvent& key_event,
      const ui::LatencyInfo& latency,
      const std::vector<common::EditCommand>* commands,
      bool* update_event = nullptr);

  // Forwards the given message to the renderer. These are called by the view
  // when it has received a message.
  void ForwardKeyboardEventWithLatencyInfo(
      const NativeWebKeyboardEvent& key_event,
      const ui::LatencyInfo& latency);
  void ForwardGestureEventWithLatencyInfo(
      const blink::WebGestureEvent& gesture_event,
      const ui::LatencyInfo& latency) override;
  void ForwardTouchEventWithLatencyInfo(
      const blink::WebTouchEvent& touch_event,
      const ui::LatencyInfo& latency);  // Virtual for testing.
  void ForwardMouseEventWithLatencyInfo(const blink::WebMouseEvent& mouse_event,
                                        const ui::LatencyInfo& latency);
  void ForwardWheelEventWithLatencyInfo(
      const blink::WebMouseWheelEvent& wheel_event,
      const ui::LatencyInfo& latency) override;

  void SetCursor(const common::WebCursor& cursor);

  void ShowContextMenuAtPoint(const gfx::Point& point,
                              const ui::MenuSourceType source_type);

  void CancelUpdateTextDirection();

  void ProgressFlingIfNeeded(base::TimeTicks current_time);

  // Update the composition node of the renderer (or WebKit).
  // WebKit has a special node (a composition node) for input method to change
  // its text without affecting any other DOM nodes. When the input method
  // (attached to the browser) updates its text, the browser sends IPC messages
  // to update the composition node of the renderer.
  // (Read the comments of each function for its detail.)

  // Sets the text of the composition node.
  // This function can also update the cursor position and mark the specified
  // range in the composition node.
  // A browser should call this function:
  // * when it receives a WM_IME_COMPOSITION message with a GCS_COMPSTR flag
  //   (on Windows);
  // * when it receives a "preedit_changed" signal of GtkIMContext (on Linux);
  // * when markedText of NSTextInput is called (on Mac).
  void ImeSetComposition(const base::string16& text,
                         const std::vector<ui::ImeTextSpan>& ime_text_spans,
                         const gfx::Range& replacement_range,
                         int selection_start,
                         int selection_end);

  // Deletes the ongoing composition if any, inserts the specified text, and
  // moves the cursor.
  // A browser should call this function or ImeFinishComposingText:
  // * when it receives a WM_IME_COMPOSITION message with a GCS_RESULTSTR flag
  //   (on Windows);
  // * when it receives a "commit" signal of GtkIMContext (on Linux);
  // * when insertText of NSTextInput is called (on Mac).
  void ImeCommitText(const base::string16& text,
                     const std::vector<ui::ImeTextSpan>& ime_text_spans,
                     const gfx::Range& replacement_range,
                     int relative_cursor_pos);

  // Finishes an ongoing composition.
  // A browser should call this function or ImeCommitText:
  // * when it receives a WM_IME_COMPOSITION message with a GCS_RESULTSTR flag
  //   (on Windows);
  // * when it receives a "commit" signal of GtkIMContext (on Linux);
  // * when insertText of NSTextInput is called (on Mac).
  void ImeFinishComposingText(bool keep_selection);

  // Cancels an ongoing composition.
  void ImeCancelComposition();

  bool ignore_input_events() const {
    return ignore_input_events_;
  }

  // Whether forwarded WebInputEvents should be dropped.
  bool ShouldDropInputEvents() const;

  bool has_touch_handler() const { return has_touch_handler_; }

  // Set the ApplicationWindow background transparency.
  void SetBackgroundOpaque(bool opaque);

  // Called when the response to a pending mouse lock request has arrived.
  // Returns true if |allowed| is true and the mouse has been successfully
  // locked.
  bool GotResponseToLockMouseRequest(bool allowed);

  void set_allow_privileged_mouse_lock(bool allow) {
    allow_privileged_mouse_lock_ = allow;
  }

  // Called when the response to a pending keyboard lock request has arrived.
  // |allowed| should be true if the current tab is in tab initiated fullscreen
  // mode.
  void GotResponseToKeyboardLockRequest(bool allowed);

  void ResetSizeAndRepaintPendingFlags();

  void DetachDelegate();

  // Update the renderer's cache of the screen rect of the view and window.
  void SendScreenRects();

  // Indicates whether the renderer drives the ApplicationWindowHosts's size or the
  // other way around.
  bool auto_resize_enabled() { return auto_resize_enabled_; }

  // The minimum size of this renderer when auto-resize is enabled.
  const gfx::Size& min_size_for_auto_resize() const {
    return min_size_for_auto_resize_;
  }

  // The maximum size of this renderer when auto-resize is enabled.
  const gfx::Size& max_size_for_auto_resize() const {
    return max_size_for_auto_resize_;
  }

  //void DidReceiveRendererFrame();

  // Returns the ID that uniquely describes this component to the latency
  // subsystem.
  int64_t GetLatencyComponentId() const;

  const GURL& GetLastCommittedURL();
  const url::Origin& GetLastCommittedOrigin();
  void SetLastCommittedOrigin(const url::Origin& origin);

  static void OnGpuSwapBuffersCompleted(
      const std::vector<ui::LatencyInfo>& latency_info);

  InputRouter* input_router() { return input_router_.get(); }

  void SetForceEnableZoom(bool);

  void RejectMouseLockOrUnlockIfNecessary();

  void set_application_initialized(bool application_initialized) {
    application_initialized_ = application_initialized;
  }

  // Indicates if the render widget host should track the render widget's size
  // as opposed to visa versa.
  void SetAutoResize(bool enable,
                     const gfx::Size& min_size,
                     const gfx::Size& max_size);

  // Fills in the |visual_properties| struct.
  // Returns |false| if the update is redundant, |true| otherwise.
  bool GetVisualProperties(common::VisualProperties* visual_properties);

  // Sets the |visual_properties| that were sent to the renderer bundled with
  // the request to create a new ApplicationWindow.
  void SetInitialApplicationSizeParams(const common::VisualProperties& visual_properties);

  // Pushes updated visual properties to the renderer as well as whether the
  // focused node should be scrolled into view.
  void SynchronizeVisualProperties(bool scroll_focused_node_into_view);

  // Called when we receive a notification indicating that the renderer process
  // is gone. This will reset our state so that our state will be consistent if
  // a new renderer is created.
  void ApplicationExited(base::TerminationStatus status, int exit_code);

  size_t in_flight_event_count() const { return in_flight_event_count_; }

  bool application_initialized() const { return application_initialized_; }

  bool needs_begin_frames() const { return needs_begin_frames_; }

  base::WeakPtr<ApplicationWindowHost> GetWeakPtr() {
    return weak_factory_.GetWeakPtr();
  }

  void RequestCompositionUpdates(bool immediate_request, bool monitor_updates);

  void RequestCompositorFrameSink(
      viz::mojom::CompositorFrameSinkRequest compositor_frame_sink_request,
      viz::mojom::CompositorFrameSinkClientPtr compositor_frame_sink_client);

  void RegisterRenderFrameMetadataObserver(
      common::mojom::RenderFrameMetadataObserverClientRequest
          render_frame_metadata_observer_client_request,
      common::mojom::RenderFrameMetadataObserverPtr render_frame_metadata_observer);

  //void RequestCompositorFrameSink(
  //    viz::mojom::CompositorFrameSinkRequest compositor_frame_sink_request,
  //    viz::mojom::CompositorFrameSinkClientPtr compositor_frame_sink_client,
  //    common::mojom::RenderFrameMetadataObserverClientRequest
  //        render_frame_metadata_observer_client_request,
  //    common::mojom::RenderFrameMetadataObserverPtr render_frame_metadata_observer);

  const viz::CompositorFrameMetadata& last_frame_metadata() {
    return last_frame_metadata_;
  }

  RenderFrameMetadataProvider* render_frame_metadata_provider() {
    return &render_frame_metadata_provider_;
  }

  void GetContentRenderingTimeoutFrom(ApplicationWindowHost* other);

  // viz::mojom::CompositorFrameSink implementation.
  void SetNeedsBeginFrame(bool needs_begin_frame) override;
  void SetWantsAnimateOnlyBeginFrames() override;
  void SubmitCompositorFrame(
      const viz::LocalSurfaceId& local_surface_id,
      viz::CompositorFrame frame,
      viz::mojom::HitTestRegionListPtr hit_test_region_list,
      uint64_t submit_time) override;
  void DidNotProduceFrame(const viz::BeginFrameAck& ack) override;
  void DidAllocateSharedBitmap(mojo::ScopedSharedBufferHandle buffer,
                               const viz::SharedBitmapId& id) override;
  void DidDeleteSharedBitmap(const viz::SharedBitmapId& id) override;

  // Signals that a frame with token |frame_token| was finished processing. If
  // there are any queued messages belonging to it, they will be processed.
  void DidProcessFrame(uint32_t frame_token);

  void SetWindowInputHandler(
      common::mojom::WindowInputHandlerAssociatedPtr widget_input_handler,
      common::mojom::WindowInputHandlerHostRequest host_request);

  viz::mojom::InputTargetClient* input_target_client() {
    return input_target_client_.get();
  }

  void SetInputTargetClient(
      viz::mojom::InputTargetClientPtr input_target_client);

  // FrameTokenMessageQueue::Client:
  void OnInvalidFrameToken(uint32_t frame_token) override;
  void OnMessageDispatchError(const IPC::Message& message) override;
  void OnProcessSwapMessage(const IPC::Message& message) override;

  // IPC::Sender
  bool Send(IPC::Message* message) override;
  bool OnMessageReceived(const IPC::Message& message);

  void ProgressFling(base::TimeTicks current_time);
  void StopFling();
  bool FlingCancellationIsDeferred() const;

  void DidReceiveFirstFrameAfterNavigation();

  void ForceFirstFrameAfterNavigationTimeout();

  uint32_t current_content_source_id() { return current_content_source_id_; }

  // Requests Keyboard lock.  Note: the lock may not take effect until later.
  // If |keys_to_lock| has no value then all keys will be locked, otherwise only
  // the keys specified will be intercepted and routed to the web page.
  void RequestKeyboardLock(base::Optional<base::flat_set<int>> keys_to_lock);

  // Cancels a previous keyboard lock request.
  void CancelKeyboardLock();

  // Indicates whether keyboard lock is active.
  bool IsKeyboardLocked() const;

  // InputAckHandler
  void OnKeyboardEventAck(const NativeWebKeyboardEventWithLatencyInfo& event,
                          common::InputEventAckSource ack_source,
                          common::InputEventAckState ack_result) override;
  void OnMouseEventAck(const common::MouseEventWithLatencyInfo& event,
                       common::InputEventAckSource ack_source,
                       common::InputEventAckState ack_result) override;
  void OnWheelEventAck(const common::MouseWheelEventWithLatencyInfo& event,
                       common::InputEventAckSource ack_source,
                       common::InputEventAckState ack_result) override;
  void OnTouchEventAck(const common::TouchEventWithLatencyInfo& event,
                       common::InputEventAckSource ack_source,
                       common::InputEventAckState ack_result) override;
  void OnGestureEventAck(const common::GestureEventWithLatencyInfo& event,
                         common::InputEventAckSource ack_source,
                         common::InputEventAckState ack_result) override;
  void OnUnexpectedEventAck(UnexpectedEventAckType type) override;

  
  bool IsMouseLocked() const;

  void Focus() override;

  void WindowCreatedAck() override;

  void GenerateRoutingID(GenerateRoutingIDCallback callback) override;

  //(probably) useful stuff from ApplicationWindowHost
  bool IsApplicationWindowLive() const;
  void DisableScrollbarsForThreshold(const gfx::Size& size);
  void EnablePreferredSizeMode();
  void ExecuteMediaPlayerActionAtLocation(
      const gfx::Point& location,
      const blink::WebMediaPlayerAction& action);
  void NotifyMoveOrResizeStarted();
  //void SetWebUIProperty(const std::string& name,
  //                      const std::string& value);
  void SyncRendererPrefs();
  common::WebPreferences GetWebkitPreferences();
  void UpdateWebkitPreferences(const common::WebPreferences& prefs);
  void OnWebkitPreferencesChanged();
  void SelectWordAroundCaret();

  bool CreateApplicationWindow();//bool launch_process = false);
      //int opener_frame_route_id,
      //int proxy_route_id,
      //const base::UnguessableToken& devtools_frame_token,
      //const common::FrameReplicationState& replicated_frame_state,
      //bool window_was_created_with_opener);

  bool is_active() const { return is_active_; }
  void SetIsActive(bool is_active);

  void set_is_swapped_out(bool is_swapped_out) {
    is_swapped_out_ = is_swapped_out;
  }

  void DispatchApplicationWindowCreated();

  void ClosePage();
  void ClosePageIgnoringUnloadEvents();

  // Tells the renderer view to focus the first (last if reverse is true) node.
  void SetInitialFocus(bool reverse);

  bool SuddenTerminationAllowed() const;
  void set_sudden_termination_allowed(bool enabled) {
    sudden_termination_allowed_ = enabled;
  }

  // Creates a new ApplicationWindow with the given route id.  |popup_type| indicates
  // if this widget is a popup and what kind of popup it is (select, autofill).
  void CreateNewWindow(int32_t route_id,
                       //mojom::WindowPtr widget,
                       blink::WebPopupType popup_type);

  // Creates a full screen ApplicationWindow.
  void CreateNewFullscreenWindow(int32_t route_id);//, mojom::WindowPtr widget);

  // Send ApplicationWindowReady to observers once the process is launched, but not
  // re-entrantly.
  void PostApplicationWindowReady();

  //void set_main_frame_routing_id(int routing_id) {
  //  main_frame_routing_id_ = routing_id;
  //}

  void ApplicationWindowDidInit();
  //void ApplicationWindowWillSetIsLoading(bool is_loading);
  //void ApplicationWindowGotFocus();
  //void ApplicationWindowLostFocus();
  //void ApplicationWindowDidForwardMouseEvent(
  //    const blink::WebMouseEvent& mouse_event);
  // bool MayApplicationWindowForwardKeyboardEvent(
  //     const NativeWebKeyboardEvent& key_event);
  bool ShouldContributePriorityToProcess();

  // ?? 
  
  // void OnShowView(int route_id,
  //                 WindowOpenDisposition disposition,
  //                 const gfx::Rect& initial_rect,
  //                 bool user_gesture);

  // probably Useful stuff from RenderFrameHost
  void CopyImageAt(int x, int y);
  void SaveImageAt(int x, int y);
  bool HasSelection();

  viz::mojom::InputTargetClient* GetInputTargetClient() {
    return input_target_client_.get();
  }

  //bool CreateRenderFrame(int proxy_routing_id,
  //                       int opener_routing_id,
  //                       int parent_routing_id,
  //                       int previous_sibling_routing_id);

  void SetApplicationWindowCreated(bool created);

  bool is_audible() const { return is_audible_; }
  void OnAudibleStateChanged(bool is_audible);

  // Tells the renderer that this RenderFrame is being swapped out for one in a
  // different renderer process.  It should run its unload handler and move to
  // a blank document.  If |proxy| is not null, it should also create a
  // RenderFrameProxy to replace the RenderFrame and set it to |is_loading|
  // state. The renderer should preserve the RenderFrameProxy object until it
  // exits, in case we come back.  The renderer can exit if it has no other
  // active RenderFrames, but not until WasSwappedOut is called.
  void SwapOut(ApplicationFrame* proxy, bool is_loading);

  bool DeleteFromPendingList(ApplicationWindowHost* app_window_host);

  // Called when either the SwapOut request has been acknowledged or has timed
  // out.
  void OnSwappedOut() override;

  // This method returns true from the time this RenderFrameHost is created
  // until SwapOut is called, at which point it is pending deletion.
  bool is_active() { return !is_waiting_for_swapout_ack_; }

  // Set this frame as focused in the renderer process.  This supports
  // cross-process window.focus() calls.
  void SetFocusedFrame();

  service_manager::InterfaceProvider* GetRemoteInterfaces();
  blink::AssociatedInterfaceProvider* GetRemoteAssociatedInterfaces();

  // Returns this FrameTree's total load progress.
  double load_progress() { return load_progress_; }
  void UpdateLoadProgress(double progress);
  void ResetLoadProgress();

  void ResetSentVisualProperties();

  common::mojom::ApplicationWindow* GetApplicationWindowInterface();

  // void UpdateViewportIntersection(
  //   const gfx::Rect& viewport_intersection,
  //   const gfx::Rect& compositor_visible_rect);
  
  void SetIsInert(bool inert);

  //void UpdateRenderThrottlingStatus(bool throttling, bool subtree_throttling);
  void SetZoomLevel(double level);
  void AudioStateChanged(bool is_audible);
  void PageWasShown();
  void PageWasHidden();
  void SetPageScale(float scale);
  void PausePageScheduledTasks(bool paused);
  void MoveAck();
  void SendCloseFromContents();
  void UpdateScreenInfo(const common::ScreenInfo& screen_info);
  void UpdateWindowScreenRect(const gfx::Rect& rect);

private:
  friend class GpuHostCompositorOutputSurface;
  friend class InProcessDisplayClient;
  friend class OffscreenHostCompositorOutputSurface;
  friend class SoftwareHostCompositorOutputSurface;
  friend class ApplicationProcessHost;
  friend class ApplicationContents;
  friend class ApplicationWindowHostViewChildFrame;

  common::mojom::WindowInputHandler* GetWindowInputHandler() override;
  
  void SetUpMojo();
  void RegisterMojoInterfaces();

  void UpdateScreenRectsAckImpl();
  void CloseAckImpl();

  // RenderFrameHost: private

  //void OnDetach();
  //void OnFrameFocused();
  void OnApplicationProcessGone(int status, int error_code);
  void OnVisualStateResponse(uint64_t id);
  //void OnTextSurroundingSelectionResponse(const base::string16& content,
  //                                        uint32_t start_offset,
  //                                        uint32_t end_offset);
  void OnUpdateTitle(const base::string16& title,
                     blink::WebTextDirection title_direction);
  void OnEnterFullscreen(const blink::WebFullscreenOptions& options);
  void OnExitFullscreen();

  void OnShowCreatedWindow(Application* application,
                           int pending_widget_routing_id,
                           WindowOpenDisposition disposition,
                           const gfx::Rect& initial_rect,
                           bool user_gesture);

  // mojom::FrameHost:
  void CreateNewWindowOnHost(common::mojom::CreateNewWindowParamsPtr params,
                             CreateNewWindowOnHostCallback callback) override;
  void DidCommitProvisionalLoad(
      common::mojom::DidCommitProvisionalLoadParamsPtr validated_params,
      service_manager::mojom::InterfaceProviderRequest
          interface_provider_request) override;

  void DidCommitProvisionalLoadImpl(
      common::mojom::DidCommitProvisionalLoadParamsPtr validated_params,
      service_manager::mojom::InterfaceProviderRequest
          interface_provider_request);

  void DidCommitSameDocumentNavigation(common::mojom::DidCommitProvisionalLoadParamsPtr params) override;
  
  // ApplicationWindow: private version

  void ApplicationWindowReady();

  void WindowCreatedAckImpl();
  
  void DidNavigate(
    const common::mojom::DidCommitProvisionalLoadParams& params,
    bool is_same_document_navigation);

  bool DidCommitNavigationInternal(
    const common::mojom::DidCommitProvisionalLoadParams& params,
    bool is_same_document_navigation);
  
  void CommitPendingIfNecessary(
    ApplicationFrame* app_frame_state,
    bool was_caused_by_user_gesture);

  void CommitPending();

  void SwapOutOldFrame(
    std::unique_ptr<ApplicationFrame> old_application_frame);
  
  // Called by |close_timeout_| when the page closing timeout fires.
  void ClosePageTimeout();
 
  void OnGpuSwapBuffersCompletedInternal(
      const ui::LatencyInfo& latency_info);

  // Tell this object to destroy itself. If |also_delete| is specified, the
  // destructor is called as well.
  void Destroy(bool also_delete);

  // Called by |hang_monitor_timeout_| on delayed response from the renderer.
  void ApplicationIsUnresponsive();

  // Called by |new_content_rendering_timeout_| if a renderer has loaded new
  // content but failed to produce a compositor frame in a defined time.
  void ClearDisplayedGraphics();

  // Called if we know the renderer is responsive. When we currently think the
  // renderer is unresponsive, this will clear that state and call
  // NotifyRendererResponsive.
  void ApplicationIsResponsive();

  void SetupInputRouter();

  // common::mojom::ApplicationWindowHost
  void ApplicationProcessGone(int32_t status, int32_t exit_code) override;
  void HittestData(const viz::SurfaceId& surface_id, bool ignored_for_hittest) override;
  void Close() override;
  void CloseAck() override;
  void UpdateScreenRectsAck() override;
  void RequestMove(const gfx::Rect& position) override;
  void SetTooltipText(const base::string16& text, base::i18n::TextDirection direction) override;
  void ResizeOrRepaintACK(const gfx::Size& view_size, int32_t flags, const base::Optional<viz::LocalSurfaceId>& local_surface_id) override;
  //void SetCursor(common::mojom::CursorPtr cursor) override;
  void AutoscrollStart(const gfx::PointF& start) override;
  void AutoscrollFling(const gfx::Vector2dF& velocity) override;
  void AutoscrollEnd() override;
  void TextInputStateChanged(const common::TextInputState& text_input_state) override;
  void LockMouse(bool user_gesture, bool privileged) override;
  void UnlockMouse() override;
  void SelectionBoundsChanged(common::mojom::SelectionBoundsParamsPtr params) override;
  void FocusedNodeTouched(bool editable) override;
  void StartDragging(const common::DropData& drop_data,
                     blink::WebDragOperationsMask ops_allowed,
                     const SkBitmap& image,
                     const gfx::Vector2d& image_offset,
                     const common::DragEventSourceInfo& event_info);
  void UpdateDragCursor(blink::WebDragOperation drag_operation) override;
  void FrameSwapMessagesReceived(uint32_t frame_token) override;
  // was:  FrameSwapMessagesReceived(uint32 frame_token, array<IPC::Message> messages);
  void ShowWindow(int32_t route_id, const gfx::Rect& initial_rect) override;
  void ShowFullscreenWindow(int32_t route_id) override;
  void UpdateTargetURL(const std::string& url) override;
  void DocumentAvailableInMainFrame(bool uses_temporary_zoom_level) override;
  void DidContentsPreferredSizeChange(const gfx::Size& pref_size) override;
  void RouteCloseEvent() override;
  void TakeFocus(bool reverse) override;
  void ClosePageACK() override;
  void SwapOutAck() override;
  void SelectWordAroundCaretAck(bool did_select, int32_t start, int32_t end) override;

  void Detach(int32_t id) override;
  void FrameFocused() override;
  void DidStartProvisionalLoad(const GURL& url, const std::vector<GURL>& redirect_chain, base::TimeTicks navigation_start) override;
  void DidFailProvisionalLoadWithError(int32_t error_code, const base::string16& error_description, const GURL& url) override;
  void DidFinishDocumentLoad() override;
  void DidFailLoadWithError(const GURL& url, int32_t error_code, const base::string16& error_description) override;
  void DidStartLoading(bool to_different_document) override;
  void DidStopLoading() override;
  void UpdateState(::common::mojom::PageStatePtr state) override;
  void DidChangeLoadProgress(double load_progress) override;
  void OpenURL(const GURL& url) override;
  void DidFinishLoad(const GURL& url) override;
  void DocumentOnLoadCompleted(base::TimeTicks timestamp) override;
  void DidAccessInitialDocument() override;
  void UpdateTitle(const base::string16& title, base::i18n::TextDirection direction) override;
  void BeforeUnloadAck(bool proceed, base::TimeTicks start_time, base::TimeTicks end_time) override;
  void SynchronizeVisualProperties(const viz::SurfaceId& surface_id, const common::ScreenInfo& screen_info, bool auto_resize_enabled, const gfx::Size& min_size_for_auto_resize, const gfx::Size& max_size_for_auto_resize, const gfx::Rect& screen_space_rect, const gfx::Size& local_frame_size, int32_t capture_sequence_number) override;
  void UpdateViewportIntersection(const gfx::Rect& viewport_intersection, const gfx::Rect& compositor_visible_rect) override;
  void VisibilityChanged(bool visible) override;
  void UpdateRenderThrottlingStatus(bool is_throttled, bool subtree_throttled) override;
  void SetHasReceivedUserGesture() override;
  void SetHasReceivedUserGestureBeforeNavigation(bool value) override;
  void ContextMenu() override;
  void SelectionChanged(const base::string16& text,
                        uint32_t offset,
                        const gfx::Range& range) override;
  void VisualStateResponse(uint64_t id) override;
  void EnterFullscreen() override;
  void ExitFullscreen() override;
  void DispatchLoad() override;
  void CheckCompleted() override;
  void UpdateFaviconURL(const std::vector<GURL>& favicons) override;
  void ScrollRectToVisibleInParentFrame(const gfx::Rect& rect_to_scroll) override;
  void FrameDidCallFocus() override;
  void TextSurroundingSelectionResponse(
    const base::string16& content,
    uint32_t start_offset, 
    uint32_t end_offset) override;

  void DidChangeOpener(int32_t opener) override;

  void UpdateTitleImpl(const base::string16& title, base::i18n::TextDirection direction);
  void DidStopLoadingImpl();

  void PasteFromSelectionClipboard();
  void WindowSnapshotReachedScreen(int snapshot_id);
  void OnSnapshotFromSurfaceReceived(int snapshot_id, 
    int retry_count, 
    const SkBitmap& bitmap);
  void OnSnapshotReceived(int snapshot_id, gfx::Image image);

  void DidCompleteResizeOrRepaint(
    int32_t flags,
    const base::TimeTicks& paint_start);

  void DelayedAutoResized();

  void SetCursorImpl(const common::WebCursor& cursor);

  void DispatchInputEventWithLatencyInfo(
    const blink::WebInputEvent& event,
    ui::LatencyInfo* latency);

  bool KeyPressListenersHandleEvent(
    const NativeWebKeyboardEvent& event);

  void StopHangMonitorTimeout();

  void TextInputStateChangedImpl(const common::TextInputState& text_input_state);

  // Binds the request end of the InterfaceProvider interface through which
  // services provided by this RenderFrameHost are exposed to the correponding
  // RenderFrame. The caller is responsible for plumbing the client end to the
  // the renderer process.
  void BindInterfaceProviderRequest(
      service_manager::mojom::InterfaceProviderRequest
          interface_provider_request);

  // Start intercepting system keyboard events.
  bool LockKeyboard();

  // Stop intercepting system keyboard events.
  void UnlockKeyboard();

  bool SurfacePropertiesMismatch(
    const common::ApplicationWindowSurfaceProperties& first,
    const common::ApplicationWindowSurfaceProperties& second) const;

  void OnFrameSwapMessagesReceived(
    uint32_t frame_token,
    std::vector<IPC::Message> messages);

  // ApplicationProcessHostObserver
  void ApplicationProcessReady(ApplicationProcessHost* host) override;
  void ApplicationProcessShutdownRequested(ApplicationProcessHost* host) override;
  void ApplicationProcessWillExit(ApplicationProcessHost* host) override;

  void ApplicationProcessExited(ApplicationProcessHost* host,
                                const ChildProcessTerminationInfo& info) override;
  void ApplicationProcessHostDestroyed(ApplicationProcessHost* host) override;

  void OnProcessInit(); 

  void OnApplicationWindowInit();

  void BindProcess(ApplicationProcessHost* process);

  void ResizeOrRepaintACKImpl(const gfx::Size& view_size, int32_t flags, const base::Optional<viz::LocalSurfaceId>& local_surface_id);

  void DidStartMainFrameNavigation(const GURL& url);

  void DispatchBeforeUnload(bool for_navigation, bool is_reload);

  bool ShouldDispatchBeforeUnload() const;

  void CommitNavigation(
    NavigationEntry* entry, 
    bool keep_alive);

  void CommitNavigationOnIO(
    NavigationEntry* entry,
    bool keep_alive,
    bool is_same_document,
    RouteRegistry* registry,
    std::unique_ptr<net::RpcMessageEncoder> encoder);
  
  void CommitNavigationImpl(
    common::mojom::CommitNavigationParamsPtr params,
    std::unique_ptr<common::URLLoaderFactoryBundleInfo> subresource_loader_factories,
    common::mojom::ControllerServiceWorkerInfoPtr controller_service_worker,
    bool is_same_document);
    
  void OnSameDocumentCommitProcessed(blink::mojom::CommitResult result);

  void CancelPendingIfNecessary();
  std::unique_ptr<ApplicationFrame> UnsetSpeculativeApplicationFrame();
  void DiscardUnusedFrame(std::unique_ptr<ApplicationFrame> app_frame_state);

  std::unique_ptr<ApplicationFrame> SetApplicationFrameState(
    std::unique_ptr<ApplicationFrame> app_frame_state);

  void DeleteApplicationProxyState(int routing_id);

  void ApplicationProcessGoneForFrame();
  void DidChangeLoadProgressInternal(double load_progress);

  void DidStartLoadingImpl(bool to_different_document);
  void DidStartProvisionalLoadImpl(const GURL& url, const std::vector<GURL>& redirect_chain, base::TimeTicks navigation_start);
  void LayerTreeFrameSinkInitializedImpl();

  void SelectionBoundsChangedImpl(common::mojom::SelectionBoundsParamsPtr params);

  void BindMediaInterfaceFactoryRequest(media::mojom::InterfaceFactoryRequest request);
  void CreateAudioInputStreamFactory(common::mojom::RendererAudioInputStreamFactoryRequest request);
  void CreateAudioOutputStreamFactory(common::mojom::RendererAudioOutputStreamFactoryRequest request);
  //void CreateAudioOutputStreamFactoryInternal();
  void CreateWebSocket(network::mojom::WebSocketRequest request);
  void CreateMediaStreamDispatcherHost(MediaStreamManager* media_stream_manager,
    common::mojom::MediaStreamDispatcherHostRequest request);
  void OnMediaInterfaceFactoryConnectionError();

  void OnKeyboardEventAckImpl(const NativeWebKeyboardEventWithLatencyInfo& event,
                          common::InputEventAckSource ack_source,
                          common::InputEventAckState ack_result);
  void OnMouseEventAckImpl(const common::MouseEventWithLatencyInfo& event,
                       common::InputEventAckSource ack_source,
                       common::InputEventAckState ack_result);
  void OnWheelEventAckImpl(const common::MouseWheelEventWithLatencyInfo& event,
                       common::InputEventAckSource ack_source,
                       common::InputEventAckState ack_result);
  void OnTouchEventAckImpl(const common::TouchEventWithLatencyInfo& event,
                       common::InputEventAckSource ack_source,
                       common::InputEventAckState ack_result);
  void OnGestureEventAckImpl(const common::GestureEventWithLatencyInfo& event,
                         common::InputEventAckSource ack_source,
                         common::InputEventAckState ack_result);

  void OnCreateNewWindow(
    const FrameHostMsg_CreateNewWindow_Params& params,
    int* new_routing_id,
    mojo::MessagePipeHandle* new_interface_provider);

  //common::mojom::RendererAudioOutputStreamFactoryPtr CreateAudioOutputStreamFactoryBinding();

  void SendCreateApplicationWindowOnIO(common::mojom::CreateNewWindowParamsPtr params);

  void CreateNetworkServiceDefaultFactory(
    network::mojom::URLLoaderFactoryRequest default_factory_request);

  void CreateNetworkServiceDefaultFactoryImpl(
    network::mojom::URLLoaderFactoryRequest default_factory_request);

  void DocumentAvailableInMainFrameImpl(bool uses_temporary_zoom_level);
  
  void SetInputTargetClientOnIO();

  void DestroyOnIO();

  // Sends
  void SendUpdateWindowScreenRect(const gfx::Rect& rect);
  void SendUpdateScreenInfo(const common::ScreenInfo& screen_info);
  void SendPausePageScheduledTasks(bool paused);
  void SendPageWasShown();
  void SendPageWasHidden();
  void SendSetPageScale(float scale);
  void SendUpdateViewportIntersection(
    const gfx::Rect& viewport_intersection,
    const gfx::Rect& compositor_visible_rect);
  void SendSetIsInert(bool inert);
  void SendUpdateRenderThrottlingStatus(bool throttling, bool subtree_throttling);
  void SendSetZoomLevel(double level);
  void SendUpdateScreenRects(const gfx::Rect& view_rect, const gfx::Rect& window_rect);
  void SendSetFocus(bool focused);
  void SendAudioStateChanged(bool is_audible);
  void SendSetTextDirection(blink::WebTextDirection text_direction);
  void SendImeSetComposition(
    const base::string16& text,
    const std::vector<ui::ImeTextSpan>& ime_text_spans,
    const gfx::Range& replacement_range,
    int selection_start,
    int selection_end);
  void SendImeCommitText(
    const base::string16& text,
    const std::vector<ui::ImeTextSpan>& ime_text_spans,
    const gfx::Range& replacement_range,
    int relative_cursor_pos);
  void SendImeFinishComposingText(bool keep_selection);
  void SendImeCancelComposition();
  void SendShowContextMenuAtPoint(
    common::mojom::MenuSourceType source_type,
    const gfx::Point& point);
  void SendRequestCompositionUpdates(
    bool immediate_request,
    bool monitor_updates);
  void SendSetEditCommandsForNextKeyEvent(const std::vector<common::EditCommand>& commands);
  void SendWasShown(const ui::LatencyInfo& latency_info, bool needs_repainting);
  void SendCursorVisibilityChanged(bool is_visible);
  void SendSynchronizeVisualProperties(common::VisualProperties properties);
  void SendWasHidden();
  void SendSetBackgroundOpaque(bool opaque);
  void SendMouseCaptureLost();
  void SendDragTargetDragOver(
    const gfx::PointF& client_pt,
    const gfx::PointF& screen_pt,
    blink::WebDragOperationsMask operations_allowed,
    int key_modifiers);
  void SendDragTargetDragLeave(
    const gfx::PointF& client_point,
    const gfx::PointF& screen_point);
  void SendDragTargetDrop(
    const common::DropData& drop_data,
    const gfx::PointF& client_pt,
    const gfx::PointF& screen_pt,
    int key_modifiers);
  void SendDragSourceEnded(
    const gfx::PointF& client_pt,
    const gfx::PointF& screen_pt,
    blink::WebDragOperation operation);
  void SendDragSourceSystemDragEnded();
  void SendMoveAck();
  void SendLockMouseAck();
  void SendUpdateTargetURLAck();
  void SendDisableScrollbarsForSmallWindows(const gfx::Size& size);
  void SendEnablePreferredSizeChangedMode();
  void SendMediaPlayerActionAt(
    const gfx::Point& location,
    const blink::WebMediaPlayerAction& action);
  void SendMoveOrResizeStarted();
  void SendMouseLockLost();
  void SendRendererPrefs(common::RendererPreferences prefs);
  void SendUpdateWebPreferences(const common::WebPreferences& prefs);
  void SendSelectWordAroundCaret();
  void SendClosePage();
  void SendSetInitialFocus(bool reverse);
  void SendClose();
  void SendCopyImageAt(int x, int y);
  void SendSaveImageAt(int x, int y);
  void SendSwapOut(int routing_id, bool is_loading);
  void SendSetFocusedWindow();
  void SendSetActive(bool active);

  void MaybeStartLoader(NavigationLoaderInterceptor* navigation_loader_interceptor, 
                        common::mojom::CommitNavigationParamsPtr params,
                        std::unique_ptr<common::URLLoaderFactoryBundleInfo> subresource_loader_factories,
                        bool is_same_document,
                        common::SingleRequestURLLoaderFactory::RequestHandler single_request_handler);
  void OnNavigationCompletion(const GURL& url, int result, NavigationEntry* entry);

  common::mojom::ApplicationWindowAssociatedPtr application_window_interface_;
  mojo::AssociatedBinding<common::mojom::ApplicationWindowHost> application_window_host_binding_;

  base::WeakPtr<ApplicationWindowHostView> view_;
  // true if a renderer has once been valid. We use this flag to display a sad
  // tab only when we lose our renderer and not if a paint occurs during
  // initialization.
  bool application_initialized_;

  // True if |Destroy()| has been called.
  bool destroyed_;

  // Our delegate, which wants to know mainly about keyboard events.
  // It will remain non-NULL until DetachDelegate() is called.
  ApplicationWindowHostDelegate* delegate_;

  // The delegate of the owner of this object.
  //ApplicationWindowHostOwnerDelegate* owner_delegate_;

  ApplicationProcessHost* process_;

  Application* application_;

  // The ID of the corresponding object in the Renderer Instance.
  const int routing_id_;

  // Track this frame's last committed URL.
  GURL last_committed_url_;

  // Track this frame's last committed origin.
  url::Origin last_committed_origin_;

  // The clock used; overridable for tests.
  const base::TickClock* clock_;

  // Indicates whether a page is loading or not.
  bool is_loading_;

  // Indicates whether a page is hidden or not. Need to call
  // process_->UpdateClientPriority when this value changes.
  bool is_hidden_;

  // For a widget that does not have an associated RenderFrame/View, assume it
  // is depth 1, ie just below the root widget.
  unsigned int frame_depth_ = 1u;

  // Set if we are waiting for a repaint ack for the view.
  bool repaint_ack_pending_;

  // True when waiting for RESIZE_ACK.
  bool resize_ack_pending_;

  // The current size of the ApplicationWindow.
  gfx::Size current_size_;

  // Visual properties that were most recently sent to the renderer.
  std::unique_ptr<common::VisualProperties> old_visual_properties_;

  // The next auto resize to send.
  gfx::Size new_auto_size_;

  // True if the render widget host should track the render widget's size as
  // opposed to visa versa.
  bool auto_resize_enabled_;

  // The minimum size for the render widget if auto-resize is enabled.
  gfx::Size min_size_for_auto_resize_;

  // The maximum size for the render widget if auto-resize is enabled.
  gfx::Size max_size_for_auto_resize_;

  base::Optional<viz::LocalSurfaceId> last_auto_resize_surface_id_;

  bool waiting_for_screen_rects_ack_;
  gfx::Rect last_view_screen_rect_;
  gfx::Rect last_window_screen_rect_;

  // Keyboard event listeners.
  std::vector<KeyPressEventCallback> key_press_event_callbacks_;

  // Mouse event callbacks.
  std::vector<MouseEventCallback> mouse_event_callbacks_;

  // Input event callbacks.
  base::ObserverList<ApplicationWindowHost::InputEventObserver>
      input_event_observers_;

  // The observers watching us.
  base::ObserverList<ApplicationWindowHostObserver> observers_;

  // If true, then we should repaint when restoring even if we have a
  // backingstore.  This flag is set to true if we receive a paint message
  // while is_hidden_ to true.  Even though we tell the render widget to hide
  // itself, a paint message could already be in flight at that point.
  bool needs_repainting_on_restore_;

  // This is true if the renderer is currently unresponsive.
  bool is_unresponsive_;

  // This value denotes the number of input events yet to be acknowledged
  // by the renderer.
  int in_flight_event_count_;

  // Flag to detect recursive calls to GetBackingStore().
  bool in_get_backing_store_;

  // Used for UMA histogram logging to measure the time for a repaint view
  // operation to finish.
  base::TimeTicks repaint_start_time_;

  // Set to true if we shouldn't send input events from the render widget.
  bool ignore_input_events_;

  // Set when we update the text direction of the selected input element.
  bool text_direction_updated_;
  blink::WebTextDirection text_direction_;

  // Set when we cancel updating the text direction.
  // This flag also ignores succeeding update requests until we call
  // NotifyTextDirection().
  bool text_direction_canceled_;

  // IPC-friendly token that represents this host for AndroidOverlays, if we
  // have created one yet.
  base::Optional<base::UnguessableToken> overlay_routing_token_;

  // Indicates if Char and KeyUp events should be suppressed or not. Usually all
  // events are sent to the renderer directly in sequence. However, if a
  // RawKeyDown event was handled by PreHandleKeyboardEvent() or
  // KeyPressListenersHandleEvent(), e.g. as an accelerator key, then the
  // RawKeyDown event is not sent to the renderer, and the following sequence of
  // Char and KeyUp events should also not be sent. Otherwise the renderer will
  // see only the Char and KeyUp events and cause unexpected behavior. For
  // example, pressing alt-2 may let the browser switch to the second tab, but
  // the Char event generated by alt-2 may also activate a HTML element if its
  // accesskey happens to be "2", then the user may get confused when switching
  // back to the original tab, because the content may already have changed.
  bool suppress_events_until_keydown_;

  bool pending_mouse_lock_request_;
  bool allow_privileged_mouse_lock_;

  // Stores the keyboard keys to lock while waiting for a pending lock request.
  base::Optional<base::flat_set<int>> keyboard_keys_to_lock_;
  bool keyboard_lock_requested_ = false;
  bool keyboard_lock_allowed_ = false;

  // Used when locking to indicate when a target application has voluntarily
  // unlocked and desires to relock the mouse. If the mouse is unlocked due
  // to ESC being pressed by the user, this will be false.
  bool is_last_unlocked_by_target_;

  // Keeps track of whether the webpage has any touch event handler. If it does,
  // then touch events are sent to the renderer. Otherwise, the touch events are
  // not sent to the renderer.
  bool has_touch_handler_;

  // TODO(wjmaclean) Remove the code for supporting resending gesture events
  // when WebView transitions to OOPIF and BrowserPlugin is removed.
  // http://crbug.com/533069
  bool is_in_gesture_scroll_[blink::kWebGestureDeviceCount] = {false};
  bool is_in_touchpad_gesture_fling_;

  std::unique_ptr<SyntheticGestureController> synthetic_gesture_controller_;

  std::unique_ptr<TouchEmulator> touch_emulator_;

  // Receives and handles all input events.
  std::unique_ptr<InputRouter> input_router_;

  std::unique_ptr<TimeoutMonitor> hang_monitor_timeout_;
  base::TimeTicks hang_monitor_start_time_;

  std::unique_ptr<TimeoutMonitor> new_content_rendering_timeout_;

  ApplicationWindowHostLatencyTracker latency_tracker_;

  int next_browser_snapshot_id_;
  using PendingSnapshotMap = std::map<int, GetSnapshotFromHostCallback>;
  PendingSnapshotMap pending_browser_snapshots_;
  PendingSnapshotMap pending_surface_browser_snapshots_;

  // Indicates whether a RenderFramehost has ownership, in which case this
  // object does not self destroy.
  bool owned_by_render_frame_host_;

  // Indicates whether this ApplicationWindowHost thinks is focused. This is trying
  // to match what the renderer process knows. It is different from
  // ApplicationWindowHostView::HasFocus in that in that the focus request may fail,
  // causing HasFocus to return false when is_focused_ is true.
  bool is_focused_;

  // Whether the view should send begin frame messages to its render widget.
  // This is state that may arrive before the view has been set and that must be
  // consistent with the state in the renderer, so this host handles it.
  bool needs_begin_frames_ = false;

  // This is used to make sure that when the fling controller sets
  // needs_begin_frames_ it doesn't get overriden by the renderer.
  bool browser_fling_needs_begin_frame_ = false;

  // This value indicates how long to wait before we consider a renderer hung.
  base::TimeDelta hung_renderer_delay_;

  // This value indicates how long to wait for a new compositor frame from a
  // renderer process before clearing any previously displayed content.
  base::TimeDelta new_content_rendering_delay_;

  // This identifier tags compositor frames according to the page load with
  // which they are associated, to prevent an unloaded web page from being
  // drawn after a navigation to a new page has already committed. This is
  // a no-op for non-top-level ApplicationWindows, as that should always be zero.
  // TODO(kenrb, fsamuel): We should use SurfaceIDs for this purpose when they
  // are available in the renderer process. See https://crbug.com/695579.
  uint32_t current_content_source_id_;

  // When true, the ApplicationWindow is regularly sending updates regarding
  // composition info. It should only be true when there is a focused editable
  // node.
  bool monitoring_composition_info_;

  // This is the content_source_id of the latest frame received. This value is
  // compared against current_content_source_id_ to determine whether the
  // received frame belongs to the current page. If a frame for the current page
  // does not arrive in time after nagivation, we clear the graphics of the old
  // page. See ApplicationWindow::current_content_source_id_ for more information.
  uint32_t last_received_content_source_id_ = 0;

  uint32_t last_latency_id_ = 0;

#if defined(OS_MACOSX)
  device::mojom::WakeLockPtr wake_lock_;
#endif

  // These information are used to verify that the renderer does not misbehave
  // when it comes to allocating LocalSurfaceIds. If surface properties change,
  // a new LocalSurfaceId must be created.
  viz::LocalSurfaceId last_local_surface_id_;
  common::ApplicationWindowSurfaceProperties last_surface_properties_;

  mojo::Binding<viz::mojom::CompositorFrameSink> compositor_frame_sink_binding_;
  viz::mojom::CompositorFrameSinkClientPtr renderer_compositor_frame_sink_;

  // Stash a request to create a CompositorFrameSink if it arrives before
  // we have a view. This is only used if |enable_viz_| is true.
  base::OnceCallback<void(const viz::FrameSinkId&)> create_frame_sink_callback_;

  viz::CompositorFrameMetadata last_frame_metadata_;

  std::unique_ptr<FrameTokenMessageQueue> frame_token_message_queue_;

  // If a CompositorFrame is submitted that references SharedBitmaps that don't
  // exist yet, we keep it here until they are available.
  struct {
    viz::LocalSurfaceId local_surface_id;
    viz::CompositorFrame frame;
    viz::mojom::HitTestRegionListPtr hit_test_region_list;
  } saved_frame_;

  bool enable_surface_synchronization_ = false;
  bool enable_viz_ = false;

  // If the |associated_widget_input_handler_| is set it should always be
  // used to ensure in order delivery of related messages that may occur
  // at the frame input level; see FrameInputHandler. Note that when the
  // RWHI wraps a WebPagePopup widget it will only have a
  // a |widget_input_handler_|.
  common::mojom::WindowInputHandlerAssociatedPtr associated_widget_input_handler_;
  common::mojom::WindowInputHandlerPtr widget_input_handler_;
  viz::mojom::InputTargetClientPtr input_target_client_;

  std::unique_ptr<common::AssociatedInterfaceRegistryImpl, HostThread::DeleteOnIOThread> associated_registry_;
  std::unique_ptr<service_manager::BinderRegistry, HostThread::DeleteOnIOThread> registry_;
  std::unique_ptr<service_manager::InterfaceProvider, HostThread::DeleteOnIOThread> remote_interfaces_;
  std::unique_ptr<common::AssociatedInterfaceProviderImpl, HostThread::DeleteOnIOThread> remote_associated_interfaces_;

  base::Optional<uint16_t> screen_orientation_angle_for_testing_;
  base::Optional<common::ScreenOrientationValues> screen_orientation_type_for_testing_;

  // The set of SharedBitmapIds that have been reported as allocated to this
  // interface. On closing this interface, the display compositor should drop
  // ownership of the bitmaps with these ids to avoid leaking them.
  std::set<viz::SharedBitmapId> owned_bitmaps_;

  bool next_resize_needs_resize_ack_ = false;

  bool force_enable_zoom_ = false;

  RenderFrameMetadataProvider render_frame_metadata_provider_;

  viz::FrameSinkId frame_sink_id_;

  bool did_receive_first_frame_after_navigation_ = true;

  // RenderFrameHost stuff

  //UniqueAudioInputStreamFactoryPtr audio_input_stream_factory_;
  //UniqueAudioOutputStreamFactoryPtr audio_output_stream_factory_;

  // We switch between |audio_service_audio_output_stream_factory_| and
  // |in_content_audio_output_stream_factory_| based on
  // features::kAudioServiceAudioStreams status.
  base::Optional<RenderFrameAudioOutputStreamFactory>
      audio_service_audio_output_stream_factory_;
  UniqueAudioOutputStreamFactoryPtr in_content_audio_output_stream_factory_;

  // We switch between |audio_service_audio_input_stream_factory_| and
  // |in_content_audio_input_stream_factory_| based on
  // features::kAudioServiceAudioStreams status.
  base::Optional<RenderFrameAudioInputStreamFactory>
      audio_service_audio_input_stream_factory_;
  UniqueAudioInputStreamFactoryPtr in_content_audio_input_stream_factory_;

  std::unique_ptr<MediaStreamDispatcherHost>
      media_stream_dispatcher_host_;

  // std::unique_ptr<MediaStreamDispatcherHost, HostThread::DeleteOnIOThread>
  //     media_stream_dispatcher_host_;

  // Hosts media::mojom::InterfaceFactory for the RenderFrame and forwards
  // media::mojom::InterfaceFactory calls to the remote "media" service.
  std::unique_ptr<MediaInterfaceProxy> media_interface_proxy_;

  // Binding for the InterfaceProvider through which this RenderFrameHostImpl
  // exposes frame-scoped Mojo services to the currently active document in the
  // corresponding RenderFrame.
  //
  // GetInterface messages dispatched through this binding are guaranteed to
  // originate from the document corresponding to the last committed navigation;
  // or the inital empty document if no real navigation has ever been committed.
  //
  // The InterfaceProvider interface connection is established as follows:
  //
  // 1) For the initial empty document, the call site that creates this
  //    RenderFrameHost is responsible for creating a message pipe, binding its
  //    request end to this instance by calling BindInterfaceProviderRequest(),
  //    and plumbing the client end to the renderer process, and ultimately
  //    supplying it to the RenderFrame synchronously at construction time.
  //
  //    The only exception to this rule are out-of-process child frames, whose
  //    RenderFrameHosts take care of this internally in CreateRenderFrame().
  //
  // 2) For subsequent documents, the RenderFrame creates a new message pipe
  //    every time a cross-document navigation is committed, and pushes its
  //    request end to the browser process as part of DidCommitProvisionalLoad.
  //    The client end will be used by the new document corresponding to the
  //    committed naviagation to access services exposed by the RenderFrameHost.
  //
  // This is required to prevent GetInterface messages racing with navigation
  // commit from being serviced in the security context corresponding to the
  // wrong document in the RenderFrame. The benefit of the approach taken is
  // that it does not necessitate using channel-associated InterfaceProvider
  // interfaces.
  mojo::Binding<service_manager::mojom::InterfaceProvider>
      document_scoped_interface_provider_binding_;

  // Boolean indicating whether this RenderFrameHost is being actively used or
  // is waiting for FrameHostMsg_SwapOut_ACK and thus pending deletion.
  bool is_waiting_for_swapout_ack_;

  // If true, then the RenderFrame has selected text.
  bool has_selection_;

  // If true, then this RenderFrame has one or more audio streams with audible
  // signal. If false, all audio streams are currently silent (or there are no
  // audio streams).
  bool is_audible_;

  bool is_swapped_out_;

  bool is_active_;

  bool updating_web_preferences_;

  bool sudden_termination_allowed_;

  base::TerminationStatus app_window_termination_status_;

  bool is_waiting_for_close_ack_;

  bool has_notified_about_creation_;

  bool application_window_created_;

  // A bitwise OR of bindings types that have been enabled for this RenderFrame.
  // See BindingsPolicy for details.
  int enabled_bindings_ = 0;

  // Used for tracking the latest size of the RenderFrame.
  base::Optional<gfx::Size> frame_size_;

  // When the last BeforeUnload message was sent.
  base::TimeTicks send_before_unload_start_time_;

  // Set to true when there is a pending FrameMsg_BeforeUnload message.  This
  // ensures we don't spam the renderer with multiple beforeunload requests.
  // When either this value or IsWaitingForUnloadACK is true, the value of
  // unload_ack_is_for_cross_site_transition_ indicates whether this is for a
  // cross-site transition or a tab close attempt.
  // TODO(clamy): Remove this boolean and add one more state to the state
  // machine.
  bool is_waiting_for_beforeunload_ack_;

  // Valid only when is_waiting_for_beforeunload_ack_ or
  // IsWaitingForUnloadACK is true.  This tells us if the unload request
  // is for closing the entire tab ( = false), or only this RenderFrameHost in
  // the case of a navigation ( = true).
  bool unload_ack_is_for_navigation_;

  bool visual_properties_ack_pending_;

  bool is_first_was_shown_;

  // Overall load progress.
  double load_progress_;

  // The timeout monitor that runs from when the beforeunload is started in
  // DispatchBeforeUnload() until either the render process ACKs it with an IPC
  // to OnBeforeUnloadACK(), or until the timeout triggers.
  std::unique_ptr<TimeoutMonitor> beforeunload_timeout_;
  // Used to swap out or shut down this RFH when the unload event is taking too
  // long to execute, depending on the number of active frames in the
  // SiteInstance.  May be null in tests.
  std::unique_ptr<TimeoutMonitor> swapout_event_monitor_timeout_;

  std::unique_ptr<TimeoutMonitor> close_timeout_;

  std::unique_ptr<common::WebPreferences> web_preferences_;

  // This monitors input changes so they can be reflected to the interaction MQ.
  std::unique_ptr<InputDeviceChangeObserver> input_device_change_observer_;
 
  std::unique_ptr<resource_coordinator::FrameResourceCoordinator> frame_resource_coordinator_;

  std::map<uint64_t, VisualStateCallback> visual_state_callbacks_;

  std::unique_ptr<ApplicationFrame> application_frame_;//render_frame_host_;

  std::unordered_map<int32_t, std::unique_ptr<ApplicationFrame>> frames_;
  std::unordered_map<int32_t, std::unique_ptr<ApplicationFrame>> proxy_frames_;

  std::list<std::unique_ptr<ApplicationFrame>> pending_delete_frames_;

  //std::unique_ptr<ServiceWorkerNavigationHandle> service_worker_handle_;

  // Stores a speculative RenderFrameHost which is created early in a navigation
  // so a renderer process can be started in parallel, if needed.
  // This is purely a performance optimization and is not required for correct
  // behavior. The speculative RenderFrameHost might be discarded later on if
  // the final URL's SiteInstance isn't compatible with the one used to create
  // it.
  std::unique_ptr<ApplicationFrame> speculative_application_frame_;
  
  base::WeakPtrFactory<ApplicationWindowHost> weak_factory_;
  base::WeakPtrFactory<ApplicationWindowHost> io_weak_factory_;
  base::WeakPtr<ApplicationWindowHost> weak_this_;
  base::WeakPtr<ApplicationWindowHost> io_weak_this_;


  DISALLOW_COPY_AND_ASSIGN(ApplicationWindowHost);
};

}


#endif
