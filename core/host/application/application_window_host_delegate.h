// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_APPLICATION_WINDOW_HOST_DELEGATE_H_
#define MUMBA_HOST_APPLICATION_APPLICATION_WINDOW_HOST_DELEGATE_H_

#include <stdint.h>

#include <string>
#include <vector>

#include "build/build_config.h"
#include "base/process/kill.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/drag_event_source_info.h"
#include "core/shared/common/drop_data.h"
#include "core/shared/common/renderer_preferences.h"
#include "core/shared/common/media_stream_request.h"
#include "core/shared/common/mojom/application.mojom.h"
#include "core/host/application/application_frame.h"
#include "core/host/application/visibility.h"
#include "core/host/application/render_frame_metadata_provider.h"
#include "mojo/public/cpp/bindings/scoped_interface_endpoint_handle.h"
#include "net/cert/cert_status_flags.h"
#include "net/http/http_response_headers.h"
#include "services/device/public/mojom/geolocation_context.mojom.h"
#include "services/device/public/mojom/wake_lock.mojom.h"
#include "third_party/blink/public/web/web_popup_type.h"
#include "third_party/blink/public/platform/web_display_mode.h"
#include "third_party/blink/public/platform/web_drag_operation.h"
#include "third_party/blink/public/platform/web_input_event.h"
#include "ui/gfx/native_widget_types.h"

namespace blink {
class WebMouseWheelEvent;
class WebGestureEvent;
}

namespace gfx {
class Point;
class Size;
}

//namespace rappor {
//class Sample;
//}

//namespace ukm {
//class UkmRecorder;
//}

namespace viz {
class SurfaceId;
class LocalSurfaceId;
}

namespace common {
struct ScreenInfo;  
}

namespace host {
class BrowserAccessibilityManager;
class Domain;
class Application;
class RouteController;
class NavigationController;
class ApplicationWindowHost;
class ApplicationWindowHostInputEventRouter;
class ApplicationWindowHostDelegateView;
class TextInputManager;
class ApplicationContents;
enum class KeyboardEventProcessingResult;
struct NativeWebKeyboardEvent;

//
// ApplicationWindowHostDelegate = RenderViewHostDelegate + RenderWidgetHostDelegate
//
//  An interface implemented by an object interested in knowing about the state
//  of the ApplicationWindowHost.
class CONTENT_EXPORT ApplicationWindowHostDelegate : public RenderFrameMetadataProvider::Observer {
 public:
  // Allows the delegate to filter incoming associated inteface requests.
  virtual void OnAssociatedInterfaceRequest(
      ApplicationWindowHost* app_window_host,
      const std::string& interface_name,
      mojo::ScopedInterfaceEndpointHandle handle) {}

  // Allows the delegate to filter incoming interface requests.
  virtual void OnInterfaceRequest(
      ApplicationWindowHost* app_window_host,
      const std::string& interface_name,
      mojo::ScopedMessagePipeHandle* interface_pipe) {}

  // The ApplicationWindowHost has just been created.
  virtual void ApplicationWindowCreated(ApplicationWindowHost* application_window_host) {}

  // The ApplicationWindowHost is going to be deleted.
  virtual void ApplicationWindowDeleted(ApplicationWindowHost* application_window_host) {}

  // The ApplicationWindowHost got the focus.
  virtual void ApplicationWindowGotFocus(ApplicationWindowHost* application_window_host) {}

  // The ApplicationWindowHost lost the focus.
  virtual void ApplicationWindowLostFocus(
      ApplicationWindowHost* application_window_host) {}

  // The ApplicationWindow was resized.
  virtual void ApplicationWindowWasResized(ApplicationWindowHost* application_window_host,
                                      const common::ScreenInfo& screen_info,
                                      bool width_changed) {}

  // The contents auto-resized and the container should match it.
  virtual void ResizeDueToAutoResize(
      ApplicationWindowHost* application_window_host,
      const gfx::Size& new_size,
      const viz::LocalSurfaceId& local_surface_id) {}

  // Callback to give the browser a chance to handle the specified keyboard
  // event before sending it to the renderer. See enum for details on return
  // value.
  virtual KeyboardEventProcessingResult PreHandleKeyboardEvent(
      const NativeWebKeyboardEvent& event);

  // Callback to inform the browser that the renderer did not process the
  // specified events. This gives an opportunity to the browser to process the
  // event (used for keyboard shortcuts).
  virtual void HandleKeyboardEvent(const NativeWebKeyboardEvent& event) {}

  // Callback to inform the browser that the renderer did not process the
  // specified mouse wheel event.  Returns true if the browser has handled
  // the event itself.
  virtual bool HandleWheelEvent(const blink::WebMouseWheelEvent& event);

  // Notification that an input event from the user was dispatched to the
  // widget.
  virtual void DidReceiveInputEvent(ApplicationWindowHost* application_window_host,
                                    const blink::WebInputEvent::Type type) {}

  // Callback to give the browser a chance to handle the specified gesture
  // event before sending it to the renderer.
  // Returns true if the |event| was handled.
  virtual bool PreHandleGestureEvent(const blink::WebGestureEvent& event);

  // Notifies that screen rects were sent to renderer process.
  virtual void DidSendScreenRects(ApplicationWindowHost* rwh) {}

  // Get the root BrowserAccessibilityManager for this frame tree.
  virtual BrowserAccessibilityManager* GetRootAccessibilityManager();

  // Get the root BrowserAccessibilityManager for this frame tree,
  // or create it if it doesn't exist.
  virtual BrowserAccessibilityManager*
      GetOrCreateRootAccessibilityManager();

  // Send OS Cut/Copy/Paste actions to the focused frame.
  virtual void ExecuteEditCommand(
      const std::string& command,
      const base::Optional<base::string16>& value) = 0;
  virtual void Cut() = 0;
  virtual void Copy() = 0;
  virtual void Paste() = 0;
  virtual void SelectAll() = 0;

  // Requests the renderer to move the selection extent to a new position.
  virtual void MoveRangeSelectionExtent(const gfx::Point& extent) {}

  // Requests the renderer to select the region between two points in the
  // currently focused frame.
  virtual void SelectRange(const gfx::Point& base, const gfx::Point& extent) {}

  // Request the renderer to Move the caret to the new position.
  virtual void MoveCaret(const gfx::Point& extent) {}

  virtual ApplicationWindowHostInputEventRouter* GetInputEventRouter();

  // Send page-level focus state to all SiteInstances involved in rendering the
  // current FrameTree, not including the main frame's SiteInstance.
  virtual void ReplicatePageFocus(bool is_focused) {}

  // Get the focused ApplicationWindowHost associated with |receiving_widget|. A
  // ApplicationWindowHostView, upon receiving a keyboard event, will pass its
  // ApplicationWindowHost to this function to determine who should ultimately
  // consume the event.  This facilitates keyboard event routing with
  // out-of-process iframes, where multiple ApplicationWindowHosts may be involved
  // in rendering a page, yet keyboard events all arrive at the main frame's
  // ApplicationWindowHostView.  When a main frame's ApplicationWindowHost is passed in,
  // the function returns the focused frame that should consume keyboard
  // events. In all other cases, the function returns back |receiving_widget|.
  virtual ApplicationWindowHost* GetFocusedApplicationWindowHost(
      ApplicationWindowHost* receiving_widget);

  // Notification that the renderer has become unresponsive. The
  // delegate can use this notification to show a warning to the user.
  virtual void ApplicationUnresponsive(ApplicationWindowHost* application_window_host) {}

  // Notification that a previously unresponsive renderer has become
  // responsive again. The delegate can use this notification to end the
  // warning shown to the user.
  virtual void ApplicationResponsive(ApplicationWindowHost* application_window_host) {}

  // Requests to lock the mouse. Once the request is approved or rejected,
  // GotResponseToLockMouseRequest() will be called on the requesting render
  // widget host. |privileged| means that the request is always granted, used
  // for Pepper Flash.
  virtual void RequestToLockMouse(ApplicationWindowHost* application_window_host,
                                  bool user_gesture,
                                  bool last_unlocked_by_target,
                                  bool privileged) {}

  // Returns whether the associated tab is in fullscreen mode.
  virtual bool IsFullscreen() const;

  // Returns the display mode for the view.
  virtual blink::WebDisplayMode GetDisplayMode(
      ApplicationWindowHost* application_window_host) const;

  // Notification that the widget has lost capture.
  virtual void LostCapture(ApplicationWindowHost* application_window_host) {}

  // Notification that the widget has lost the mouse lock.
  virtual void LostMouseLock(ApplicationWindowHost* application_window_host) {}

  // Returns true if |application_window_host| holds the mouse lock.
  virtual bool HasMouseLock(ApplicationWindowHost* application_window_host);

  // Returns the widget that holds the mouse lock or nullptr if the mouse isn't
  // locked.
  virtual ApplicationWindowHost* GetMouseLockWidget();

  // Requests to lock the keyboard. Once the request is approved or rejected,
  // GotResponseToKeyboardLockRequest() will be called on the requesting render
  // widget host.
  virtual bool RequestKeyboardLock(ApplicationWindowHost* application_window_host,
                                   bool esc_key_locked);

  // Cancels a previous keyboard lock request.
  virtual void CancelKeyboardLock(ApplicationWindowHost* application_window_host) {}

  // Returns the widget that holds the keyboard lock or nullptr if not locked.
  virtual ApplicationWindowHost* GetKeyboardLockWidget();

  // Called when the visibility of the RenderFrameProxyHost in outer
  // ApplicationContents changes. This method is only called on an inner ApplicationContents and
  // will eventually notify all the ApplicationWindowHostViews belonging to that
  // ApplicationContents.
  virtual void OnRenderFrameProxyVisibilityChanged(bool visible) {}

  // Update the renderer's cache of the screen rect of the view and window.
  virtual void SendScreenRects() {}

  // Returns the TextInputManager tracking text input state.
  virtual TextInputManager* GetTextInputManager();

  virtual RouteController* GetRouteController();
  virtual NavigationController* GetNavigationController();

  // Returns true if this ApplicationWindowHost should remain hidden. This is used by
  // the ApplicationWindowHost to ask the delegate if it can be shown in the event of
  // something other than the ApplicationContents attempting to enable visibility of
  // this ApplicationWindowHost.
  virtual bool IsHidden();

  // Returns the associated RenderViewHostDelegateView*, if possible.
  virtual ApplicationWindowHostDelegateView* GetDelegateView();

  // Returns the current Flash fullscreen ApplicationWindowHost if any. This is
  // not intended for use with other types of fullscreen, such as HTML
  // fullscreen, and will return nullptr for those cases.
  virtual ApplicationWindowHost* GetFullscreenApplicationWindowHost() const;

  // Allow the delegate to handle the cursor update. Returns true if handled.
  virtual bool OnUpdateDragCursor();

  // Notification that the frame wants to go into fullscreen mode.
  // |origin| represents the origin of the frame that requests fullscreen.
  virtual void EnterFullscreenMode() {}

  // Notification that the frame wants to go out of fullscreen mode.
  // |will_cause_resize| indicates whether the fullscreen change causes a
  // view resize. e.g. This will be false when going from tab fullscreen to
  // browser fullscreen.
  virtual void ExitFullscreenMode(bool will_cause_resize) {}

  // Returns true if the provided ApplicationWindowHost matches the current
  // ApplicationWindowHost on the main frame, and false otherwise.
  //virtual bool IsWindowForMainFrame(ApplicationWindowHost*);

  // Inner ApplicationContents Helpers -------------------------------------------------
  //
  // These functions are helpers in managing a hierharchy of ApplicationContents
  // involved in rendering inner ApplicationContents.

  // Get the ApplicationWindowHost that should receive page level focus events. This
  // will be the widget that is rendering the main frame of the currently
  // focused ApplicationContents.
  virtual ApplicationWindowHost* GetApplicationWindowHostWithPageFocus();

  // In cases with multiple ApplicationWindowHosts involved in rendering a page, only
  // one widget should be focused and active. This ensures that
  // |application_window_host| is focused and that its owning ApplicationContents is also
  // the focused ApplicationContents.
  virtual void FocusOwningApplicationContents(
      ApplicationWindowHost* application_window_host) {}

  // Augment a Rappor sample with eTLD+1 context. The caller is still
  // responsible for logging the sample to the RapporService. Returns false
  // if the eTLD+1 is not known for |application_window_host|.
  //virtual bool AddDomainInfoToRapporSample(rappor::Sample* sample);

  // Update UkmRecorder for the given source with the URL. This is used for
  // URL-keyed metrics to set the url for a report.
  //virtual void UpdateUrlForUkmSource(ukm::UkmRecorder* service,
  //                                   ukm::SourceId ukm_source_id);
  //
  // Notifies the delegate that a focused editable element has been touched
  // inside this ApplicationWindowHost. If |editable| is true then the focused
  // element accepts text input.
  virtual void FocusedNodeTouched(bool editable) {}

  virtual const GURL& GetURL() const = 0;

  // Return this object cast to a ApplicationContents, if it is one. If the object is
  // not a ApplicationContents, returns nullptr.
  virtual ApplicationContents* GetAsApplicationContents();

  // Notifies that a CompositorFrame was received from the renderer.
  virtual void DidReceiveCompositorFrame() {}

  // The frame changed its window.name property.
  virtual void DidChangeName(ApplicationWindowHost* application_window_host,
                             const std::string& name) {}

  // Updates the Picture-in-Picture controller with the relevant viz::SurfaceId
  // of the video to be in Picture-in-Picture mode.
  virtual void UpdatePictureInPictureSurfaceId(const viz::SurfaceId& surface_id,
                                               const gfx::Size& natural_size) {}

  // Updates the Picture-in-Picture controller with a signal that
  // Picture-in-Picture mode has ended.
  virtual void ExitPictureInPicture() {}

  // Gets the size set by a top-level frame with auto-resize enabled.
  virtual gfx::Size GetAutoResizeSize();

  // Reset the auto-size value, to indicate that auto-size is no longer active.
  virtual void ResetAutoResizeSize() {}

  // Returns true if there is context menu shown on page.
  virtual bool IsShowingContextMenuOnPage() const;



/*
 *
 * RenderViewHostDelegate
 *
 */
  
  // This is used to give the delegate a chance to filter IPC messages.
  virtual bool OnMessageReceived(ApplicationWindowHost* application_window_host,
                                 const IPC::Message& message);

  // The RenderView has been constructed.
  virtual void ApplicationWindowReady(ApplicationWindowHost* app_window_host) {}

  // The process containing the RenderView exited somehow (either cleanly,
  // crash, or user kill).
  virtual void ApplicationWindowTerminated(ApplicationWindowHost* app_window_host,
                                           base::TerminationStatus status,
                                           int error_code) {}

  // The destination URL has changed should be updated.
  virtual void UpdateTargetURL(ApplicationWindowHost* app_window_host,
                               const GURL& url) {}

  // The page is trying to close the RenderView's representation in the client.
  virtual void Close(ApplicationWindowHost* app_window_host) {}

  // The page is trying to move the RenderView's representation in the client.
  virtual void RequestMove(const gfx::Rect& new_bounds) {}

  // The RenderView's main frame document element is ready. This happens when
  // the document has finished parsing.
  virtual void DocumentAvailableInMainFrame(ApplicationWindowHost* app_window_host) {}

  // The page wants to close the active view in this tab.
  virtual void RouteCloseEvent(ApplicationWindowHost* rvh) {}

  // Return a dummy RendererPreferences object that will be used by the renderer
  // associated with the owning RenderViewHost.
  virtual common::RendererPreferences GetRendererPrefs() const = 0;

  // Notification from the renderer host that blocked UI event occurred.
  // This happens when there are tab-modal dialogs. In this case, the
  // notification is needed to let us draw attention to the dialog (i.e.
  // refocus on the modal dialog, flash title etc).
  virtual void OnIgnoredUIEvent() {}

  // The page wants the hosting window to activate itself (it called the
  // JavaScript window.focus() method).
  virtual void Activate() {}

  virtual Domain* GetDomain() const { return nullptr; }

  virtual Application* GetApplication() const { return nullptr; }

  // The contents' preferred size changed.
  virtual void UpdatePreferredSize(const gfx::Size& pref_size) {}

  // The page is trying to open a new widget (e.g. a select popup). The
  // widget should be created associated with the given |route_id| in the
  // process |render_process_id|, but it should not be shown yet. That should
  // happen in response to ShowCreatedWidget.
  // |popup_type| indicates if the widget is a popup and what kind of popup it
  // is (select, autofill...).
  virtual void CreateNewWindow(int32_t render_process_id,
                               int32_t route_id,
                               //mojom::WidgetPtr widget,
                               blink::WebPopupType popup_type) {}

  virtual void CreateNewWindow(
      ApplicationWindowHost* opener,
      Domain* parent,
      Application* application,
      int32_t application_window_route_id,
      bool initially_hidden,
      bool application_initiated,  
      const common::mojom::CreateNewWindowParams& params) {}

  // Creates a full screen RenderWidget. Similar to above.
  virtual void CreateNewFullscreenWindow(int32_t render_process_id,
                                         int32_t route_id) {}//,
                                         //mojom::WidgetPtr widget) {}

  // Show the newly created widget with the specified bounds.
  // The widget is identified by the route_id passed to CreateNewWidget.
  virtual void ShowCreatedWindow(int process_id,
                                 int route_id,
                                 const gfx::Rect& initial_rect) {}

  virtual void ShowCreatedWindow(Application* application,
                                 int process_id,
                                 int main_frame_widget_route_id,
                                 WindowOpenDisposition disposition,
                                 const gfx::Rect& initial_rect,
                                 bool user_gesture) {}

  // Show the newly created full screen widget. Similar to above.
  virtual void ShowCreatedFullscreenWindow(int process_id, int route_id) {}

  // Returns the zoom level for the pending navigation for the page. If there
  // is no pending navigation, this returns the zoom level for the current
  // page.
  virtual double GetPendingPageZoomLevel();

  // Returns true if the RenderViewHost will never be visible.
  virtual bool IsNeverVisible();

  // Returns the FrameTree the render view should use. Guaranteed to be constant
  // for the lifetime of the render view.
  //
  // TODO(ajwong): Remove once the main frame RenderFrameHost is no longer
  // created by the RenderViewHost.
  //virtual FrameTree* GetFrameTree();

  // Whether the user agent is overridden using the Chrome for Android "Request
  // Desktop Site" feature.
  //virtual bool IsOverridingUserAgent();

  //virtual bool IsJavaScriptDialogShowing() const;

  // If a timer for an unresponsive renderer fires, whether it should be
  // ignored.
  virtual bool ShouldIgnoreUnresponsiveApplication();

  // Whether the ApplicationContents as a persistent video.
  virtual bool HasPersistentVideo() const;

  virtual std::string GetDefaultMediaDeviceID(common::MediaStreamType media_stream_type);

  // Returns the RenderFrameHost for a pending or speculative main frame
  // navigation for the page.  Returns nullptr if there is no such navigation.
  //virtual RenderFrameHost* GetPendingMainFrame();

  /*
   *
   * End of RenderViewHostDelegate
   *
   */

  virtual bool CanOverscrollContent() const;
  virtual void UpdateTitle(
    ApplicationWindowHost* application_window_host,
    const base::string16& title, 
    base::i18n::TextDirection title_direction);

  virtual void CancelModalDialogs();
  virtual void DidChangeLoadProgress();
  virtual void DidStopLoading();
  virtual void DidCallFocus();
  virtual void DidCancelLoading();
  virtual void DidStartLoading(bool is_main_frame, bool to_different_document);
  virtual void DidFailLoadWithError(const GURL& url, int32_t error_code, const base::string16& error_description);
  virtual void UpdateStateForFrame(ApplicationFrame* application_frame, const common::mojom::PageState& page_state);
  virtual void UpdateApplicationWindowSize(bool is_main_frame);
  virtual void DidAccessInitialDocument();
  virtual void DocumentOnLoadCompleted(ApplicationFrame* application_frame);
  virtual void DidNavigateMainFramePreCommit(bool navigation_is_within_page);
  virtual void DidNavigateMainFramePostCommit(ApplicationFrame* application_window_host, const common::mojom::DidCommitProvisionalLoadParams& params);
  virtual void DidNavigateAnyFramePostCommit(ApplicationFrame* application_window_host, const common::mojom::DidCommitProvisionalLoadParams& params);
  virtual void NotifySwapped(ApplicationFrame* old_host,
                             ApplicationFrame* new_host,
                             bool is_main_frame);
  virtual void NotifyMainFrameSwapped(
    ApplicationFrame* old_host,
    ApplicationFrame* new_host);
  virtual void NotifyFrameSwapped(
    ApplicationFrame* old_frame,
    ApplicationFrame* new_frame);
  
  virtual ApplicationContents* OpenURL(const GURL& url);

  virtual Visibility GetVisibility() const;
  virtual void OnCloseAckReceived(ApplicationWindowHost* application_window_host);

  // RenderFrameMetadataProviderObserver
  virtual void OnRenderFrameMetadataChanged() override {}
  virtual void OnRenderFrameSubmission() override {}

 protected:
  virtual ~ApplicationWindowHostDelegate() {}
};

}  // namespace host

#endif  // MUMBA_HOST_APPLICATION_RENDER_WIDGET_HOST_DELEGATE_H_
