// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_APPLICATION_CONTENTS_DELEGATE_H_
#define MUMBA_HOST_APPLICATION_APPLICATION_CONTENTS_DELEGATE_H_

#include <stdint.h>

#include <memory>
#include <set>
#include <string>
#include <vector>

#include "base/callback.h"
#include "base/strings/string16.h"
#include "build/build_config.h"
#include "core/shared/common/content_export.h"
//#include "core/host/application/bluetooth_chooser.h"
#include "core/host/application/invalidate_type.h"
#include "core/shared/common/media_stream_request.h"
//#include "core/common/previews_state.h"
#include "core/shared/common/window_container_type.mojom.h"
#include "third_party/blink/public/mojom/color_chooser/color_chooser.mojom.h"
#include "third_party/blink/public/platform/web_display_mode.h"
#include "third_party/blink/public/platform/web_drag_operation.h"
#include "third_party/blink/public/platform/web_security_style.h"
#include "third_party/skia/include/core/SkColor.h"
#include "ui/base/window_open_disposition.h"
#include "ui/gfx/geometry/rect_f.h"
#include "ui/gfx/native_widget_types.h"

#if defined(OS_ANDROID)
#include "base/android/scoped_java_ref.h"
#endif

class GURL;

namespace base {
class FilePath;
}

namespace gfx {
class Rect;
class Size;
}

namespace url {
class Origin;
}

namespace viz {
class SurfaceId;
}  // namespace viz

namespace blink {
class WebGestureEvent;
}

namespace common {
struct ContextMenuParams;
struct DropData;  
}

namespace host {
class ApplicationProcessHost;
class ApplicationWindowHost;
class ApplicationContents;
struct NativeWebKeyboardEvent;
struct OpenURLParams;

enum class KeyboardEventProcessingResult;

// Objects implement this interface to get notified about changes in the
// ApplicationContents and to provide necessary functionality.
class CONTENT_EXPORT ApplicationContentsDelegate {
 public:
  ApplicationContentsDelegate();

  // Opens a new URL inside the passed in ApplicationContents (if source is 0 open
  // in the current front-most tab), unless |disposition| indicates the url
  // should be opened in a new tab or window.
  //
  // A nullptr source indicates the current tab (callers should probably use
  // OpenURL() for these cases which does it for you).

  // Returns the ApplicationContents the URL is opened in, or nullptr if the URL wasn't
  // opened immediately.
  virtual ApplicationContents* OpenURL(
    ApplicationContents* source,
    const OpenURLParams& params);

  // Allows the delegate to optionally cancel navigations that attempt to
  // transfer to a different process between the start of the network load and
  // commit.  Defaults to true.
  virtual bool ShouldTransferNavigation(bool is_main_frame_navigation);

  // Called to inform the delegate that the ApplicationContents's navigation state
  // changed. The |changed_flags| indicates the parts of the navigation state
  // that have been updated.
  virtual void NavigationStateChanged(ApplicationContents* source,
                                      InvalidateTypes changed_flags) {}

  // Called to inform the delegate that the WebContent's visible
  // security state changed and that security UI should be updated.
  virtual void VisibleSecurityStateChanged(ApplicationContents* source) {}

  // Creates a new tab with the already-created ApplicationContents 'new_contents'.
  // The window for the added contents should be reparented correctly when this
  // method returns.  If |disposition| is NEW_POPUP, |initial_rect| should hold
  // the initial position and size. If |was_blocked| is non-nullptr, then
  // |*was_blocked| will be set to true if the popup gets blocked, and left
  // unchanged otherwise.
  virtual void AddNewContents(const std::string& app_name,
                              ApplicationContents* source,
                              ApplicationContents* new_contents,
                              WindowOpenDisposition disposition,
                              const gfx::Rect& initial_rect,
                              bool user_gesture,
                              bool* was_blocked) {}

  // Selects the specified contents, bringing its container to the front.
  virtual void ActivateContents(ApplicationContents* contents) {}

  // Notifies the delegate that this contents is starting or is done loading
  // some resource. The delegate should use this notification to represent
  // loading feedback. See ApplicationContents::IsLoading()
  // |to_different_document| will be true unless the load is a fragment
  // navigation, or triggered by history.pushState/replaceState.
  virtual void LoadingStateChanged(ApplicationContents* source,
                                   bool to_different_document) {}

  // Notifies the delegate that the page has made some progress loading.
  // |progress| is a value between 0.0 (nothing loaded) to 1.0 (page fully
  // loaded).
  virtual void LoadProgressChanged(ApplicationContents* source,
                                   double progress) {}

  // Request the delegate to close this web contents, and do whatever cleanup
  // it needs to do.
  virtual void CloseContents(ApplicationContents* source) {}

  // Request the delegate to move this ApplicationContents to the specified position
  // in screen coordinates.
  virtual void MoveContents(ApplicationContents* source, const gfx::Rect& pos) {}

  // Called to determine if the ApplicationContents is contained in a popup window
  // or a panel window.
  virtual bool IsPopupOrPanel(const ApplicationContents* source) const;

  // Notification that the target URL has changed.
  virtual void UpdateTargetURL(ApplicationContents* source,
                               const GURL& url) {}

  // Notification that there was a mouse event, along with the type of event.
  // If |motion| is true, this is a normal motion event. If |exited| is true,
  // the pointer left the contents area.
  virtual void ContentsMouseEvent(ApplicationContents* source,
                                  bool motion,
                                  bool exited) {}

  // Request the delegate to change the zoom level of the current tab.
  virtual void ContentsZoomChange(bool zoom_in) {}

  // Called to determine if the ApplicationContents can be overscrolled with touch/wheel
  // gestures.
  virtual bool CanOverscrollContent() const;

  // Invoked prior to showing before unload handler confirmation dialog.
  virtual void WillRunBeforeUnloadConfirm() {}

  // Returns true if javascript dialogs and unload alerts are suppressed.
  // Default is false.
  virtual bool ShouldSuppressDialogs(ApplicationContents* source);

  // Returns whether pending NavigationEntries for aborted browser-initiated
  // navigations should be preserved (and thus returned from GetVisibleURL).
  // Defaults to false.
  virtual bool ShouldPreserveAbortedURLs(ApplicationContents* source);

  // A message was added to the console of a frame of the page. Returning true
  // indicates that the delegate handled the message. If false is returned the
  // default logging mechanism will be used for the message.
  virtual bool DidAddMessageToConsole(ApplicationContents* source,
                                      int32_t level,
                                      const base::string16& message,
                                      int32_t line_no,
                                      const base::string16& source_id);

  // Tells us that we've finished firing this tab's beforeunload event.
  // The proceed bool tells us whether the user chose to proceed closing the
  // tab. Returns true if the tab can continue on firing its unload event.
  // If we're closing the entire browser, then we'll want to delay firing
  // unload events until all the beforeunload events have fired.
  virtual void BeforeUnloadFired(ApplicationContents* tab,
                                 bool proceed,
                                 bool* proceed_to_fire_unload);

  // Returns true if the location bar should be focused by default rather than
  // the page contents. NOTE: this is only used if ApplicationContents can't determine
  // for itself whether the location bar should be focused by default. For a
  // complete check, you should use ApplicationContents::FocusLocationBarByDefault().
  virtual bool ShouldFocusLocationBarByDefault(ApplicationContents* source);

  // Sets focus to the location bar or some other portal that is appropriate.
  // This is called when the tab wants to encourage user input, like for the
  // new tab page.
  virtual void SetFocusToLocationBar(bool select_all) {}

  // Returns whether the page should be focused when transitioning from crashed
  // to live. Default is true.
  virtual bool ShouldFocusPageAfterCrash();

  // Returns whether the page should resume accepting requests for the new
  // window. This is used when window creation is asynchronous
  // and the navigations need to be delayed. Default is true.
  virtual bool ShouldResumeRequestsForCreatedWindow();

  // This is called when WebKit tells us that it is done tabbing through
  // controls on the page. Provides a way for ApplicationContentsDelegates to handle
  // this. Returns true if the delegate successfully handled it.
  virtual bool TakeFocus(ApplicationContents* source,
                         bool reverse);

  // Invoked when the page loses mouse capture.
  virtual void LostCapture() {}

  // Asks the delegate if the given tab can download.
  // Invoking the |callback| synchronously is OK.
  virtual void CanDownload(const GURL& url,
                           const std::string& request_method,
                           const base::Callback<void(bool)>& callback);

  // Returns true if the context menu operation was handled by the delegate.
  virtual bool HandleContextMenu(const common::ContextMenuParams& params);

  // Allows delegates to handle keyboard events before sending to the renderer.
  // See enum for description of return values.
  virtual KeyboardEventProcessingResult PreHandleKeyboardEvent(
      ApplicationContents* source,
      const NativeWebKeyboardEvent& event);

  // Allows delegates to handle unhandled keyboard messages coming back from
  // the renderer.
  virtual void HandleKeyboardEvent(ApplicationContents* source,
                                   const NativeWebKeyboardEvent& event) {}

  // Allows delegates to handle gesture events before sending to the renderer.
  // Returns true if the |event| was handled and thus shouldn't be processed
  // by the renderer's event handler. Note that the touch events that create
  // the gesture are always passed to the renderer since the gesture is created
  // and dispatched after the touches return without being "preventDefault()"ed.
  virtual bool PreHandleGestureEvent(
      ApplicationContents* source,
      const blink::WebGestureEvent& event);

  // Called when an external drag event enters the web contents window. Return
  // true to allow dragging and dropping on the web contents window or false to
  // cancel the operation. This method is used by Chromium Embedded Framework.
  virtual bool CanDragEnter(ApplicationContents* source,
                            const common::DropData& data,
                            blink::WebDragOperationsMask operations_allowed);

  // Shows the repost form confirmation dialog box.
  virtual void ShowRepostFormWarningDialog(ApplicationContents* source) {}

  // Allows delegate to override navigation to the history entries.
  // Returns true to allow ApplicationContents to continue with the default processing.
  virtual bool OnGoToEntryOffset(int offset);

  // Allows delegate to control whether a new ApplicationContents can be created by
  // |application_contents|.
  //
  // The route ID parameters passed to this method are associated with the
  // |source_site_instance|'s RenderProcessHost. They may also be
  // MSG_ROUTING_NONE. If they are valid, they correspond to a trio of
  // RenderView, RenderFrame, and RenderWidget objects that have been created in
  // the renderer, but not yet assigned a ApplicationContents, RenderViewHost,
  // RenderFrameHost, or ApplicationWindowHost.
  //
  // The return value is interpreted as follows:
  //
  //   Return true: |application_contents| should create a ApplicationContents.
  //   Return false: |application_contents| should not create a ApplicationContents. The
  //       provisionally-created RenderView (if it exists) in the renderer
  //       process will be destroyed, UNLESS the delegate, during this method,
  //       itself creates a ApplicationContents using |source_site_instance|,
  //       |route_id|, |main_frame_route_id|, and |main_frame_widget_route_id|
  //       as creation parameters. If this happens, the delegate assumes
  //       ownership of the corresponding RenderView, etc. |application_contents| will
  //       detect that this has happened by looking for the existence of a
  //       RenderViewHost in |source_site_instance| with |route_id|.
  virtual bool ShouldCreateApplicationContents(
      ApplicationContents* application_contents,
      ApplicationWindowHost* opener,
      //SiteInstance* source_site_instance,
      int32_t route_id,
      int32_t main_frame_route_id,
      int32_t main_frame_widget_route_id,
      common::mojom::WindowContainerType window_container_type,
      const GURL& opener_url,
      const std::string& frame_name,
      const GURL& target_url);//,
      //const std::string& partition_id,
      //SessionStorageNamespace* session_storage_namespace);

  // Notifies the delegate about the creation of a new ApplicationContents. This
  // typically happens when popups are created.
  virtual void ApplicationContentsCreated(ApplicationContents* source_contents,
                                  int opener_render_process_id,
                                  int opener_render_frame_id,
                                  const std::string& frame_name,
                                  const GURL& target_url,
                                  ApplicationContents* new_contents) {}

  // Notification that one of the frames in the ApplicationContents is hung. |source| is
  // the ApplicationContents that is hung, and |application_window_host| is the
  // ApplicationWindowHost that, while routing events to it, discovered the hang.
  //
  // Useful member functions on |application_window_host|:
  // - Getting the hung render process: GetProcess()
  // - Querying whether the process is still hung: IsCurrentlyUnresponsive()
  // - Waiting for the process to recover on its own:
  //     RestartHangMonitorTimeoutIfNecessary()
  virtual void ApplicationUnresponsive(ApplicationContents* source,
                                    ApplicationWindowHost* application_window_host) {}

  // Notification that a process in the ApplicationContents is no longer hung. |source|
  // is the ApplicationContents that was hung, and |application_window_host| is the
  // ApplicationWindowHost that was passed in an earlier call to
  // ApplicationUnresponsive().
  virtual void ApplicationResponsive(ApplicationContents* source,
                                  ApplicationWindowHost* application_window_host) {}

  // Invoked when a main fram navigation occurs.
  virtual void DidNavigateMainFramePostCommit(ApplicationContents* source) {}

  // Returns a pointer to a service to manage JavaScript dialogs. May return
  // nullptr in which case dialogs aren't shown.
  //virtual JavaScriptDialogManager* GetJavaScriptDialogManager(
  //    ApplicationContents* source);

  // Called when color chooser should open. Returns the opened color chooser.
  // Returns nullptr if we failed to open the color chooser (e.g. when there is
  // a ColorChooserDialog already open on Windows). Ownership of the returned
  // pointer is transferred to the caller.
  //virtual ColorChooser* OpenColorChooser(
  //    ApplicationContents* application_contents,
  //    SkColor color,
  //    const std::vector<blink::mojom::ColorSuggestionPtr>& suggestions);

  // Called when a file selection is to be done.
  //virtual void RunFileChooser(RenderFrameHost* render_frame_host,
  //                            const FileChooserParams& params) {}

  // Request to enumerate a directory.  This is equivalent to running the file
  // chooser in directory-enumeration mode and having the user select the given
  // directory.
  //virtual void EnumerateDirectory(ApplicationContents* application_contents,
  //                                int request_id,
  //                                const base::FilePath& path) {}

  // Shows a chooser for the user to select a nearby Bluetooth device. The
  // observer must live at least as long as the returned chooser object.
  //virtual std::unique_ptr<BluetoothChooser> RunBluetoothChooser(
  //    RenderFrameHost* frame,
  //    const BluetoothChooser::EventHandler& event_handler);

  // Returns true if the delegate will embed a ApplicationContents-owned fullscreen
  // render widget.  In this case, the delegate may access the widget by calling
  // ApplicationContents::GetFullscreenApplicationWindowHostView().  If false is returned,
  // ApplicationContents will be responsible for showing the fullscreen widget.
  virtual bool EmbedsFullscreenWindow() const;

  // Called when the renderer puts a tab into fullscreen mode.
  // |origin| is the origin of the initiating frame inside the |application_contents|.
  // |origin| can be empty in which case the |application_contents| last committed
  // URL's origin should be used.
  virtual void EnterFullscreenMode(ApplicationContents* application_contents) {}

  // Called when the renderer puts a tab out of fullscreen mode.
  virtual void ExitFullscreenMode(ApplicationContents*) {}

  virtual bool IsFullscreenOrPending(
      const ApplicationContents* application_contents) const;

  // Returns the actual display mode of the top-level browsing context.
  // For example, it should return 'blink::WebDisplayModeFullscreen' whenever
  // the browser window is put to fullscreen mode (either by the end user,
  // or HTML API or from a web manifest setting).
  // See http://w3c.github.io/manifest/#dfn-display-mode
  virtual blink::WebDisplayMode GetDisplayMode(
      const ApplicationContents* application_contents) const;

  // Register a new handler for URL requests with the given scheme.
  // |user_gesture| is true if the registration is made in the context of a user
  // gesture.
  virtual void RegisterProtocolHandler(ApplicationContents* application_contents,
                                       const std::string& protocol,
                                       const GURL& url,
                                       bool user_gesture) {}

  // Unregister the registered handler for URL requests with the given scheme.
  // |user_gesture| is true if the registration is made in the context of a user
  // gesture.
  virtual void UnregisterProtocolHandler(ApplicationContents* application_contents,
                                         const std::string& protocol,
                                         const GURL& url,
                                         bool user_gesture) {}

  // Result of string search in the page. This includes the number of matches
  // found and the selection rect (in screen coordinates) for the string found.
  // If |final_update| is false, it indicates that more results follow.
  virtual void FindReply(ApplicationContents* application_contents,
                         int request_id,
                         int number_of_matches,
                         const gfx::Rect& selection_rect,
                         int active_match_ordinal,
                         bool final_update) {}

#if defined(OS_ANDROID)
  // Provides the rects of the current find-in-page matches.
  // Sent as a reply to RequestFindMatchRects.
  virtual void FindMatchRectsReply(ApplicationContents* application_contents,
                                   int version,
                                   const std::vector<gfx::RectF>& rects,
                                   const gfx::RectF& active_rect) {}
#endif

  // Invoked when the preferred size of the contents has been changed.
  virtual void UpdatePreferredSize(ApplicationContents* application_contents,
                                   const gfx::Size& pref_size) {}

  // Invoked when the contents auto-resized and the container should match it.
  virtual void ResizeDueToAutoResize(ApplicationContents* application_contents,
                                     const gfx::Size& new_size) {}

  // Requests to lock the mouse. Once the request is approved or rejected,
  // GotResponseToLockMouseRequest() will be called on the requesting tab
  // contents.
  virtual void RequestToLockMouse(ApplicationContents* application_contents,
                                  bool user_gesture,
                                  bool last_unlocked_by_target) {}

  // Notification that the page has lost the mouse lock.
  virtual void LostMouseLock() {}

  // Requests keyboard lock. Once the request is approved or rejected,
  // GotResponseToKeyboardLockRequest() will be called on |application_contents|.
  virtual void RequestKeyboardLock(ApplicationContents* application_contents,
                                   bool esc_key_locked) {}

  // Notification that the keyboard lock request has been canceled.
  virtual void CancelKeyboardLockRequest(ApplicationContents* application_contents) {}

  // Asks permission to use the camera and/or microphone. If permission is
  // granted, a call should be made to |callback| with the devices. If the
  // request is denied, a call should be made to |callback| with an empty list
  // of devices. |request| has the details of the request (e.g. which of audio
  // and/or video devices are requested, and lists of available devices).
  virtual void RequestMediaAccessPermission(
      ApplicationContents* application_contents,
      const common::MediaStreamRequest& request,
      const common::MediaResponseCallback& callback);

  // Checks if we have permission to access the microphone or camera. Note that
  // this does not query the user. |type| must be MEDIA_DEVICE_AUDIO_CAPTURE
  // or MEDIA_DEVICE_VIDEO_CAPTURE.
  virtual bool CheckMediaAccessPermission(ApplicationWindowHost* render_frame_host,
                                          const GURL& security_origin,
                                          common::MediaStreamType type);

  // Returns the ID of the default device for the given media device |type|.
  // If the returned value is an empty string, it means that there is no
  // default device for the given |type|.
  virtual std::string GetDefaultMediaDeviceID(ApplicationContents* application_contents,
                                              common::MediaStreamType type);

#if defined(OS_ANDROID)
  // Creates a view embedding the video view.
  virtual base::android::ScopedJavaLocalRef<jobject>
      GetContentVideoViewEmbedder();

  // Returns true if the given media should be blocked to load.
  virtual bool ShouldBlockMediaRequest(const GURL& url);

  // Tells the delegate to enter overlay mode.
  // Overlay mode means that we are currently using AndroidOverlays to display
  // video, and that the compositor's surface should support alpha and not be
  // marked as opaque. See media/base/android/android_overlay.h.
  virtual void SetOverlayMode(bool use_overlay_mode);
#endif

  // Requests permission to access the PPAPI broker. The delegate should return
  // true and call the passed in |callback| with the result, or return false
  // to indicate that it does not support asking for permission.
  //virtual bool RequestPpapiBrokerPermission(
  //    ApplicationContents* application_contents,
  //    const GURL& url,
  //    const base::FilePath& plugin_path,
  //    const base::Callback<void(bool)>& callback);

  // Returns the size for the new render view created for the pending entry in
  // |application_contents|; if there's no size, returns an empty size.
  // This is optional for implementations of ApplicationContentsDelegate; if the
  // delegate doesn't provide a size, the current ApplicationContentsView's size will be
  // used.
  virtual gfx::Size GetSizeForNewApplicationWindow(ApplicationContents* application_contents) const;

  // Returns true if the ApplicationContents is never visible.
  virtual bool IsNeverVisible(ApplicationContents* application_contents);

  // Called in response to a request to save a frame. If this returns true, the
  // default behavior is suppressed.
//  virtual bool SaveFrame(const GURL& url, const Referrer& referrer);

  // Can be overridden by a delegate to return the security style of the
  // given |application_contents|, populating |security_style_explanations| to
  // explain why the SecurityStyle was downgraded. Returns
  // WebSecurityStyleUnknown if not overriden.
  //virtual blink::WebSecurityStyle GetSecurityStyle(
  //    ApplicationContents* application_contents,
  //    SecurityStyleExplanations* security_style_explanations);

  // Requests the app banner. This method is called from the DevTools.
  //virtual void RequestAppBannerFromDevTools(ApplicationContents* application_contents);

  // Called when an audio change occurs.
  virtual void OnAudioStateChanged(ApplicationContents* application_contents, bool audible) {}

  // Called when a suspicious navigation of the main frame has been blocked.
  // Allows the delegate to provide some UI to let the user know about the
  // blocked navigation and give them the option to recover from it. The given
  // URL is the blocked navigation target.
  virtual void OnDidBlockFramebust(ApplicationContents* application_contents,
                                   const GURL& url) {}

  // Reports that passive mixed content was found at the specified url.
  virtual void PassiveInsecureContentFound(const GURL& resource_url) {}

  // Checks if running of active mixed content is allowed for the specified
  // ApplicationContents/tab.
  virtual bool ShouldAllowRunningInsecureContent(ApplicationContents* application_contents,
                                                 bool allowed_per_prefs,
                                                 const url::Origin& origin,
                                                 const GURL& resource_url);

  // Requests to get browser controls info such as the height of the top/bottom
  // controls, and whether they will shrink the Blink's view size.
  // Note that they are not complete in the sense that there is no API to tell
  // content to poll these values again, except part of resize. But this is not
  // needed by embedder because it's always accompanied by view size change.
  virtual int GetTopControlsHeight() const;
  virtual int GetBottomControlsHeight() const;
  virtual bool DoBrowserControlsShrinkBlinkSize() const;

  // Give ApplicationContentsDelegates the opportunity to adjust the previews state.
//  virtual void AdjustPreviewsStateForNavigation(
//      ApplicationContents* application_contents,
//      PreviewsState* previews_state) {}

  // Requests to print an out-of-process subframe for the specified ApplicationContents.
  // |rect| is the rectangular area where its content resides in its parent
  // frame. |document_cookie| is a unique id for a printed document associated
  // with
  //                   a print job.
  // |subframe_host| is the render frame host of the subframe to be printed.
  //virtual void PrintCrossProcessSubframe(ApplicationContents* application_contents,
  //                                       const gfx::Rect& rect,
  //                                       int document_cookie,
  //                                       RenderFrameHost* subframe_host) const {
 // }

  // Updates the Picture-in-Picture controller with the relevant viz::SurfaceId
  // and natural size of the video to be in Picture-in-Picture mode.
  virtual void UpdatePictureInPictureSurfaceId(const viz::SurfaceId& surface_id,
                                               const gfx::Size& natural_size);

  // Updates the Picture-in-Picture controller with a signal that
  // Picture-in-Picture mode has ended.
  virtual void ExitPictureInPicture();

 protected:
  virtual ~ApplicationContentsDelegate();

 private:
  friend class ApplicationContents;

  // Called when |this| becomes the ApplicationContentsDelegate for |source|.
  void Attach(ApplicationContents* source);

  // Called when |this| is no longer the ApplicationContentsDelegate for |source|.
  void Detach(ApplicationContents* source);

  // The ApplicationContents that this is currently a delegate for.
  std::set<ApplicationContents*> attached_contents_;
};

}  // namespace host

#endif  // CONTENT_PUBLIC_BROWSER_WEB_CONTENTS_DELEGATE_H_
