// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_APPLICATION_CONTENTS_H_
#define MUMBA_HOST_APPLICATION_APPLICATION_CONTENTS_H_

#include <stdint.h>

#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "base/compiler_specific.h"
#include "base/gtest_prod_util.h"
#include "base/macros.h"
#include "base/observer_list.h"
#include "base/process/process.h"
#include "base/time/time.h"
#include "base/values.h"
#include "base/supports_user_data.h"
#include "base/uuid.h"
#include "build/build_config.h"
//#include "components/download/public/common/download_url_parameters.h"
//#include "core/host/frame_host/frame_tree.h"
//#include "core/host/frame_host/frame_tree_node.h"
//#include "core/host/frame_host/interstitial_page_impl.h"
//#include "core/host/frame_host/navigation_controller_delegate.h"
//#include "core/host/frame_host/navigation_controller_impl.h"
//#include "core/host/frame_host/navigator_delegate.h"
//#include "core/host/frame_host/render_frame_host_delegate.h"
//#include "core/host/frame_host/render_frame_host_manager.h"
#include "core/host/media/audio_stream_monitor.h"
#include "core/host/application/application_window_host_delegate.h"
#include "core/host/application/application_window_host.h"
#include "core/host/wake_lock/wake_lock_context_host.h"
#include "core/shared/common/content_export.h"
//#include "core/host/color_chooser.h"
#include "core/host/notification_observer.h"
#include "core/host/notification_registrar.h"
#include "core/host/application/invalidate_type.h"
#include "core/host/application/resource_context.h"
#include "core/host/route/route_controller.h"
#include "core/host/application/application_contents_binding_set.h"
#include "core/host/application/application_contents_observer.h"
#include "core/host/ui/navigator_params.h"
//#include "core/common/page_importance_signals.h"
#include "core/shared/common/renderer_preferences.h"
#include "core/shared/common/resource_type.h"
#include "core/shared/common/context_menu_params.h"
//#include "core/shared/common/three_d_api_types.h"
#include "net/base/load_states.h"
#include "net/http/http_response_headers.h"
#include "services/device/public/mojom/geolocation_context.mojom.h"
#include "services/device/public/mojom/wake_lock.mojom.h"
#include "services/metrics/public/cpp/ukm_recorder.h"
#include "third_party/blink/public/mojom/color_chooser/color_chooser.mojom.h"
#include "third_party/blink/public/platform/web_drag_operation.h"
#include "ui/accessibility/ax_modes.h"
#include "ui/accessibility/ax_tree_update.h"
#include "ui/base/page_transition_types.h"
#include "ui/gfx/geometry/rect_f.h"
#include "ui/gfx/geometry/size.h"
#include "ui/gfx/image/image_skia.h"
#include "ui/gfx/image/image.h"

#if defined(OS_ANDROID)
#include "core/host/android/nfc_host.h"
#include "core/host/android/child_process_importance.h"
#endif

struct ViewHostMsg_DateTimeDialogValue_Params;

namespace service_manager {
class InterfaceProvider;
}

namespace common {
namespace mojom {
class CreateNewWindowParams;
}  
}

namespace host {
class Domain;
class RouteResolver;
class InterstitialPage;
class InterstitialPageImpl;
class MediaApplicationContentsObserver;
class ApplicationWindowHost;
class ApplicationWindowHostDelegateView;
class ApplicationContentsView;
class ApplicationWindowHostInputEventRouter;
class ScreenOrientationProvider;
class TextInputManager;
class ApplicationContentsAudioMuter;
class ApplicationContentsDelegate;
class ApplicationContents;
class ApplicationContentsViewDelegate;
struct AXEventNotificationDetails;
//struct FaviconURL;
struct LoadNotificationDetails;

#if defined(OS_ANDROID)
class ApplicationContentsAndroid;
#else  // !defined(OS_ANDROID)
class HostZoomMapObserver;
#endif  // defined(OS_ANDROID)

ApplicationContentsView* CreateApplicationContentsView(
    ApplicationContents* app_contents,
    ApplicationContentsViewDelegate* delegate,
    ApplicationWindowHostDelegateView** app_window_host_delegate_view);
 
class CONTENT_EXPORT ApplicationContents :  public base::SupportsUserData,
                                            public ApplicationWindowHostDelegate,
                                            public NotificationObserver {
public:
  class FriendWrapper;

  using AXTreeSnapshotCallback = base::OnceCallback<void(const ui::AXTreeUpdate&)>;
  // Returns a map containing the sizes of all currently playing videos.
  using VideoSizeMap =
      base::flat_map<ApplicationContentsObserver::MediaPlayerId, gfx::Size>;

  struct CONTENT_EXPORT CreateParams {
    CreateParams();
    CreateParams(const CreateParams& other);
    ~CreateParams();

    scoped_refptr<Workspace> workspace;

    // The process id of the frame initiating the open.
    int opener_application_process_id = 0;

    // The routing id of the frame initiating the open.
    //int opener_render_frame_id;

    // If the opener is suppressed, then the new WebContents doesn't hold a
    // reference to its opener.
    bool opener_suppressed = false;

    // Indicates whether this WebContents was created with a window.opener.
    // This is used when determining whether the WebContents is allowed to be
    // closed via window.close(). This may be true even with a null |opener|
    // (e.g., for blocked popups).
    bool created_with_opener = false;

    // The routing ids of the RenderView, main RenderFrame, and the widget for
    // the main RenderFrame. Either all routing IDs must be provided or all must
    // be MSG_ROUTING_NONE to have WebContents make the assignment. If provided,
    // these routing IDs are associated with |site_instance->GetProcess()|.
    int32_t routing_id = MSG_ROUTING_NONE;
    //int32_t main_frame_routing_id;
    //int32_t main_frame_widget_routing_id;

    // The name of the top-level frame of the new window. It is non-empty
    // when creating a named window (e.g. <a target="foo"> or
    // window.open('', 'bar')).
    //std::string main_frame_name;

    // Initial size of the new WebContent's view. Can be (0, 0) if not needed.
    gfx::Size initial_size = gfx::Size();

    // True if the contents should be initially hidden.
    bool initially_hidden = false;

    // Used to specify the location context which display the new view should
    // belong. This can be nullptr if not needed.
    gfx::NativeView context;

    // Used to specify that the new WebContents creation is driven by the
    // application process. In this case, the renderer-side objects, such as
    // RenderFrame, have already been created on the renderer side, and
    // WebContents construction should take this into account.
    bool application_initiated_creation = false;

    // True if the WebContents should create its renderer process and main
    // RenderFrame before the first navigation. This is useful to reduce
    // the latency of the first navigation in cases where it might
    // not happen right away.
    // Note that the pre-created renderer process may not be used if the first
    // navigation requires a dedicated or privileged process, such as a WebUI.
    bool initialize_application = true;

    // Sandboxing flags set on the new WebContents.
    blink::WebSandboxFlags starting_sandbox_flags;

    Application* application = nullptr;

    std::string page_name;

    Domain* parent = nullptr;

    RouteResolver* url_resolver = nullptr;

    GURL url;
  };

#if defined (OS_WIN)  
  static ApplicationContents* Create(const CreateParams& params);
  static ApplicationContents* FromApplicationWindowHost(ApplicationWindowHost* awh);
  static ApplicationContents* FromID(int32_t process_id, int32_t routing_id);
#else
  CONTENT_EXPORT static ApplicationContents* Create(const CreateParams& params);
  CONTENT_EXPORT static ApplicationContents* FromApplicationWindowHost(ApplicationWindowHost* awh);
  CONTENT_EXPORT static ApplicationContents* FromID(int32_t process_id, int32_t routing_id);
#endif
  static std::vector<ApplicationContents*> GetAllApplicationContents();

  ~ApplicationContents();

  void Init(const CreateParams& params);

  // Cancels modal dialogs in this ApplicationContents, as well as in any browser
  // plugins it is hosting.
  //void CancelActiveAndPendingDialogs();

  // Informs the render view host and the BrowserPluginEmbedder, if present, of
  // a Drag Source End.
  void DragSourceEndedAt(float client_x,
                         float client_y,
                         float screen_x,
                         float screen_y,
                         blink::WebDragOperation operation,
                         ApplicationWindowHost* source_rwh);

  // Notification that the ApplicationWindowHost's load state changed.
  void LoadStateChanged(const std::string& host,
                        const net::LoadStateWithParam& load_state,
                        uint64_t upload_position,
                        uint64_t upload_size);

  // Set the visibility to |visibility| and notifies observers.
  void SetVisibility(Visibility visibility);

  // Notify observers that the web contents has been focused.
  void NotifyApplicationContentsFocused(ApplicationWindowHost* application_window_host);

  // Notify observers that the web contents has lost focus.
  void NotifyApplicationContentsLostFocus(ApplicationWindowHost* application_window_host);

  ApplicationContentsView* GetView() const;
  void OnScreenOrientationChange();

  ResourceContext* GetResourceContext() const { 
    return resource_context_; 
  }

  ScreenOrientationProvider* GetScreenOrientationProviderForTesting() const {
    return screen_orientation_provider_.get();
  }

  // Broadcasts the mode change to all frames.
  void SetAccessibilityMode(ui::AXMode mode);

  // Adds the given accessibility mode to the current accessibility mode
  // bitmap.
  void AddAccessibilityMode(ui::AXMode mode);

#if !defined(OS_ANDROID)
  // Set a temporary zoom level for the frames associated with this ApplicationContents.
  // If |is_temporary| is true, we are setting a new temporary zoom level,
  // otherwise we are clearing a previously set temporary zoom level.
  void SetTemporaryZoomLevel(double level, bool temporary_zoom_enabled);

  // Sets the zoom level for frames associated with this ApplicationContents.
  void UpdateZoom(double level);

  // Sets the zoom level for frames associated with this ApplicationContents if it
  // matches |host| and (if non-empty) |scheme|. Matching is done on the
  // last committed entry.
  void UpdateZoomIfNecessary(const std::string& scheme,
                             const std::string& host,
                             double level);
#endif  // !defined(OS_ANDROID)

  // Adds a new binding set to the ApplicationContents. Returns a closure which may be
  // used to remove the binding set at any time. The closure is safe to call
  // even after ApplicationContents destruction.
  //
  // |binding_set| is not owned and must either outlive this ApplicationContents or be
  // explicitly removed before being destroyed.
  base::Closure AddBindingSet(const std::string& interface_name,
                              ApplicationContentsBindingSet* binding_set);

  // Accesses a ApplicationContentsBindingSet for a specific interface on this
  // ApplicationContents. Returns null of there is no registered binder for the
  // interface.
  ApplicationContentsBindingSet* GetBindingSet(const std::string& interface_name);

  // Returns the focused ApplicationContents.
  // If there are multiple inner/outer ApplicationContents (when embedding <webview>,
  // <guestview>, ...) returns the single one containing the currently focused
  // frame. Otherwise, returns this ApplicationContents.
  //ApplicationContents* GetFocusedApplicationContents();

  // TODO(paulmeyer): Once GuestViews are no longer implemented as
  // BrowserPluginGuests, frame traversal across ApplicationContents should be moved to
  // be handled by FrameTreeNode, and |GetInnerApplicationContents| and
  // |GetApplicationContentsAndAllInner| can be removed.

  // Returns a vector to the inner ApplicationContents within this ApplicationContents.
  //std::vector<ApplicationContents*> GetInnerApplicationContents();

  // Returns a vector containing this ApplicationContents and all inner ApplicationContents
  // within it (recursively).
  //std::vector<ApplicationContents*> GetApplicationContentsAndAllInner();

  //void NotifyManifestUrlChanged(const base::Optional<GURL>& manifest_url);

  //ManifestManagerHost* GetManifestManagerHost() const {
  //  return manifest_manager_host_.get();
  //}

  // TODO(https://crbug.com/826293): This is a simple mitigation to validate
  // that an action that requires a user gesture actually has one in the
  // trustworthy browser process, rather than relying on the untrustworthy
  // renderer. This should be eventually merged into and accounted for in the
  // user activation work.
  bool HasRecentInteractiveInputEvent() const;

//#if defined(OS_ANDROID)
  //std::set<ApplicationWindowHost*> GetAllApplicationWindowHosts();
  //void SetImportance(ChildProcessImportance importance);
//#endif

  // ApplicationContents ------------------------------------------------------
  ApplicationContentsDelegate* GetDelegate();
  void SetDelegate(ApplicationContentsDelegate* delegate);
  //NavigationControllerImpl& GetController() override;
  //const NavigationControllerImpl& GetController() const override;
  //ApplicationContents* GetApplicationContents() const override;
  const std::string& GetApplicationName() const;
  const base::UUID& GetApplicationUUID() const;
  Application* GetApplication() const override;
  const std::string& GetPageName() const;
  const GURL& GetURL() const;
  const GURL& GetVisibleURL() const;
  const GURL& GetLastCommittedURL() const;
  bool CanOverscrollContent() const override;
  Domain* GetDomain() const override;
  //RenderFrameHostImpl* GetMainFrame() const override;
  //RenderFrameHostImpl* GetFocusedFrame() override;
  //RenderFrameHostImpl* FindFrameByFrameTreeNodeId(int frame_tree_node_id,
  //                                                int process_id) override;
  // RenderFrameHostImpl* UnsafeFindFrameByFrameTreeNodeId(
  //     int frame_tree_node_id) override;
  //void ForEachFrame(
  //    const base::RepeatingCallback<void(RenderFrameHost*)>& on_frame) override;
  //std::vector<RenderFrameHost*> GetAllFrames() override;
  //int SendToAllFrames(IPC::Message* message) override;
  ApplicationProcessHost* GetApplicationProcessHost() const;
  ApplicationWindowHost* GetApplicationWindowHost() const;
  ApplicationWindowHostView* GetApplicationWindowHostView() const;
  ApplicationWindowHostView* GetTopLevelApplicationWindowHostView();
  void ClosePage();
  ApplicationWindowHostView* GetFullscreenApplicationWindowHostView() const;
  //SkColor GetThemeColor() const;
  //WebUI* GetWebUI() const;
  //WebUI* GetCommittedWebUI() const;
  //void SetUserAgentOverride(const std::string& override,
  //                          bool override_in_new_tabs);
  //const std::string& GetUserAgentOverride() const;
  //bool ShouldOverrideUserAgentInNewTabs();
  void EnableApplicationContentsOnlyAccessibilityMode();
  bool IsApplicationContentsOnlyAccessibilityModeForTesting() const;
  const base::string16& GetTitle() const;
  gfx::Image GetFavicon();
  bool IsLoading() const;
  bool IsWaitingForResponse() const;
  const net::LoadStateWithParam& GetLoadState() const;
  const base::string16& GetLoadStateHost() const;
  void RequestAXTreeSnapshot(AXTreeSnapshotCallback callback,
                             ui::AXMode ax_mode);
  uint64_t GetUploadSize() const;
  uint64_t GetUploadPosition() const;
  const std::string& GetEncoding() const;
  void SetWasDiscarded(bool was_discarded);
  void IncrementCapturerCount(const gfx::Size& capture_size);
  void DecrementCapturerCount();
  bool IsBeingCaptured() const;
  bool IsAudioMuted() const;
  void SetAudioMuted(bool mute);
  bool IsCurrentlyAudible();
  bool IsConnectedToBluetoothDevice() const;
  bool IsCrashed() const;
  void SetIsCrashed(base::TerminationStatus status, int error_code);
  base::TerminationStatus GetCrashedStatus() const;
  int GetCrashedErrorCode() const;
  bool IsBeingDestroyed() const;
  void NotifyNavigationStateChanged(InvalidateTypes changed_flags);
  void OnAudioStateChanged(bool is_audible);
  base::TimeTicks GetLastActiveTime() const;
  void SetLastActiveTime(base::TimeTicks last_active_time);
  void WasShown();
  void WasHidden();
  void WasOccluded();
  Visibility GetVisibility() const override;
  bool NeedToFireBeforeUnload();
  void DispatchBeforeUnload();
  // void AttachToOuterApplicationContentsFrame(
  //     ApplicationContents* outer_application_contents,
  //     RenderFrameHost* outer_contents_frame);
  //ApplicationContents* GetOuterApplicationContents();
  void DidChangeVisibleSecurityState();
  void NotifyPreferencesChanged();
  void DidStartLoading(bool is_main_frame, bool to_different_document) override;
  void DidStopLoading() override;
  void Stop();
  void FreezePage();
  ApplicationContents* Clone();
  //void ReloadFocusedFrame(bool bypass_cache);
  void Undo();
  void Redo();
  void Cut();
  void Copy();
  void CopyToFindPboard();
  void Paste();
  void PasteAndMatchStyle();
  void Delete();
  void SelectAll();
  void CollapseSelection();
  void Replace(const base::string16& word);
  void ReplaceMisspelling(const base::string16& word);
  void NotifyContextMenuClosed(
      const common::CustomContextMenuContext& context);
  void ReloadLoFiImages();
  void ExecuteCustomContextMenuCommand(
      int action,
      const common::CustomContextMenuContext& context);
  gfx::NativeView GetNativeView();
  gfx::NativeView GetContentNativeView();
  gfx::NativeWindow GetTopLevelNativeWindow();
  gfx::Rect GetContainerBounds();
  gfx::Rect GetViewBounds();
  common::DropData* GetDropData();
  void Focus();
  void SetInitialFocus();
  void StoreFocus();
  void RestoreFocus();
  void FocusThroughWindowTraversal(bool reverse);
  bool ShowingInterstitialPage() const;
  //void AdjustPreviewsStateForNavigation(PreviewsState* previews_state);
  InterstitialPageImpl* GetInterstitialPage() const;
  //bool IsSavable();
  //void OnSavePage();
  //bool SavePage(const base::FilePath& main_file,
  //              const base::FilePath& dir_path,
  //              SavePageType save_type);
  //void SaveFrame(const GURL& url, const Referrer& referrer);
  //void SaveFrameWithHeaders(const GURL& url,
  //                          const Referrer& referrer,
  //                          const std::string& headers,
  //                          const base::string16& suggested_filename);
  //void GenerateMHTML(const MHTMLGenerationParams& params,
  //                   base::OnceCallback<void(int64_t)> callback);
  //const std::string& GetContentsMimeType() const;
  bool WillNotifyDisconnection() const;
  common::RendererPreferences* GetMutableRendererPrefs();
  void Close();
  void CloseNow();
  void SystemDragEnded(ApplicationWindowHost* source_rwh);
  void NavigatedByUser();
  void SetClosedByUserGesture(bool value);
  bool GetClosedByUserGesture() const;
  int GetMinimumZoomPercent() const;
  int GetMaximumZoomPercent() const;
  void SetPageScale(float page_scale_factor);
  gfx::Size GetPreferredSize() const;
  bool GotResponseToLockMouseRequest(bool allowed);
  bool GotResponseToKeyboardLockRequest(bool allowed);
  //bool HasOpener() const;
  //RenderFrameHostImpl* GetOpener() const;
  //bool HasOriginalOpener() const;
  //RenderFrameHostImpl* GetOriginalOpener() const;
  //void DidChooseColorInColorChooser(SkColor color);
  //void DidEndColorChooser();
  //int DownloadImage(const GURL& url,
  //                  bool is_favicon,
  //                  uint32_t max_bitmap_size,
  //                  bool bypass_cache,
  //                  ImageDownloadCallback callback);
  //bool IsSubframe() const;
  //void Find(int request_id,
  //          const base::string16& search_text,
  //          const blink::WebFindOptions& options);
  //void StopFinding(StopFindAction action);
  bool WasRecentlyAudible();
  bool WasEverAudible();
  //void GetManifest(GetManifestCallback callback);
  //bool IsFullscreenForCurrentTab() const;
  //void ExitFullscreen(bool will_cause_resize) override;
  void ResumeLoadingCreatedApplicationContents();
  void SetIsOverlayContent(bool is_overlay_content);
  //bool IsFocusedElementEditable();
  //void ClearFocusedElement();
  bool IsShowingContextMenu() const;
  void SetShowingContextMenu(bool showing);
  void PausePageScheduledTasks(bool paused);

#if defined(OS_ANDROID)
  base::android::ScopedJavaLocalRef<jobject> GetJavaApplicationContents();
  virtual ApplicationContentsAndroid* GetApplicationContentsAndroid();
  //void ActivateNearestFindResult(float x, float y);
  //void RequestFindMatchRects(int current_version);
  service_manager::InterfaceProvider* GetJavaInterfaces();
#elif defined(OS_MACOSX)
  void SetAllowOtherViews(bool allow);
  bool GetAllowOtherViews();
  bool CompletedFirstVisuallyNonEmptyPaint() const;
#endif

  // Implementation of PageNavigator.
  ApplicationContents* OpenURL(const GURL& url);//const OpenURLParams& params);

  // This gets called by Dock and it was originally in NavigatorController
  // as in contents->controller()->LoadURLParams(...)
  void LoadURL(const GURL& url, const NavigateParams& params);

  // RenderFrameHostDelegate ---------------------------------------------------
  //bool OnMessageReceived(RenderFrameHostImpl* render_frame_host,
  //                       const IPC::Message& message);
  //void OnAssociatedInterfaceRequest(
  //    RenderFrameHost* render_frame_host,
  //    const std::string& interface_name,
  //    mojo::ScopedInterfaceEndpointHandle handle);
//   void OnInterfaceRequest(
//       RenderFrameHost* render_frame_host,
//       const std::string& interface_name,
//       mojo::ScopedMessagePipeHandle* interface_pipe);
//   void OnDidBlockFramebust(const GURL& url);
//   const GURL& GetMainFrameLastCommittedURL() const;
//   void RenderFrameCreated(RenderFrameHost* render_frame_host);
//   void RenderFrameDeleted(RenderFrameHost* render_frame_host);
//   void ShowContextMenu(RenderFrameHost* render_frame_host,
//                        const ContextMenuParams& params);
//   void RunJavaScriptDialog(RenderFrameHost* render_frame_host,
//                            const base::string16& message,
//                            const base::string16& default_prompt,
//                            JavaScriptDialogType dialog_type,
//                            IPC::Message* reply_msg);
//   void RunBeforeUnloadConfirm(RenderFrameHost* render_frame_host,
//                               bool is_reload,
//                               IPC::Message* reply_msg);
//   void RunFileChooser(RenderFrameHost* render_frame_host,
//                       const FileChooserParams& params);
   void DidCancelLoading();
   void DidAccessInitialDocument() override;
//   void DidChangeName(RenderFrameHost* render_frame_host,
//                      const std::string& name);
   void DocumentOnLoadCompleted(ApplicationFrame* application_frame) override;
   void UpdateStateForFrame(ApplicationFrame* application_frame,
                         const common::mojom::PageState& page_state) override;
   void UpdateTitle(ApplicationWindowHost* application_window_host,
                    const base::string16& title,
                    base::i18n::TextDirection title_direction) override;
   void DidFailLoadWithError(const GURL& url, int32_t error_code, const base::string16& error_description) override;
  
//   void UpdateEncoding(RenderFrameHost* render_frame_host,
//                       const std::string& encoding);
ApplicationContents* GetAsApplicationContents() override;
//   bool IsNeverVisible();
//   ui::AXMode GetAccessibilityMode() const;
//   void AccessibilityEventReceived(
//       const std::vector<AXEventNotificationDetails>& details);
//   void AccessibilityLocationChangesReceived(
//       const std::vector<AXLocationChangeNotificationDetails>& details);
//   RenderFrameHost* GetGuestByInstanceID(
//       RenderFrameHost* render_frame_host,
//       int browser_plugin_instance_id);
//   device::mojom::GeolocationContext* GetGeolocationContext();
   device::mojom::WakeLockContext* GetWakeLockContext();
//   device::mojom::WakeLock* GetRendererWakeLock();
// #if defined(OS_ANDROID)
//   void GetNFC(device::mojom::NFCRequest request);
// #endif
  bool IsFullscreen() const override;
  void EnterFullscreenMode() override;
  void ExitFullscreen(bool will_cause_resize);
  void ExitFullscreenMode(bool will_cause_resize) override;
  // bool ShouldRouteMessageEvent(
  //     RenderFrameHost* target_rfh,
  //     SiteInstance* source_site_instance) const;
  // void EnsureOpenerProxiesExist(RenderFrameHost* source_rfh);
  // std::unique_ptr<WebUIImpl> CreateWebUIForRenderFrameHost(
  //     const GURL& url);
  // void SetFocusedFrame(FrameTreeNode* node, SiteInstance* source);
  void DidCallFocus();
  // RenderFrameHost* GetFocusedFrameIncludingInnerApplicationContents();
  // void OnFocusedElementChangedInFrame(
  //     RenderFrameHostImpl* frame,
  //     const gfx::Rect& bounds_in_root_view);
  // void OnAdvanceFocus(RenderFrameHostImpl* source_rfh);
  ApplicationWindowHost* GetFullscreenApplicationWindowHost() const;
  
  // ApplicationWindowHostDelegate
  void CreateNewWindow(
      ApplicationWindowHost* opener,
      Domain* parent,
      Application* application,
      int32_t application_window_route_id,
      bool initially_hidden,
      bool application_initiated,  
      const common::mojom::CreateNewWindowParams& params) override;

  void ShowCreatedWindow(Application* application,
                         int process_id,
                         int main_frame_widget_route_id,
                         WindowOpenDisposition disposition,
                         const gfx::Rect& initial_rect,
                         bool user_gesture) override;
  //void DidDisplayInsecureContent();
  //void DidRunInsecureContent(const GURL& security_origin,
  //                           const GURL& target_url);
  //void PassiveInsecureContentFound(const GURL& resource_url);
  //bool ShouldAllowRunningInsecureContent(content::ApplicationContents* application_contents,
  //                                       bool allowed_per_prefs,
  //                                       const url::Origin& origin,
  //                                       const GURL& resource_url);
  //void ViewSource(RenderFrameHostImpl* frame);
  //void PrintCrossProcessSubframe(const gfx::Rect& rect,
  //                               int document_cookie,
  //                               RenderFrameHost* render_frame_host);
//#if defined(OS_ANDROID)
//  base::android::ScopedJavaLocalRef<jobject> GetJavaRenderFrameHostDelegate()
//     ;
//#endif
//  void SubresourceResponseStarted(const GURL& url,
//                                  net::CertStatus cert_status);
//  void ResourceLoadComplete(
//      mojom::ResourceLoadInfoPtr resource_load_information);
//  void UpdatePictureInPictureSurfaceId(const viz::SurfaceId& surface_id,
//                                       const gfx::Size& natural_size);
//  void ExitPictureInPicture();

  // ApplicationWindowHostDelegate ----------------------------------------------------
  ApplicationWindowHostDelegateView* GetDelegateView();
  bool OnMessageReceived(ApplicationWindowHost* application_window_host,
                         const IPC::Message& message);
  // RenderFrameHostDelegate has the same method, so list it there because this
  // interface is going away.
  // ApplicationContents* GetAsApplicationContents();
  void UpdateTargetURL(ApplicationWindowHost* application_window_host,
                       const GURL& url);
  void Close(ApplicationWindowHost* application_window_host);
  void CloseNowImpl(ApplicationWindowHost* application_window_host);
  void RequestMove(const gfx::Rect& new_bounds);
  void DocumentAvailableInMainFrame(ApplicationWindowHost* application_window_host);
  void RouteCloseEvent(ApplicationWindowHost* rvh);
  //bool DidAddMessageToConsole(int32_t level,
  //                            const base::string16& message,
  //                            int32_t line_no,
  //                            const base::string16& source_id);
  common::RendererPreferences GetRendererPrefs() const;
      //ApplicationContents* application_contents) const;
  void DidReceiveInputEvent(ApplicationWindowHost* application_window_host,
                            const blink::WebInputEvent::Type type);
  void OnIgnoredUIEvent();
  void Activate();
  void UpdatePreferredSize(const gfx::Size& pref_size);
  void CreateNewWindow(int32_t render_process_id,
                       int32_t route_id,
                       blink::WebPopupType popup_type) override;  
  void CreateNewFullscreenWindow(int32_t render_process_id,
                                 int32_t route_id) override;
  void ShowCreatedWindow(int process_id,
                         int route_id,
                         const gfx::Rect& initial_rect) override;

  void ShowCreatedFullscreenWindow(int process_id, int route_id) override;
  // void RequestMediaAccessPermission(
  //     const MediaStreamRequest& request,
  //     const MediaResponseCallback& callback);
  // bool CheckMediaAccessPermission(RenderFrameHost* render_frame_host,
  //                                 const url::Origin& security_origin,
  //                                 MediaStreamType type);
  // std::string GetDefaultMediaDeviceID(MediaStreamType type);
  // SessionStorageNamespace* GetSessionStorageNamespace(
  //     SiteInstance* instance);
  // SessionStorageNamespaceMap GetSessionStorageNamespaceMap();
//#if !defined(OS_ANDROID)
//  double GetPendingPageZoomLevel();
//#endif  // !defined(OS_ANDROID)
  // FrameTree* GetFrameTree();
  // bool IsOverridingUserAgent();
  // bool IsJavaScriptDialogShowing() const;
  // bool ShouldIgnoreUnresponsiveRenderer();
  // bool HideDownloadUI() const;
  // bool HasPersistentVideo() const;
  // RenderFrameHost* GetPendingMainFrame();

  // ApplicationWindowHostDelegate --------------------------------------------------
  void ApplicationWindowCreated(ApplicationWindowHost* application_window_host) override;
  void ApplicationWindowDeleted(ApplicationWindowHost* application_window_host) override;
  void ApplicationWindowGotFocus(ApplicationWindowHost* application_window_host) override;
  void ApplicationWindowLostFocus(ApplicationWindowHost* application_window_host) override;
  void ApplicationWindowWasResized(ApplicationWindowHost* application_window_host,
                              const common::ScreenInfo& screen_info,
                              bool width_changed) override;
  void ApplicationWindowReady(ApplicationWindowHost* application_window_host);
  void ApplicationWindowTerminated(ApplicationWindowHost* application_window_host,
                                   base::TerminationStatus status,
                                   int error_code);
  
  void ResizeDueToAutoResize(
      ApplicationWindowHost* application_window_host,
      const gfx::Size& new_size,
      const viz::LocalSurfaceId& local_surface_id) override;
  gfx::Size GetAutoResizeSize() override;
  void ResetAutoResizeSize() override;
  KeyboardEventProcessingResult PreHandleKeyboardEvent(
      const NativeWebKeyboardEvent& event) override;
  void HandleKeyboardEvent(const NativeWebKeyboardEvent& event) override;
  bool HandleWheelEvent(const blink::WebMouseWheelEvent& event) override;
  bool PreHandleGestureEvent(const blink::WebGestureEvent& event) override;
 // BrowserAccessibilityManager* GetRootAccessibilityManager() override;
  //BrowserAccessibilityManager* GetOrCreateRootAccessibilityManager() override;
  // The following 4 functions are already listed under ApplicationContents overrides:
  // void Cut() override;
  // void Copy() override;
  // void Paste() override;
  // void SelectAll() override;
  void ExecuteEditCommand(const std::string& command,
                          const base::Optional<base::string16>& value) override;
  void MoveRangeSelectionExtent(const gfx::Point& extent) override;
  void SelectRange(const gfx::Point& base, const gfx::Point& extent) override;
  void MoveCaret(const gfx::Point& extent) override;
  void AdjustSelectionByCharacterOffset(int start_adjust,
                                        int end_adjust,
                                        bool show_selection_menu);// override;
  ApplicationWindowHostInputEventRouter* GetInputEventRouter() override;
  void ReplicatePageFocus(bool is_focused) override;
  ApplicationWindowHost* GetFocusedApplicationWindowHost(
      ApplicationWindowHost* receiving_widget) override;
  ApplicationWindowHost* GetApplicationWindowHostWithPageFocus() override;
  void FocusOwningApplicationContents(
      ApplicationWindowHost* application_window_host) override;
  void ApplicationUnresponsive(ApplicationWindowHost* application_window_host) override;
  void ApplicationResponsive(ApplicationWindowHost* application_window_host) override;
  void RequestToLockMouse(ApplicationWindowHost* application_window_host,
                          bool user_gesture,
                          bool last_unlocked_by_target,
                          bool privileged) override;
  bool RequestKeyboardLock(ApplicationWindowHost* application_window_host,
                           bool esc_key_locked) override;
  void CancelKeyboardLock(ApplicationWindowHost* application_window_host) override;
  ApplicationWindowHost* GetKeyboardLockWidget() override;
  // The following function is already listed under ApplicationContents overrides:
  // bool IsFullscreenForCurrentTab() const override;
  blink::WebDisplayMode GetDisplayMode(
      ApplicationWindowHost* application_window_host) const override;
  void LostCapture(ApplicationWindowHost* application_window_host) override;
  void LostMouseLock(ApplicationWindowHost* application_window_host) override;
  bool HasMouseLock(ApplicationWindowHost* application_window_host) override;
  ApplicationWindowHost* GetMouseLockWidget() override;
  //void OnRenderFrameProxyVisibilityChanged(bool visible) override;
  void SendScreenRects() override;
  TextInputManager* GetTextInputManager() override;
  bool OnUpdateDragCursor() override;
  //bool IsWidgetForMainFrame(ApplicationWindowHost* application_window_host) override;
  //bool AddDomainInfoToRapporSample(rappor::Sample* sample) override;
  void FocusedNodeTouched(bool editable) override;
  void DidReceiveCompositorFrame() override;
  bool IsShowingContextMenuOnPage() const override;
  void DidChangeLoadProgress() override;
  void OnCloseAckReceived(ApplicationWindowHost* application_window_host) override;
  void OnRenderFrameMetadataChanged() override;

  // RenderFrameHostManager::Delegate ------------------------------------------

  // bool CreateApplicationWindowForRenderManager(
  //     ApplicationWindowHost* application_window_host,
  //     int opener_frame_routing_id,
  //     int proxy_routing_id,
  //     const base::UnguessableToken& devtools_frame_token,
  //     const FrameReplicationState& replicated_frame_state) override;
  // void CreateApplicationWindowHostViewForRenderManager(
  //     ApplicationWindowHost* application_window_host) override;
  // bool CreateRenderFrameForRenderManager(
  //     RenderFrameHost* render_frame_host,
  //     int proxy_routing_id,
  //     int opener_routing_id,
  //     int parent_routing_id,
  //     int previous_sibling_routing_id) override;
  // void BeforeUnloadFiredFromRenderManager(
  //     bool proceed,
  //     const base::TimeTicks& proceed_time,
  //     bool* proceed_to_fire_unload) override;
  // void RenderProcessGoneFromRenderManager(
  //     ApplicationWindowHost* application_window_host) override;
  void UpdateApplicationWindowSize(bool is_main_frame) override;
  RouteController* GetRouteController() override;
  NavigationController* GetNavigationController() override;
  
  void CancelModalDialogs() override;
  void DidNavigateMainFramePreCommit(bool navigation_is_within_page) override;
  void DidNavigateMainFramePostCommit(
    ApplicationFrame* app_window_host,
    const common::mojom::DidCommitProvisionalLoadParams& params);
  void DidNavigateAnyFramePostCommit(
    ApplicationFrame* app_window_host,
    const common::mojom::DidCommitProvisionalLoadParams& params);
  // void NotifySwappedFromRenderManager(RenderFrameHost* old_host,
  //                                     RenderFrameHost* new_host,
  //                                     bool is_main_frame) override;
  // void NotifyMainFrameSwappedFromRenderManager(
  //     ApplicationWindowHost* old_host,
  //     ApplicationWindowHost* new_host) override;
  // NavigationControllerImpl& GetControllerForRenderManager() override;
  // NavigationEntry* GetLastCommittedNavigationEntryForRenderManager() override;
  // InterstitialPageImpl* GetInterstitialForRenderManager() override;
  // bool FocusLocationBarByDefault() override;
  // void SetFocusToLocationBar(bool select_all) override;
  // bool IsHidden() override;
  // int GetOuterDelegateFrameTreeNodeId() override;
  // ApplicationWindowHost* GetFullscreenApplicationWindowHost() const override;

  // blink::mojom::ColorChooserFactory ---------------------------------------

  // void OnColorChooserFactoryRequest(
  //     blink::mojom::ColorChooserFactoryRequest request);
  // void OpenColorChooser(
  //     blink::mojom::ColorChooserRequest chooser,
  //     blink::mojom::ColorChooserClientPtr client,
  //     SkColor color,
  //     std::vector<blink::mojom::ColorSuggestionPtr> suggestions) override;

  // NotificationObserver ------------------------------------------------------

  void Observe(int type,
               const NotificationSource& source,
               const NotificationDetails& details) override;

  // Called by InterstitialPageImpl when it creates a RenderFrameHost.
  //void RenderFrameForInterstitialPageCreated(
  //    RenderFrameHost* render_frame_host) override;

  // Sets the passed interstitial as the currently showing interstitial.
  // No interstitial page should already be attached.
  void AttachInterstitialPage(InterstitialPageImpl* interstitial_page);

  void MediaMutedStatusChanged(const ApplicationContentsObserver::MediaPlayerId& id,
                               bool muted);

  // Unsets the currently showing interstitial.
  void DetachInterstitialPage(bool has_focus);

  // Unpause the throbber if it was paused.
  void DidProceedOnInterstitial();// override;

  // Forces overscroll to be disabled (used by touch emulation).
  void SetForceDisableOverscrollContent(bool force_disable);

  // Override the render view/widget size of the main frame, return whether the
  // size changed.
  bool SetDeviceEmulationSize(const gfx::Size& new_size);
  void ClearDeviceEmulationSize();

  AudioStreamMonitor* audio_stream_monitor() const {
    return audio_stream_monitor_.get();
  }

  // Called by MediaApplicationContentsObserver when playback starts or stops.  See the
  // ApplicationContentsObserver function stubs for more details.
  void MediaStartedPlaying(
      const ApplicationContentsObserver::MediaPlayerInfo& media_info,
      const ApplicationContentsObserver::MediaPlayerId& id);
  void MediaStoppedPlaying(
      const ApplicationContentsObserver::MediaPlayerInfo& media_info,
      const ApplicationContentsObserver::MediaPlayerId& id,
      ApplicationContentsObserver::MediaStoppedReason reason);
  // This will be called before playback is started, check
  // GetCurrentlyPlayingVideoCount if you need this when playback starts.
  void MediaResized(const gfx::Size& size,
                    const ApplicationContentsObserver::MediaPlayerId& id);
  void MediaEffectivelyFullscreenChanged(bool is_fullscreen);

  int GetCurrentlyPlayingVideoCount();// override;
  base::Optional<gfx::Size> GetFullscreenVideoSize();// override;

  MediaApplicationContentsObserver* media_application_contents_observer() {
    return media_application_contents_observer_.get();
  }

  // Update the web contents visibility.
  void UpdateApplicationContentsVisibility(Visibility visibility);

  // Called by FindRequestManager when find replies come in from a renderer
  // process.
  //void NotifyFindReply(int request_id,
  //                     int number_of_matches,
  //                     const gfx::Rect& selection_rect,
  //                     int active_match_ordinal,
  //                     bool final_update);

  // Modify the counter of connected devices for this ApplicationContents.
  void IncrementBluetoothConnectedDeviceCount();
  void DecrementBluetoothConnectedDeviceCount();

  // Called when the ApplicationContents gains or loses a persistent video.
  void SetHasPersistentVideo(bool has_persistent_video);

  // Whether the ApplicationContents has an active player is effectively fullscreen.
  // That means that the video is either fullscreen or it is the content of
  // a fullscreen page (in other words, a fullscreen video with custom
  // controls).
  // |IsFullscreen| must return |true| when this method is called.
  bool HasActiveEffectivelyFullscreenVideo() const;

  // Whether the ApplicationContents effectively fullscreen active player allows
  // Picture-in-Picture.
  // |IsFullscreen| must return |true| when this method is called.
  bool IsPictureInPictureAllowedForFullscreenVideo() const;

  // When inner or outer ApplicationContents are present, become the focused
  // ApplicationContents. This will activate this content's main frame ApplicationWindow
  // and indirectly all its subframe widgets.  GetFocusedApplicationWindowHost will
  // search this ApplicationContents for a focused ApplicationWindowHost. The previously
  // focused ApplicationContents, if any, will have its ApplicationWindowHosts
  // deactivated.
  //void SetAsFocusedApplicationContentsIfNecessary();

  // Add and remove observers for page navigation notifications. The order in
  // which notifications are sent to observers is undefined. Clients must be
  // sure to remove the observer before they go away.
  void AddObserver(base::WeakPtr<ApplicationContentsObserver> observer);
  void RemoveObserver(ApplicationContentsObserver* observer);

 private:
  friend class ApplicationContentsObserver;
  class DestructionObserver;

  // Represents a ApplicationContents node in a tree of ApplicationContents structure.
  //
  // Two ApplicationContents with separate FrameTrees can be connected by
  // outer/inner relationship using this class. Note that their FrameTrees
  // still remain disjoint.
  // The parent is referred to as "outer ApplicationContents" and the descendents are
  // referred to as "inner ApplicationContents".
  // For each inner ApplicationContents, the outer ApplicationContents will have a
  // corresponding FrameTreeNode.
  // class ApplicationContentsTreeNode final : public FrameTreeNode::Observer {
  //  public:
  //   explicit ApplicationContentsTreeNode(ApplicationContents* current_application_contents);
  //   ~ApplicationContentsTreeNode() final;

  //   void ConnectToOuterApplicationContents(ApplicationContents* outer_application_contents,
  //                                  RenderFrameHostImpl* outer_contents_frame);

  //   ApplicationContents* outer_application_contents() const { return outer_application_contents_; }
  //   int outer_contents_frame_tree_node_id() const {
  //     return outer_contents_frame_tree_node_id_;
  //   }
  //   FrameTreeNode* OuterContentsFrameTreeNode() const;

  //   ApplicationContents* focused_application_contents() { return focused_application_contents_; }
  //   void SetFocusedApplicationContents(ApplicationContents* application_contents);

  //   // Returns the inner ApplicationContents within |frame|, if one exists, or nullptr
  //   // otherwise.
  //   ApplicationContents* GetInnerApplicationContentsInFrame(const FrameTreeNode* frame);

  //   const std::vector<ApplicationContents*>& inner_application_contents() const;

  //  private:
  //   void AttachInnerApplicationContents(ApplicationContents* inner_application_contents);
  //   void DetachInnerApplicationContents(ApplicationContents* inner_application_contents);

  //   // FrameTreeNode::Observer implementation.
  //   void OnFrameTreeNodeDestroyed(FrameTreeNode* node) final;

  //   // The ApplicationContents that owns this ApplicationContentsTreeNode.
  //   ApplicationContents* const current_application_contents_;

  //   // The outer ApplicationContents of |current_application_contents_|, or nullptr if
  //   // |current_application_contents_| is the outermost ApplicationContents.
  //   ApplicationContents* outer_application_contents_;

  //   // The ID of the FrameTreeNode in the |outer_application_contents_| that hosts
  //   // |current_application_contents_| as an inner ApplicationContents.
  //   int outer_contents_frame_tree_node_id_;

  //   // List of inner ApplicationContents that we host.
  //   std::vector<ApplicationContents*> inner_application_contents_;

  //   // Only the root node should have this set. This indicates the ApplicationContents
  //   // whose frame tree has the focused frame. The ApplicationContents tree could be
  //   // arbitrarily deep.
  //   ApplicationContents* focused_application_contents_;
  // };

  // See ApplicationContents::Create for a description of these parameters.
  explicit ApplicationContents();//ApplicationContents* application_contents);


  // Clears a pending contents that has been closed before being shown.
  void OnApplicationContentsDestroyed(ApplicationContents* application_contents);

  // Creates and adds to the map a destruction observer watching |application_contents|.
  // No-op if such an observer already exists.
  void AddDestructionObserver(ApplicationContents* application_contents);

  // Deletes and removes from the map a destruction observer
  // watching |application_contents|. No-op if there is no such observer.
  void RemoveDestructionObserver(ApplicationContents* application_contents);

  // Traverses all the RenderFrameHosts in the FrameTree and creates a set
  // all the unique ApplicationWindowHostViews.
  //std::set<ApplicationWindowHostView*> GetApplicationWindowHostViewsInTree();

  // Called with the result of a DownloadImage() request.
  //void OnDidDownloadImage(ImageDownloadCallback callback,
  //                        int id,
  //                        const GURL& image_url,
  //                        int32_t http_status_code,
  //                        const std::vector<SkBitmap>& images,
  //                        const std::vector<gfx::Size>& original_image_sizes);

  // Callback function when showing JavaScript dialogs. Takes in a routing ID
  // pair to identify the RenderFrameHost that opened the dialog, because it's
  // possible for the RenderFrameHost to be deleted by the time this is called.
  //void OnDialogClosed(int render_process_id,
  //                    int render_frame_id,
  //                    IPC::Message* reply_msg,
  //                    bool dialog_was_suppressed,
  //                    bool success,
  //                    const base::string16& user_input);

  // IPC message handlers.
  //void OnThemeColorChanged(RenderFrameHostImpl* source, SkColor theme_color);
  //void OnDidLoadResourceFromMemoryCache(RenderFrameHostImpl* source,
  //                                      const GURL& url,
  //                                     const std::string& http_request,
  //                                    const std::string& mime_type,
  //                                   ResourceType resource_type);
  //void OnDidDisplayInsecureContent(RenderFrameHostImpl* source);
  //void OnDidContainInsecureFormAction(RenderFrameHostImpl* source);
  //void OnDidRunInsecureContent(RenderFrameHostImpl* source,
  //                             const GURL& security_origin,
  //                             const GURL& target_url);
  //void OnDidDisplayContentWithCertificateErrors(RenderFrameHostImpl* source);
  //void OnDidRunContentWithCertificateErrors(RenderFrameHostImpl* source);
  //void OnDocumentLoadedInFrame(RenderFrameHostImpl* source);
  //void OnDidFinishLoad(RenderFrameHostImpl* source, const GURL& url);
  //void OnGoToEntryAtOffset(ApplicationWindowHost* source, int offset);
  void OnUpdateZoomLimits(ApplicationWindowHost* source,
                          int minimum_percent,
                          int maximum_percent);
  void OnPageScaleFactorChanged(ApplicationWindowHost* source,
                                float page_scale_factor);
  //void OnEnumerateDirectory(ApplicationWindowHost* source,
  //                          int request_id,
  //                          const base::FilePath& path);

  //void OnRegisterProtocolHandler(RenderFrameHostImpl* source,
  //                               const std::string& protocol,
  //                               const GURL& url,
  //                               const base::string16& title,
  //                               bool user_gesture);
  //void OnUnregisterProtocolHandler(RenderFrameHostImpl* source,
  //                                 const std::string& protocol,
  //                                 const GURL& url,
  //                                 bool user_gesture);
  //void OnFindReply(RenderFrameHostImpl* source,
  //                 int request_id,
  //                 int number_of_matches,
  //                 const gfx::Rect& selection_rect,
  //                 int active_match_ordinal,
  //                 bool final_update);
//#if defined(OS_ANDROID)
//  void OnFindMatchRectsReply(RenderFrameHostImpl* source,
//                             int version,
//                             const std::vector<gfx::RectF>& rects,
//                             const gfx::RectF& active_rect);
//  void OnGetNearestFindResultReply(RenderFrameHostImpl* source,
//                                   int request_id,
//                                   float distance);
//  void OnOpenDateTimeDialog(
//      ApplicationWindowHost* source,
//      const ViewHostMsg_DateTimeDialogValue_Params& value);
//#endif
//  void OnDomOperationResponse(RenderFrameHostImpl* source,
//                              const std::string& json_string);
//  void OnAppCacheAccessed(ApplicationWindowHost* source,
//                          const GURL& manifest_url,
//                          bool blocked_by_policy);
//  void OnUpdatePageImportanceSignals(RenderFrameHostImpl* source,
//                                     const PageImportanceSignals& signals);
//  void OnUpdateFaviconURL(RenderFrameHostImpl* source,
//                          const std::vector<FaviconURL>& candidates);
  void OnFirstVisuallyNonEmptyPaint(ApplicationWindowHost* source);
//  void OnShowValidationMessage(ApplicationWindowHost* source,
//                               const gfx::Rect& anchor_in_root_view,
//                               const base::string16& main_text,
//                               const base::string16& sub_text);
//  void OnHideValidationMessage(ApplicationWindowHost* source);
//  void OnMoveValidationMessage(ApplicationWindowHost* source,
//                               const gfx::Rect& anchor_in_root_view);

  // Called by derived classes to indicate that we're no longer waiting for a
  // response. Will inform |delegate_| of the change in status so that it may,
  // for example, update the throbber.
  void SetNotWaitingForResponse();

  // Inner ApplicationContents Helpers -------------------------------------------------
  //
  // These functions are helpers in managing a hierarchy of ApplicationContents
  // involved in rendering inner ApplicationContents.

  // When multiple ApplicationContents are present within a tab or window, a single one
  // is focused and will route keyboard events in most cases to a ApplicationWindow
  // contained within it. |GetFocusedApplicationContents()|'s main frame widget will
  // receive page focus and blur events when the containing window changes focus
  // state.

  // Returns true if |this| is the focused ApplicationContents or an ancestor of the
  // focused ApplicationContents.
  //bool ContainsOrIsFocusedApplicationContents();

  // Returns the root of the ApplicationContents tree.
  //ApplicationContents* GetOutermostApplicationContents();

  // Walks up the outer ApplicationContents chain and focuses the FrameTreeNode where
  // each inner ApplicationContents is attached.
  //void FocusOuterAttachmentFrameChain();

  // Navigation helpers --------------------------------------------------------
  //
  // These functions are helpers for Navigate() and DidNavigate().

  // Handles post-navigation tasks in DidNavigate AFTER the entry has been
  // committed to the navigation controller. Note that the navigation entry is
  // not provided since it may be invalid/changed after being committed. The
  // current navigation entry is in the NavigationController at this point.

  // Helper for CreateNewWidget/CreateNewFullscreenWidget.
  //void CreateNewWindow(int32_t render_process_id,
  //                     int32_t route_id,
  //                     bool is_fullscreen,
   //                    mojom::WidgetPtr widget,
//                       blink::WebPopupType popup_type);

  // Helper for ShowCreatedWidget/ShowCreatedFullscreenWidget.
//  void ShowCreatedWindow(int process_id,
//                         int route_id,
//                         bool is_fullscreen,
//                         const gfx::Rect& initial_rect);

  // Finds the new ApplicationWindowHost and returns it. Note that this can only be
  // called once as this call also removes it from the internal map.
  ApplicationWindowHostView* GetCreatedWindow(int process_id, int route_id);

  // Finds the new ApplicationContents by |main_frame_widget_route_id|, initializes
  // it for renderer-initiated creation, and returns it. Note that this can only
  // be called once as this call also removes it from the internal map.
  ApplicationContents* GetCreatedContents(int process_id,
                                          int main_frame_widget_route_id);

  // Sends a Page message IPC.
  //void SendPageMessage(IPC::Message* msg);

  //void SetOpenerForNewContents(FrameTreeNode* opener, bool opener_suppressed);

  // Tracking loading progress -------------------------------------------------

  // Resets the tracking state of the current load progress.
  void ResetLoadProgressState();

  // Notifies the delegate that the load progress was updated.
  void SendChangeLoadProgress();

  // Notifies the delegate of a change in loading state.
  // |details| is used to provide details on the load that just finished
  // (but can be null if not applicable).
  // |due_to_interstitial| is true if the change in load state occurred because
  // an interstitial page started showing/proceeded.
  void LoadingStateChanged(bool to_different_document,
                           bool due_to_interstitial,
                           LoadNotificationDetails* details);

  // Misc non-view stuff -------------------------------------------------------

  // Sets the history for a specified ApplicationWindowHost to |history_length|
  // entries, with an offset of |history_offset|.
  //void SetHistoryOffsetAndLengthForView(ApplicationWindowHost* application_window_host,
  //                                      int history_offset,
  //                                      int history_length);

  void NotifySwapped(ApplicationFrame* old_window,
                     ApplicationFrame* new_window,
                     bool is_main_frame) override;
  void NotifyMainFrameSwapped(
    ApplicationFrame* old_host,
    ApplicationFrame* new_host) override;

  void NotifyFrameSwapped(ApplicationFrame* old_frame,
                          ApplicationFrame* new_frame) override;

  // Helper functions for sending notifications.
  void NotifyViewSwapped(ApplicationWindowHost* old_host, ApplicationWindowHost* new_host);
  //void NotifyFrameSwapped(RenderFrameHost* old_host, RenderFrameHost* new_host);
  void NotifyDisconnected();

  //void SetEncoding(const std::string& encoding);

  // TODO(creis): This should take in a FrameTreeNode to know which node's
  // render manager to return.  For now, we just return the root's.
  //RenderFrameHostManager* GetRenderManager() const;

  // Removes browser plugin embedder if there is one.
  //void RemoveBrowserPluginEmbedder();

  // Helper function to invoke ApplicationContentsDelegate::GetSizeForNewApplicationWindow().
  gfx::Size GetSizeForNewApplicationWindow(bool is_main_frame);

  //void OnFrameRemoved(RenderFrameHost* render_frame_host);

  // Helper method that's called whenever |preferred_size_| or
  // |preferred_size_for_capture_| changes, to propagate the new value to the
  // |delegate_|.
  void OnPreferredSizeChanged(const gfx::Size& old_size);

  void OnUserInteraction(const blink::WebInputEvent::Type type);

  // Removes a registered ApplicationContentsBindingSet by interface name.
  void RemoveBindingSet(const std::string& interface_name);

  // Sets the visibility of immediate child views, i.e. views whose parent view
  // is that of the main frame.
  void SetVisibilityForChildViews(bool visible);

  //bool InitApplicationWindow(const CreateParams& params, ApplicationWindowHost* application_window_host);

  bool CreateApplicationWindowForApplicationContents(
        ApplicationWindowHost* application_window_host);
  void CreateApplicationWindowHostViewForApplicationContents(
    ApplicationWindowHost* application_window_host);

  void CreateNewWindowImpl(int32_t render_process_id,
                           int32_t route_id,
                           bool is_fullscreen,
                           blink::WebPopupType popup_type);

  void ShowCreatedWindowImpl(int process_id,
                             int route_id,
                             bool is_fullscreen,
                             const gfx::Rect& initial_rect);

  ApplicationContents* GetFocusedApplicationContents();

  ApplicationWindowHost* application_window_host() const {
    return application_window_host_;
  }

  void InitAfterLaunch(const CreateParams& params, ApplicationProcessHost* app_process_host, bool result);
  void OnNavigationCompletion(const CreateParams& params, int result, NavigationEntry* entry);

  // Reattaches this inner ApplicationContents to its outer ApplicationContents.
  //void ReattachToOuterApplicationContentsFrame();

  // A helper for clearing the link status bubble after navigating away.
  // See also UpdateTargetURL.
  //void ClearTargetURL();

  //class AXTreeSnapshotCombiner;
  //void RecursiveRequestAXTreeSnapshotOnFrame(FrameTreeNode* root_node,
  //                                           AXTreeSnapshotCombiner* combiner,
  //                                           ui::AXMode ax_mode);

  // Data for core operation ---------------------------------------------------

  // Delegate for notifying our owner about stuff. Not owned by us.
  ApplicationContentsDelegate* delegate_;

  // Handles the back/forward list and loading.
  //NavigationControllerImpl controller_;

  // The corresponding view.
  std::unique_ptr<ApplicationContentsView> view_;

  // The view of the RVHD. Usually this is our ApplicationContentsView implementation,
  // but if an embedder uses a different ApplicationContentsView, they'll need to
  // provide this.
  ApplicationWindowHostDelegateView* application_window_host_delegate_view_;

  // Tracks created ApplicationContents objects that have not been shown yet. They
  // are identified by the process ID and routing ID passed to CreateNewWindow.
  typedef std::pair<int, int> ProcessRoutingIdPair;
  std::map<ProcessRoutingIdPair, ApplicationContents*> pending_contents_;

  // This map holds widgets that were created on behalf of the renderer but
  // haven't been shown yet.
  std::map<ProcessRoutingIdPair, ApplicationWindowHostView*> pending_widget_views_;

  std::map<ApplicationContents*, std::unique_ptr<DestructionObserver>>
      destruction_observers_;

  // A list of observers notified when page state changes. Weak references.
  // This MUST be listed above frame_tree_ since at destruction time the
  // latter might cause ApplicationWindowHost's destructor to call us and we might use
  // the observer list then.
  //base::ObserverList<ApplicationContentsObserver> observers_;
  std::vector<base::WeakPtr<ApplicationContentsObserver>> observers_;

  // Associated interface binding sets attached to this ApplicationContents.
  std::map<std::string, ApplicationContentsBindingSet*> binding_sets_;

  // True if this tab was opened by another tab. This is not unset if the opener
  // is closed.
  bool created_with_opener_;

  // Helper classes ------------------------------------------------------------

  // Manages the frame tree of the page and process swaps in each node.
  //FrameTree frame_tree_;

  // Contains information about the ApplicationContents tree structure.
  //ApplicationContentsTreeNode node_;

  // SaveContainer, lazily created.
  //scoped_refptr<SaveContainer> save_container_;

  // Manages/coordinates multi-process find-in-page requests. Created lazily.
  //std::unique_ptr<FindRequestManager> find_request_manager_;

  // Data for loading state ----------------------------------------------------

  // Indicates whether the current load is to a different document. Only valid
  // if |is_loading_| is true and only tracks loads in the main frame.
  //bool is_load_to_different_document_;

  // Indicates if the tab is considered crashed.
  base::TerminationStatus crashed_status_;
  int crashed_error_code_;

  // Whether this ApplicationContents is waiting for a first-response for the
  // main resource of the page. This controls whether the throbber state is
  // "waiting" or "loading."
  bool waiting_for_response_;

  // The current load state and the URL associated with it.
  net::LoadStateWithParam load_state_;
  base::string16 load_state_host_;

  base::TimeTicks loading_last_progress_update_;

  // Upload progress, for displaying in the status bar.
  // Set to zero when there is no significant upload happening.
  uint64_t upload_size_;
  uint64_t upload_position_;

  // Tracks that this ApplicationContents needs to unblock requests to the renderer.
  // See ResumeLoadingCreatedApplicationContents.
  bool is_resume_pending_;

  // The interstitial page currently shown, if any. Not owned by this class: the
  // InterstitialPage is self-owned and deletes itself asynchronously when
  // hidden. Because it may outlive this ApplicationContents, it enters a disabled state
  // when hidden or preparing for destruction.
  InterstitialPageImpl* interstitial_page_;

  // Data for current page -----------------------------------------------------

  // When a title cannot be taken from any entry, this title will be used.
  base::string16 page_title_when_no_navigation_entry_;

  // When a navigation occurs, we record its contents MIME type. It can be
  // used to check whether we can do something for some special contents.
  std::string contents_mime_type_;

  // The last reported character encoding, not canonicalized.
  std::string last_reported_encoding_;

  // The canonicalized character encoding.
  std::string canonical_encoding_;

  // Whether the initial empty page has been accessed by another page, making it
  // unsafe to show the pending URL. Usually false unless another window tries
  // to modify the blank page.  Always false after the first commit.
  bool has_accessed_initial_document_;

  // The theme color for the underlying document as specified
  // by theme-color meta tag.
  //SkColor theme_color_;

  // The last published theme color.
  //SkColor last_sent_theme_color_;

  // Whether the first visually non-empty paint has occurred.
  bool did_first_visually_non_empty_paint_;

  // Data for misc internal state ----------------------------------------------

  // When > 0, the ApplicationContents is currently being captured (e.g., for
  // screenshots or mirroring); and the underlying ApplicationWindowHost should not
  // be told it is hidden.
  int capturer_count_;

  // The visibility of the ApplicationContents. Initialized from
  // |CreateParams::initially_hidden|. Updated from
  // UpdateApplicationContentsVisibility(), WasShown(), WasHidden(), WasOccluded().
  Visibility visibility_ = Visibility::VISIBLE;

  // Whether there has been a call to UpdateApplicationContentsVisibility(VISIBLE).
  bool did_first_set_visible_ = false;

  // See getter above.
  bool is_being_destroyed_;

  // Keep track of whether this ApplicationContents is currently iterating over its list
  // of observers, during which time it should not be deleted.
  bool is_notifying_observers_;

  // Indicates whether we should notify about disconnection of this
  // ApplicationContents. This is used to ensure disconnection notifications only
  // happen if a connection notification has happened and that they happen only
  // once.
  bool notify_disconnection_;

    // Set to true when there is an active JavaScript dialog showing.
  //bool is_showing_javascript_dialog_ = false;

  // Set to true when there is an active "before unload" dialog.  When true,
  // we've forced the throbber to start in Navigate, and we need to remember to
  // turn it off in OnJavaScriptMessageBoxClosed if the navigation is canceled.
  bool is_showing_before_unload_dialog_;

  // Settings that get passed to the renderer process.
  common::RendererPreferences renderer_preferences_;

  // The time that this ApplicationContents was last made active. The initial value is
  // the ApplicationContents creation time.
  base::TimeTicks last_active_time_;

  // The time that this ApplicationContents last received an 'interactive' input event
  // from the user. Interactive input events are things like mouse clicks and
  // keyboard input, but not mouse wheel scrolling or mouse moves.
  base::TimeTicks last_interactive_input_event_time_;

  // See description above setter.
  bool closed_by_user_gesture_;

  // Minimum/maximum zoom percent.
  int minimum_zoom_percent_;
  int maximum_zoom_percent_;

  // Used to correctly handle integer zooming through a smooth scroll device.
  float zoom_scroll_remainder_;

  // The intrinsic size of the page.
  gfx::Size preferred_size_;

  // The preferred size for content screen capture.  When |capturer_count_| > 0,
  // this overrides |preferred_size_|.
  gfx::Size preferred_size_for_capture_;

  // Size set by a top-level frame with auto-resize enabled. This is needed by
  // out-of-process iframes for their visible viewport size.
  gfx::Size auto_resize_size_;

  // When device emulation is enabled, override the size of current and newly
  // created render views/widgets.
  gfx::Size device_emulation_size_;
  gfx::Size view_size_before_emulation_;

//#if defined(OS_ANDROID)
  // Date time chooser opened by this tab.
  // Only used in Android since all other platforms use a multi field UI.
//  std::unique_ptr<DateTimeChooserAndroid> date_time_chooser_;
//#endif

  // Holds information about a current color chooser dialog, if one is visible.
  //class ColorChooser;
  //std::unique_ptr<ColorChooser> color_chooser_;

  // Manages the embedder state for browser plugins, if this ApplicationContents is an
  // embedder; NULL otherwise.
  //std::unique_ptr<BrowserPluginEmbedder> browser_plugin_embedder_;
  // Manages the guest state for browser plugin, if this ApplicationContents is a guest;
  // NULL otherwise.
  //std::unique_ptr<BrowserPluginGuest> browser_plugin_guest_;

//#if BUILDFLAG(ENABLE_PLUGINS)
  // Manages the whitelist of plugin content origins exempt from power saving.
//  std::unique_ptr<PluginContentOriginWhitelist>
//      plugin_content_origin_whitelist_;
//#endif

  // This must be at the end, or else we might get notifications and use other
  // member variables that are gone.
  NotificationRegistrar registrar_;

  // All live ApplicationWindowHost that are created by this object and may
  // outlive it.
  std::set<ApplicationWindowHost*> created_windows_;

  // substitute for RenderManager->current_host
  ApplicationProcessHost* application_process_host_;

  ApplicationWindowHost* application_window_host_;

  // a owned version of the original current_host from RenderManager and RenderFrame
  //std::unique_ptr<ApplicationWindowHost> owned_application_window_host_;

  // Process id of the shown fullscreen widget, or kInvalidUniqueID if there is
  // no fullscreen widget.
  int fullscreen_widget_process_id_;

  // Routing id of the shown fullscreen widget or MSG_ROUTING_NONE otherwise.
  int fullscreen_widget_routing_id_;

  // At the time the fullscreen widget was being shut down, did it have focus?
  // This is used to restore focus to the ApplicationContentsView after both: 1) the
  // fullscreen widget is destroyed, and 2) the ApplicationContentsDelegate has
  // completed making layout changes to effect an exit from fullscreen mode.
  bool fullscreen_widget_had_focus_at_shutdown_;

  // Whether this ApplicationContents is responsible for displaying a subframe in a
  // different process from its parent page.
  //bool is_subframe_;

  // When a new tab is created asynchronously, stores the OpenURLParams needed
  // to continue loading the page once the tab is ready.
  //std::unique_ptr<OpenURLParams> delayed_open_url_params_;
  std::unique_ptr<GURL> delayed_open_url_;

  // Whether overscroll should be unconditionally disabled.
  bool force_disable_overscroll_content_;

  // Whether the last JavaScript dialog shown was suppressed. Used for testing.
  //bool last_dialog_suppressed_;

  device::mojom::GeolocationContextPtr geolocation_context_;

  std::unique_ptr<WakeLockContextHost> wake_lock_context_host_;

  device::mojom::WakeLockPtr renderer_wake_lock_;

  // We have no color chooser here
  //service_manager::BinderRegistry registry_;

  //mojo::BindingSet<blink::mojom::ColorChooserFactory>
  //    color_chooser_factory_bindings_;

//#if defined(OS_ANDROID)
//  std::unique_ptr<NFCHost> nfc_host_;
//#endif

  std::unique_ptr<ScreenOrientationProvider> screen_orientation_provider_;

  //std::unique_ptr<ManifestManagerHost> manifest_manager_host_;

  // The accessibility mode for all frames. This is queried when each frame
  // is created, and broadcast to all frames when it changes.
  ui::AXMode accessibility_mode_;

  // Monitors power levels for audio streams associated with this ApplicationContents.
  std::unique_ptr<AudioStreamMonitor> audio_stream_monitor_;

  // Created on-demand to mute all audio output from this ApplicationContents.
  std::unique_ptr<ApplicationContentsAudioMuter> audio_muter_;

  size_t bluetooth_connected_device_count_;

  // Notifies ResourceDispatcherHostImpl of various events related to loading.
  //std::unique_ptr<LoaderIOThreadNotifier> loader_io_thread_notifier_;

  // Manages media players, CDMs, and power save blockers for media.
  std::unique_ptr<MediaApplicationContentsObserver> media_application_contents_observer_;

#if !defined(OS_ANDROID)
  std::unique_ptr<HostZoomMapObserver, HostThread::DeleteOnIOThread> host_zoom_map_observer_;
#endif  // !defined(OS_ANDROID)

  std::unique_ptr<ApplicationWindowHostInputEventRouter> awh_input_event_router_;

  //PageImportanceSignals page_importance_signals_;

#if !defined(OS_ANDROID)
  bool page_scale_factor_is_one_;
#endif  // !defined(OS_ANDROID)

  // TextInputManager tracks the IME-related state for all the
  // ApplicationWindowHostViews on this ApplicationContents. Only exists on the outermost
  // ApplicationContents and is automatically destroyed when a ApplicationContents becomes an
  // inner ApplicationContents by attaching to an outer ApplicationContents. Then the
  // IME-related state for ApplicationWindowHosts on the inner ApplicationContents is tracked
  // by the TextInputManager in the outer ApplicationContents.
  std::unique_ptr<TextInputManager> text_input_manager_;

  // Stores the ApplicationWindowHost that currently holds a mouse lock or nullptr if
  // there's no ApplicationWindowHost holding a lock.
  ApplicationWindowHost* mouse_lock_widget_ = nullptr;

  // Stores the ApplicationWindowHost that currently holds a keyboard lock or nullptr
  // if no ApplicationWindowHost has the keyboard locked.
  ApplicationWindowHost* keyboard_lock_widget_ = nullptr;

  // Indicates whether the escape key is one of the requested keys to be locked.
  // This information is used to drive the browser UI so the correct exit
  // instructions are displayed to the user in fullscreen mode.
  bool esc_key_locked_ = false;

#if defined(OS_ANDROID)
  std::unique_ptr<service_manager::InterfaceProvider> java_interfaces_;
#endif

  // Whether this ApplicationContents is for content overlay.
  bool is_overlay_content_;

  bool showing_context_menu_;

  int currently_playing_video_count_ = 0;
  VideoSizeMap cached_video_sizes_;

  bool has_persistent_video_ = false;

  bool was_ever_audible_ = false;

  ResourceContext* resource_context_;

  Domain* parent_;

  Application* application_;

  RouteResolver* url_resolver_;

  std::unique_ptr<RouteController> url_controller_;
  
  std::unique_ptr<NavigationController> navigation_controller_;

  GURL url_;

  // Helper variable for resolving races in UpdateTargetURL / ClearTargetURL.
  ApplicationWindowHost* view_that_set_last_target_url_ = nullptr;

  gfx::Image cached_favicon_;

  mutable bool is_waiting_for_close_ack_;

  base::Lock observers_lock_;

  //std::string page_name_;
  //base::string16 page_name_utf16_;

  // Whether we should override user agent in new tabs.
//  bool should_override_user_agent_in_new_tabs_ = false;

  base::WeakPtrFactory<ApplicationContents> loading_weak_factory_;
  base::WeakPtrFactory<ApplicationContents> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(ApplicationContents);
};

// Dangerous methods which should never be made part of the public API, so we
// grant their use only to an explicit friend list (c++ attorney/client idiom).
class CONTENT_EXPORT ApplicationContents::FriendWrapper {
 public:
  using CreatedCallback = base::RepeatingCallback<void(ApplicationContents*)>;

 private:
  friend class ApplicationContentsAddedObserver;
  
  FriendWrapper();  // Not instantiable.

  // Adds/removes a callback called on creation of each new WebContents.
  static void AddCreatedCallbackForTesting(const CreatedCallback& callback);
  static void RemoveCreatedCallbackForTesting(const CreatedCallback& callback);

  DISALLOW_COPY_AND_ASSIGN(FriendWrapper);
};

}


#endif
