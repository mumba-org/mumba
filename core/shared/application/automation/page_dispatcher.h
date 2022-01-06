// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_APPLICATION_PAGE_DISPATCHER_H_
#define MUMBA_APPLICATION_PAGE_DISPATCHER_H_

#include "core/shared/common/mojom/automation.mojom.h"

#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/heap/heap_allocator.h"
#include "third_party/blink/renderer/core/loader/frame_loader_types.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource.h"
#include "third_party/blink/public/web/web_window_features.h"

namespace blink {
class LocalFrame;  
class DocumentLoader;
class Resource;
class SharedBuffer;
class Document;
class ScheduledNavigation;
class WebLocalFrame;
namespace probe {
class RecalculateStyle;
class UpdateLayout;
}  // namespace probe
}

namespace v8_inspector {
class String16;  
}

namespace service_manager {
class InterfaceProvider;  
}

namespace IPC {
class SyncChannel;
}

namespace application {
class PageInstance;
class ApplicationWindowDispatcher;
class InspectorPageAgentImpl;
class ApplicationThread;
class AutomationContext;

class PageDispatcher : public automation::Page {
public:
  enum ResourceType {
    kDocumentResource,
    kStylesheetResource,
    kImageResource,
    kFontResource,
    kMediaResource,
    kScriptResource,
    kTextTrackResource,
    kXHRResource,
    kFetchResource,
    kEventSourceResource,
    kWebSocketResource,
    kManifestResource,
    kOtherResource
  };

  static ResourceType ToResourceType(const blink::Resource::Type);
  static String ResourceTypeJson(ResourceType);
  static automation::ResourceType ToAutomationResourceType(ResourceType);
  static String CachedResourceTypeJson(const blink::Resource&);
  static blink::KURL UrlWithoutFragment(const blink::KURL& url);

  static bool SharedBufferContent(
    scoped_refptr<const blink::SharedBuffer> buffer,
    const String& mime_type,
    const String& text_encoding_name,
    String* result,
    bool* base64_encoded);

  static bool CachedResourceContent(blink::Resource* cached_resource,
                                    String* result,
                                    bool* base64_encoded);
  
  static std::vector<automation::SearchMatchPtr> SearchInTextByLines(
    const v8_inspector::String16& text,
    const v8_inspector::String16& query, 
    bool case_sensitive,
    bool is_regex);

  static blink::HeapVector<blink::Member<blink::Document>> ImportsForFrame(blink::LocalFrame* frame);

  static void Create(automation::PageRequest request, ApplicationWindowDispatcher* dispatcher, PageInstance* page_instance);

  PageDispatcher(automation::PageRequest request, ApplicationWindowDispatcher* dispatcher, PageInstance* page_instance);
  PageDispatcher(ApplicationWindowDispatcher* dispatcher, PageInstance* page_instance);
  ~PageDispatcher() override;

  void Init(IPC::SyncChannel* channel);
  void Bind(automation::PageAssociatedRequest request);

  // Page
  void Register(int32_t application_id) override;
  void Enable() override;
  void Disable() override;
  void AddScriptToEvaluateOnNewDocument(const std::string& source, AddScriptToEvaluateOnNewDocumentCallback callback) override;
  void RemoveScriptToEvaluateOnNewDocument(const std::string& identifier) override;
  void SetAutoAttachToCreatedPages(bool auto_attach) override;
  void SetLifecycleEventsEnabled(bool enabled) override;
  void Reload(bool ignore_cache, const std::string& script_to_evaluate_on_load) override;
  void SetAdBlockingEnabled(bool enabled) override;
  void Navigate(const std::string& url, const std::string& referrer, automation::TransitionType transition_type, NavigateCallback callback) override;
  void StopLoading() override;
  void GetNavigationHistory(GetNavigationHistoryCallback callback) override;
  void NavigateToHistoryEntry(int32_t entry_id) override;
  void GetCookies(GetCookiesCallback callback) override;
  void DeleteCookie(const std::string& cookie_name, const std::string& url) override;
  void GetResourceTree(GetResourceTreeCallback callback) override;
  void GetFrameTree(GetFrameTreeCallback callback) override;
  void GetResourceContent(const std::string& frame_id, const std::string& url, GetResourceContentCallback callback) override;
  void SearchInResource(const std::string& frame_id, const std::string& url, const std::string& query, bool case_sensitive, bool is_regex, SearchInResourceCallback callback) override;
  void SetDocumentContent(const std::string& frame_id, const std::string& html) override;
  void SetDeviceMetricsOverride(int32_t width, int32_t height, int32_t device_scale_factor, bool mobile, int32_t scale, int32_t screen_width, int32_t screen_height, int32_t position_x, int32_t position_y, bool dont_set_visible_size, automation::ScreenOrientationPtr screen_orientation, automation::ViewportPtr viewport) override;
  void ClearDeviceMetricsOverride() override;
  void SetGeolocationOverride(int32_t latitude, int32_t longitude, int32_t accuracy) override;
  void ClearGeolocationOverride() override;
  void SetDeviceOrientationOverride(int32_t alpha, int32_t beta, int32_t gamma) override;
  void ClearDeviceOrientationOverride() override;
  void SetTouchEmulationEnabled(bool enabled, const std::string& configuration) override;
  void CaptureScreenshot(automation::FrameFormat format, int32_t quality, automation::ViewportPtr clip, bool from_surface, CaptureScreenshotCallback callback) override;
  void PrintToPDF(bool landscape, bool display_header_footer, bool print_background, float scale, float paper_width, float paper_height, float margin_top, float margin_bottom, float margin_left, float margin_right, const base::Optional<std::string>& page_ranges, bool ignore_invalid_page_ranges, PrintToPDFCallback callback) override;
  void StartScreencast(automation::FrameFormat format, int32_t quality, int32_t max_width, int32_t max_height, int32_t every_nth_frame) override;
  void StopScreencast() override;
  void SetBypassCSP(bool enable) override;
  void ScreencastFrameAck(int32_t session_id) override;
  void HandleJavaScriptDialog(bool accept, const std::string& prompt_text) override;
  void GetAppManifest(GetAppManifestCallback callback) override;
  void RequestAppBanner() override;
  void GetLayoutMetrics(GetLayoutMetricsCallback callback) override;
  void CreateIsolatedWorld(const std::string& frame_id, const base::Optional<std::string>& world_name, bool grant_universal_access, CreateIsolatedWorldCallback callback) override;
  void BringToFront() override;
  void SetDownloadBehavior(const std::string& behavior, const base::Optional<std::string>& download_path) override;
  void Close() override;

  automation::PageClient* GetClient() const;

  PageInstance* page_instance() const {
    return page_instance_;
  }

  void OnWebFrameCreated(blink::WebLocalFrame* web_frame);
  
private:
  friend class InspectorPageAgentImpl;
  friend class ApplicationThread;
  friend class AutomationContext;

  blink::LocalFrame* GetMainFrame();

  void DispatchFrameAttached(blink::LocalFrame* frame, blink::LocalFrame* parent_frame);
  void DispatchDomContentEventFired(blink::LocalFrame* frame);
  void DispatchFrameClearedScheduledNavigation(blink::LocalFrame* frame);
  void DispatchFrameDetached(blink::LocalFrame* frame);
  void DispatchFrameNavigated(blink::LocalFrame* frame);
  void DispatchFrameResized();
  void DispatchFrameScheduledNavigation(blink::LocalFrame* frame, int32_t delay, automation::NavigationReason reason, const std::string& url);
  void DispatchFrameStartedLoading(blink::LocalFrame* frame);
  void DispatchFrameStoppedLoading(blink::LocalFrame* frame);
  void DispatchInterstitialHidden();
  void DispatchInterstitialShown();
  void DispatchJavascriptDialogClosed(bool result, const std::string& user_input);
  void DispatchJavascriptDialogOpening(const std::string& url, const std::string& message, automation::DialogType type, bool has_browser_handler, const base::Optional<std::string>& default_prompt);
  void DispatchLifecycleEvent(
    blink::LocalFrame* frame,
    blink::DocumentLoader* loader,
    const char* name,
    double timestamp); 
  void DispatchLoadEventFired(blink::LocalFrame* frame);
  void DispatchNavigatedWithinDocument(blink::LocalFrame* frame, const std::string& url);
  void DispatchScreencastFrame(const std::string& base64_data, automation::ScreencastFrameMetadataPtr metadata, int32_t session_id);
  void DispatchScreencastVisibilityChanged(bool visible);
  void DispatchWindowOpen(const std::string& url, const std::string& window_name, const std::vector<std::string>& window_features, bool user_gesture);

  void GetResourceContentAfterResourcesContentLoaded(
    const std::string& frame_id, 
    const std::string& url,
    GetResourceContentCallback callback);

  void SearchContentAfterResourcesContentLoaded(
      const std::string& frame_id,
      const std::string& url,
      const std::string& query,
      bool case_sensitive,
      bool is_regex,
      SearchInResourceCallback callback);

  // FIXME: this needs to get plugged and called by the observed frames (probably as a FrameClient/Delegate or Observer)
  
  void DidClearDocumentOfWindowObject(blink::LocalFrame* frame);
  void DidNavigateWithinDocument(blink::LocalFrame*);
  void DomContentLoadedEventFired(blink::LocalFrame*);
  void LoadEventFired(blink::LocalFrame*);
  void WillCommitLoad(blink::LocalFrame*, blink::DocumentLoader* loader);
  void FrameAttachedToParent(blink::LocalFrame*);
  void FrameDetachedFromParent(blink::LocalFrame*);
  void FrameStartedLoading(blink::LocalFrame*, blink::FrameLoadType);
  void FrameStoppedLoading(blink::LocalFrame*);
  void FrameScheduledNavigation(blink::LocalFrame*, blink::ScheduledNavigation*);
  void FrameClearedScheduledNavigation(blink::LocalFrame*);
  void WillRunJavaScriptDialog();
  void DidRunJavaScriptDialog();
  void DidResizeMainFrame();
  void DidChangeViewport();
  void PaintTiming(blink::Document*, const char* name, double timestamp);
  void Will(const blink::probe::UpdateLayout&);
  void Did(const blink::probe::UpdateLayout&);
  void Will(const blink::probe::RecalculateStyle&);
  void Did(const blink::probe::RecalculateStyle&);
  void WindowOpen(blink::Document*,
                  const String&,
                  const AtomicString&,
                  const blink::WebWindowFeatures&,
                  bool);

  void FinishReload();
  void PageLayoutInvalidated(bool resized);

  automation::FramePtr BuildObjectForFrame(blink::LocalFrame* frame);
  automation::FrameTreePtr BuildObjectForFrameTree(blink::LocalFrame* frame);
  automation::FrameResourceTreePtr BuildObjectForResourceTree(blink::LocalFrame* frame);

  int32_t application_id_;
  ApplicationWindowDispatcher* dispatcher_;
  PageInstance* page_instance_;
  mojo::AssociatedBinding<automation::Page> binding_;
  automation::PageClientAssociatedPtr page_client_ptr_;
  std::string pending_script_to_evaluate_on_load_once_;
  std::string script_to_evaluate_on_load_once_;
  // hack to receive the events back from probe
  blink::Persistent<InspectorPageAgentImpl> page_agent_impl_;
  bool enabled_;
  bool reloading_;
  bool screencast_enabled_;

  DISALLOW_COPY_AND_ASSIGN(PageDispatcher); 
};

}

#endif