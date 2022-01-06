// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_APPLICATION_CONTENTS_OBSERVER_H_
#define MUMBA_HOST_APPLICATION_APPLICATION_CONTENTS_OBSERVER_H_

#include <stdint.h>

#include "base/macros.h"
#include "base/optional.h"
#include "base/process/kill.h"
#include "base/process/process_handle.h"
#include "core/shared/common/content_export.h"
//#include "core/host/application/navigation_controller.h"
//#include "core/host/application/reload_type.h"
#include "core/host/application/visibility.h"
//#include "core/common/frame_navigate_params.h"
//#include "core/common/resource_load_info.mojom.h"
#include "core/shared/common/resource_type.h"
#include "ipc/ipc_listener.h"
#include "url/gurl.h"
#include "mojo/public/cpp/system/message_pipe.h"
#include "services/service_manager/public/cpp/bind_source_info.h"
#include "third_party/blink/public/platform/web_input_event.h"
#include "third_party/skia/include/core/SkColor.h"
#include "ui/base/page_transition_types.h"
#include "ui/base/window_open_disposition.h"

namespace gfx {
class Size;
}  // namespace gfx

namespace common {
struct FaviconURL;  
}

namespace host {

//class NavigationEntry;
//class NavigationHandle;
class ApplicationProcessHost;
class ApplicationWindowHost;
class ApplicationContents;
struct AXEventNotificationDetails;
struct AXLocationChangeNotificationDetails;
struct EntryChangedDetails;
struct LoadCommittedDetails;
struct PrunedDetails;
struct Referrer;

// An observer API implemented by classes which are interested in various page
// load events from ApplicationContents.  They also get a chance to filter IPC messages.
//
// Since a ApplicationContents can be a delegate to almost arbitrarily many
// ApplicationWindowHosts, it is important to check in those ApplicationContentsObserver
// methods which take a ApplicationWindowHost that the event came from the
// ApplicationWindowHost the observer cares about.
//
// Usually, observers should only care about the current ApplicationWindowHost as
// returned by GetApplicationWindowHost().
//
// TODO(creis, jochen): Hide the fact that there are several ApplicationWindowHosts
// from the ApplicationContentsObserver API. http://crbug.com/173325
class CONTENT_EXPORT ApplicationContentsObserver : public IPC::Listener {
 public:
  // Frames and Views ----------------------------------------------------------

  // Called when a RenderFrame for |render_frame_host| is created in the
  // renderer process. Use |RenderFrameDeleted| to listen for when this
  // RenderFrame goes away.
  //virtual void RenderFrameCreated(RenderFrameHost* render_frame_host) {}

  // Called when a RenderFrame for |render_frame_host| is deleted or the
  // renderer process in which it runs it has died. Use |RenderFrameCreated| to
  // listen for when RenderFrame objects are created.
  //virtual void RenderFrameDeleted(RenderFrameHost* render_frame_host) {}

  // This method is invoked whenever one of the current frames of a ApplicationContents
  // swaps its RenderFrameHost with another one; for example because that frame
  // navigated and the new content is in a different process. The
  // RenderFrameHost that has been replaced is in |old_host|, which can be
  // nullptr if the old RenderFrameHost was shut down or a new frame has been
  // created and no old RenderFrameHost exists.
  //
  // This method, in combination with |FrameDeleted|, is appropriate for
  // observers wishing to track the set of current RenderFrameHosts -- i.e.,
  // those hosts that would be visited by calling ApplicationContents::ForEachFrame().
  //virtual void RenderFrameHostChanged(RenderFrameHost* old_host,
  //                                    RenderFrameHost* new_host) {}

  // This method is invoked when a subframe associated with a ApplicationContents is
  // deleted or the ApplicationContents is destroyed and the top-level frame is deleted.
  // Use |RenderFrameHostChanged| to listen for when a RenderFrameHost object is
  // made the current host for a frame.
  //virtual void FrameDeleted(RenderFrameHost* render_frame_host) {}

  // This is called when a RVH is created for a ApplicationContents, but not if it's an
  // interstitial.
  virtual void ApplicationWindowCreated(ApplicationWindowHost* application_window_host) {}

  // Called for every RenderFrameHost that's created for an interstitial.
  //virtual void RenderFrameForInterstitialPageCreated(
 //     RenderFrameHost* render_frame_host) {}

  // This method is invoked when the RenderView of the current ApplicationWindowHost
  // is ready, e.g. because we recreated it after a crash.
  virtual void ApplicationWindowReady() {}

  // This method is invoked when a ApplicationWindowHost of the ApplicationContents is
  // deleted. Note that this does not always happen when the ApplicationContents starts
  // to use a different ApplicationWindowHost, as the old ApplicationWindowHost might get
  // just swapped out.
  virtual void ApplicationWindowDeleted(ApplicationWindowHost* application_window_host) {}

  // This method is invoked when the process for the current main
  // RenderFrameHost exits (usually by crashing, though possibly by other
  // means). The ApplicationContents continues to use the RenderFrameHost, e.g. when the
  // user reloads the current page. When the RenderFrameHost itself is deleted,
  // the RenderFrameDeleted method will be invoked.
  //
  // Note that this is triggered upstream through
  // ApplicationProcessHostObserver::RenderProcessExited(); for code that doesn't
  // otherwise need to be a ApplicationContentsObserver, that API is probably a better
  // choice.
  virtual void ApplicationProcessGone(base::TerminationStatus status) {}

  // This method is invoked when a ApplicationContents swaps its visible ApplicationWindowHost
  // with another one, possibly changing processes. The ApplicationWindowHost that has
  // been replaced is in |old_host|, which is nullptr if the old RVH was shut
  // down.
  virtual void ApplicationWindowChanged(ApplicationWindowHost* old_host,
                                        ApplicationWindowHost* new_host) {}

  // This method is invoked when a process in the ApplicationContents becomes
  // unresponsive.
  virtual void OnApplicationUnresponsive(ApplicationProcessHost* application_process_host) {}

  // Navigation ----------------------------------------------------------------

  // Called when a navigation started in the ApplicationContents. |navigation_handle|
  // is unique to a specific navigation. The same |navigation_handle| will be
  // provided on subsequent calls to DidRedirectNavigation, DidFinishNavigation,
  // and ReadyToCommitNavigation when related to this navigation. Observers
  // should clear any references to |navigation_handle| in DidFinishNavigation,
  // just before it is destroyed.
  //
  // Note that this is fired by navigations in any frame of the ApplicationContents,
  // not just the main frame.
  //
  // Note that this is fired by same-document navigations, such as fragment
  // navigations or pushState/replaceState, which will not result in a document
  // change. To filter these out, use NavigationHandle::IsSameDocument.
  //
  // Note that more than one navigation can be ongoing in the same frame at the
  // same time (including the main frame). Each will get its own
  // NavigationHandle.
  //
  // Note that there is no guarantee that DidFinishNavigation will be called
  // for any particular navigation before DidStartNavigation is called on the
  // next.
  virtual void DidStartNavigation() {}//NavigationHandle* navigation_handle) {}

  // Called when a navigation encountered a server redirect.
  virtual void DidRedirectNavigation() {}//NavigationHandle* navigation_handle) {}

  // Called when the navigation is ready to be committed in a renderer. Most
  // observers should use DidFinishNavigation instead, which happens right
  // after the navigation commits. This method is for observers that want to
  // initialize renderer-side state just before the RenderFrame commits the
  // navigation.
  //
  // PlzNavigate
  // This is the first point in time where a RenderFrameHost is associated with
  // the navigation.
  virtual void ReadyToCommitNavigation() {}//NavigationHandle* navigation_handle) {}

  // Called when a navigation finished in the ApplicationContents. This happens when a
  // navigation is committed, aborted or replaced by a new one. To know if the
  // navigation has committed, use NavigationHandle::HasCommitted; use
  // NavigationHandle::IsErrorPage to know if the navigation resulted in an
  // error page.
  //
  // If this is called because the navigation committed, then the document load
  // will still be ongoing in the RenderFrameHost returned by
  // |navigation_handle|. Use the document loads events such as DidStopLoading
  // and related methods to listen for continued events from this
  // RenderFrameHost.
  //
  // Note that this is fired by same-document navigations, such as fragment
  // navigations or pushState/replaceState, which will not result in a document
  // change. To filter these out, use NavigationHandle::IsSameDocument.
  //
  // Note that |navigation_handle| will be destroyed at the end of this call,
  // so do not keep a reference to it afterward.
  virtual void DidFinishNavigation() {}//NavigationHandle* navigation_handle) {}

  // Navigation (obsolete and deprecated) --------------------------------------

  // This method is invoked after the browser process starts a navigation to a
  // pending NavigationEntry. It is not called for renderer-initiated
  // navigations unless they are sent to the browser process via OpenURL. It may
  // be called multiple times for a given navigation, such as a typed URL
  // followed by a cross-process client or server redirect.
  //
  // SOON TO BE DEPRECATED. Use DidStartNavigation instead in PlzNavigate. In
  // default mode, it is still necessary to override this function to be
  // notified about a navigation earlier than DidStartProvisionalLoad. This
  // function will be removed when PlzNavigate is enabled.
  //virtual void DidStartNavigationToPendingEntry(const GURL& url,
  //                                              ReloadType reload_type) {}


  virtual void DidInitializeApplicationContents() {}

  // Document load events ------------------------------------------------------

  // These three methods correspond to the points in time when a document starts
  // loading for the first time (initiates outgoing requests), when incoming
  // data subsequently starts arriving, and when it finishes loading.
  virtual void DidStartLoading() {}
  virtual void DidReceiveResponse() {}
  virtual void DidStopLoading() {}

  // This method is invoked once the window.document object of the main frame
  // was created.
  virtual void DocumentAvailableInMainFrame() {}

  // This method is invoked once the onload handler of the main frame has
  // completed.
  virtual void DocumentOnLoadCompletedInMainFrame() {}

  // This method is invoked when the document in the given frame finished
  // loading. At this point, scripts marked as defer were executed, and
  // content scripts marked "document_end" get injected into the frame.
  virtual void DocumentLoadedInFrame(ApplicationWindowHost* app_window_host) {}

  // This method is invoked when the load is done, i.e. the spinner of the tab
  // will stop spinning, and the onload event was dispatched.
  //
  // If the ApplicationContents is displaying replacement content, e.g. network error
  // pages, DidFinishLoad is invoked for frames that were not sending
  // navigational events before. It is safe to ignore these events.
  virtual void DidFinishLoad(ApplicationWindowHost* app_window_host,
                             const GURL& validated_url) {}

  // This method is like DidFinishLoad, but when the load failed or was
  // cancelled, e.g. window.stop() is invoked.
  virtual void DidFailLoad(ApplicationWindowHost* app_window_host,
                           const GURL& validated_url,
                           int error_code,
                           const base::string16& error_description) {}

  // This method is invoked when the visible security state of the page changes.
  //virtual void DidChangeVisibleSecurityState() {}

  // This method is invoked when content was loaded from an in-memory cache.
  virtual void DidLoadResourceFromMemoryCache(
      const GURL& url,
      const std::string& mime_type,
      common::ResourceType resource_type) {}

  // This method is invoked when a resource has been loaded, successfully or
  // not.
  //virtual void ResourceLoadComplete(
  //    const mojom::ResourceLoadInfo& resource_load_info) {}

  // This method is invoked when a new non-pending navigation entry is created.
  // This corresponds to one NavigationController entry being created
  // (in the case of new navigations) or renavigated to (for back/forward
  // navigations).
  //virtual void NavigationEntryCommitted(
  //    const LoadCommittedDetails& load_details) {}

  // Invoked when the NavigationController decreased its back/forward list count
  // by removing entries from either the front or back of its list. This is
  // usually the result of going back and then doing a new navigation, meaning
  // all the "forward" items are deleted.
  //
  // This normally happens as a result of a new navigation. It will be
  // followed by a NavigationEntryCommitted() call for the new page that
  // caused the pruning. It could also be a result of removing an item from
  // the list to delete history or fix up after interstitials.
  //virtual void NavigationListPruned(const PrunedDetails& pruned_details) {}

  // Invoked when NavigationEntries have been deleted because of a history
  // deletion. Observers should ensure that they remove all traces of the
  // deleted entries.
  //virtual void NavigationEntriesDeleted() {}

  // Invoked when a NavigationEntry has changed.
  //
  // This will NOT be sent on navigation, interested parties should also
  // implement NavigationEntryCommitted() to handle that case. This will be
  // sent when the entry is updated outside of navigation (like when a new
  // title comes).
  //virtual void NavigationEntryChanged(
  //    const EntryChangedDetails& change_details) {}

  // This method is invoked when a new ApplicationContents was created in response to
  // an action in the observed ApplicationContents, e.g. a link with target=_blank was
  // clicked. The |source_render_frame_host| is the frame in which the action
  // took portal.
  virtual void DidOpenRequestedURL(ApplicationContents* new_contents,
                                   ApplicationWindowHost* source_render_frame_host,
                                   const GURL& url,
                                   WindowOpenDisposition disposition,
                                   ui::PageTransition transition,
                                   bool started_from_context_menu,
                                   bool renderer_initiated) {}

  // This method is invoked when the renderer process has completed its first
  // paint after a non-empty layout.
  virtual void DidFirstVisuallyNonEmptyPaint() {}

  // When ApplicationContents::Stop() is called, the ApplicationContents stops loading and then
  // invokes this method. If there are ongoing navigations, their respective
  // failure methods will also be invoked.
  virtual void NavigationStopped() {}

  // Called when there has been direct user interaction with the ApplicationContents.
  // The type argument specifies the kind of interaction. Direct user input
  // signalled through this callback includes:
  // 1) any mouse down event (blink::WebInputEvent::MouseDown);
  // 2) the start of a scroll (blink::WebInputEvent::GestureScrollBegin);
  // 3) any raw key down event (blink::WebInputEvent::RawKeyDown);
  // 4) any touch event (inc. scrolls) (blink::WebInputEvent::TouchStart); and
  // 5) a browser navigation or reload (blink::WebInputEvent::Undefined).
  virtual void DidGetUserInteraction(const blink::WebInputEvent::Type type) {}

  // This method is invoked when a ApplicationWindowHost of this ApplicationContents was
  // configured to ignore UI events, and an UI event took portal.
  virtual void DidGetIgnoredUIEvent() {}

  // Invoked every time the ApplicationContents changes visibility.
  virtual void OnVisibilityChanged(Visibility visibility) {}

  // Invoked when the main frame changes size.
  //virtual void MainFrameWasResized(bool width_changed) {}
  virtual void WindowWasResized(bool width_changed) {}

  // Invoked when the given frame changes its window.name property.
  //virtual void FrameNameChanged(RenderFrameHost* render_frame_host,
  //                              const std::string& name) {}

  // This method is invoked when the title of the ApplicationContents is set. Note that
  // |entry| may be null if the web page whose title changed has not yet had a
  // NavigationEntry assigned to it.
  virtual void TitleWasSet() {}//NavigationEntry* entry) {}

  //virtual void AppCacheAccessed(const GURL& manifest_url,
   //                             bool blocked_by_policy) {}


  // Invoked when ApplicationContents::Clone() was used to clone a ApplicationContents.
  virtual void DidCloneToNewApplicationContents(ApplicationContents* old_application_contents,
                                                ApplicationContents* new_application_contents) {}

  // Invoked when the ApplicationContents is being destroyed. Gives subclasses a chance
  // to cleanup. After the whole loop over all ApplicationContentsObservers has been
  // finished, application_contents() returns nullptr.
  virtual void ApplicationContentsDestroyed() {}

  // Called when the user agent override for a ApplicationContents has been changed.
  virtual void UserAgentOverrideSet(const std::string& user_agent) {}

  // Invoked when new FaviconURL candidates are received from the renderer
  // process.
  virtual void DidUpdateFaviconURL(const std::vector<common::FaviconURL>& candidates) {}

  // Invoked when the ApplicationContents is muted/unmuted.
  virtual void DidUpdateAudioMutingState(bool muted) {}

  // Invoked when a pepper plugin creates and shows or destroys a fullscreen
  // RenderWidget.
  virtual void DidShowFullscreenWindow() {}
  virtual void DidDestroyFullscreenWindow() {}

  // Invoked when the renderer process has toggled the tab into/out of
  // fullscreen mode.
  virtual void DidToggleFullscreenMode(bool entered_fullscreen,
                                       bool will_cause_resize) {}

  // Invoked when an interstitial page is attached or detached.
  virtual void DidAttachInterstitialPage() {}
  virtual void DidDetachInterstitialPage() {}

  // Invoked before a form repost warning is shown.
  //virtual void BeforeFormRepostWarningShow() {}

  // Invoked when the beforeunload handler fires. The time is from the renderer
  // process.
  virtual void BeforeUnloadFired(const base::TimeTicks& proceed_time) {}

  // Invoked when a user cancels a before unload dialog.
  virtual void BeforeUnloadDialogCancelled() {}

  // Called when accessibility events or location changes are received
  // from a render frame, but only when the accessibility mode has the
  // ui::AXMode::kApplicationContents flag set.
  virtual void AccessibilityEventReceived(
      const std::vector<AXEventNotificationDetails>& details) {}
  virtual void AccessibilityLocationChangesReceived(
      const std::vector<AXLocationChangeNotificationDetails>& details) {}

  // Invoked when theme color is changed to |theme_color|.
  //virtual void DidChangeThemeColor(SkColor theme_color) {}

  // Invoked when media is playing or paused.  |id| is unique per player and per
  // RenderFrameHost.  There may be multiple players within a RenderFrameHost
  // and subsequently within a ApplicationContents.  MediaStartedPlaying() will always
  // be followed by MediaStoppedPlaying() after player teardown.  Observers must
  // release all stored copies of |id| when MediaStoppedPlaying() is received.
  struct MediaPlayerInfo {
    MediaPlayerInfo(bool has_video, bool has_audio)
        : has_video(has_video), has_audio(has_audio) {}
    bool has_video;
    bool has_audio;
  };
  //using MediaPlayerId = std::pair<RenderFrameHost*, int>;
  using MediaPlayerId = std::pair<ApplicationWindowHost*, int>;
  virtual void MediaStartedPlaying(const MediaPlayerInfo& video_type,
                                   const MediaPlayerId& id) {}
  enum class MediaStoppedReason {
    // The media was stopped for an unspecified reason.
    kUnspecified,

    // The media was stopped because it reached the end of the stream.
    kReachedEndOfStream,
  };
  virtual void MediaStoppedPlaying(
      const MediaPlayerInfo& video_type,
      const MediaPlayerId& id,
      ApplicationContentsObserver::MediaStoppedReason reason) {}
  virtual void MediaResized(const gfx::Size& size, const MediaPlayerId& id) {}
  // Invoked when media enters or exits fullscreen. We must use a heuristic
  // to determine this as it is not trivial for media with custom controls.
  // There is a slight delay between media entering or exiting fullscreen
  // and it being detected.
  virtual void MediaEffectivelyFullscreenChanged(bool is_fullscreen) {}
  virtual void MediaMutedStatusChanged(const MediaPlayerId& id, bool muted) {}

  // Invoked when the renderer process changes the page scale factor.
  virtual void OnPageScaleFactorChanged(float page_scale_factor) {}

  // Invoked if an IPC message is coming from a specific RenderFrameHost.
  virtual bool OnMessageReceived(const IPC::Message& message,
                                 ApplicationWindowHost* application_window_host);
                                 //RenderFrameHost* render_frame_host);

  // Notification that the |application_window_host| for this ApplicationContents has gained
  // focus.
  virtual void OnApplicationContentsFocused(ApplicationWindowHost* application_window_host) {}

  // Notification that the |application_window_host| for this ApplicationContents has lost
  // focus.
  virtual void OnApplicationContentsLostFocus(ApplicationWindowHost* application_window_host) {}

  // Notifes that a CompositorFrame was received from the renderer.
  virtual void DidReceiveCompositorFrame() {}

  // Notifies that the manifest URL for the main frame changed to
  // |manifest_url|. This will be invoked when a document with a manifest loads
  // or when the manifest URL changes (possibly to nothing). It is not invoked
  // when a document with no manifest loads. During document load, if the
  // document has both a manifest and a favicon, DidUpdateWebManifestURL() will
  // be invoked before DidUpdateFaviconURL().
  virtual void DidUpdateWebManifestURL(
      const base::Optional<GURL>& manifest_url) {}

  // Called to give the embedder an opportunity to bind an interface request
  // from a frame. If the request can be bound, |interface_pipe| will be taken.
  //virtual void OnInterfaceRequestFromFrame(
  //    RenderFrameHost* render_frame_host,
  //    const std::string& interface_name,
  //    mojo::ScopedMessagePipeHandle* interface_pipe) {}

  // IPC::Listener implementation.
  // DEPRECATED: Use (i.e. override) the other overload instead:
  //     virtual bool OnMessageReceived(const IPC::Message& message,
  //                                    RenderFrameHost* render_frame_host);
  // TODO(https://crbug.com/758026): Delete this overload when possible.
  bool OnMessageReceived(const IPC::Message& message) override;

  ApplicationContents* application_contents() const;

 protected:
  // Use this constructor when the object is tied to a single ApplicationContents for
  // its entire lifetime.
  explicit ApplicationContentsObserver(ApplicationContents* application_contents);

  // Use this constructor when the object wants to observe a ApplicationContents for
  // part of its lifetime.  It can then call Observe() to start and stop
  // observing.
  ApplicationContentsObserver();

  ~ApplicationContentsObserver() override;

  // Start observing a different ApplicationContents; used with the default constructor.
  void Observe(ApplicationContents* application_contents);

 private:
  friend class ApplicationContents;

  void ResetApplicationContents();

  ApplicationContents* application_contents_;

  base::WeakPtrFactory<ApplicationContentsObserver> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(ApplicationContentsObserver);
};

}  // namespace host

#endif  // CONTENT_PUBLIC_BROWSER_WEB_CONTENTS_OBSERVER_H_
