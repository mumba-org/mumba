// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_UI_APPLICATION_VIEW_H_
#define MUMBA_HOST_UI_APPLICATION_VIEW_H_

#include <stdint.h>

#include <memory>

#include "base/macros.h"
#include "core/shared/common/content_export.h"
#include "core/host/application/application_contents_delegate.h"
#include "core/host/application/application_contents_observer.h"
#include "ui/gfx/native_widget_types.h"
#include "ui/views/view.h"

// In the original views::WebView theres some linking violation
// by pointing back to objects in content/public wich is amenized
// by content/public being only implementation public headers

// we avoid this here by creating the control here on the host module
// that will use components of the ui/views layer

// in our case would be worse giving we dont have/need a public implementation
// headers, so we would need to move some classes to shared/common so they 
// could be consumed by the host and the ui/views component without ui/views
// need to be (unnecessarily) linked together with the host module

namespace views {
class NativeViewHost;  
}

namespace host {
// Provides a view of a WebContents instance.  WebView can be used standalone,
// creating and displaying an internally-owned WebContents; or within a full
// browser where the browser swaps its own WebContents instances in/out (e.g.,
// for browser tabs).
//
// WebView creates and owns a single child view, a NativeViewHost, which will
// hold and display the native view provided by a WebContents.
//
// EmbedFullscreenWidgetMode: When enabled, WebView will observe for WebContents
// fullscreen changes and automatically swap the normal native view with the
// fullscreen native view (if different).  In addition, if the WebContents is
// being screen-captured, the view will be centered within WebView, sized to
// the aspect ratio of the capture video resolution, and scaling will be avoided
// whenever possible.

class CONTENT_EXPORT ApplicationView : public views::View,
                                       public ApplicationContentsDelegate,
                                       public ApplicationContentsObserver {
 public:
  static const char kViewClassName[];

  explicit ApplicationView();//content::BrowserContext* browser_context);
  ~ApplicationView() override;

  // This creates a WebContents if none is yet associated with this WebView. The
  // WebView owns this implicitly created WebContents.
  ApplicationContents* GetApplicationContents();

  // WebView does not assume ownership of WebContents set via this method, only
  // those it implicitly creates via GetWebContents() above.
  void SetApplicationContents(ApplicationContents* app_contents);

  // If |mode| is true, WebView will register itself with WebContents as a
  // WebContentsObserver, monitor for the showing/destruction of fullscreen
  // render widgets, and alter its child view hierarchy to embed the fullscreen
  // widget or restore the normal WebContentsView.
  void SetEmbedFullscreenWindowMode(bool mode);

  //content::BrowserContext* browser_context() { return browser_context_; }

  // Loads the initial URL to display in the attached WebContents. Creates the
  // WebContents if none is attached yet. Note that this is intended as a
  // convenience for loading the initial URL, and so URLs are navigated with
  // PAGE_TRANSITION_AUTO_TOPLEVEL, so this is not intended as a general purpose
  // navigation method - use WebContents' API directly.
  void LoadInitialURL(const GURL& url);

  // Controls how the attached WebContents is resized.
  // false = WebContents' views' bounds are updated continuously as the
  //         WebView's bounds change (default).
  // true  = WebContents' views' position is updated continuously but its size
  //         is not (which may result in some clipping or under-painting) until
  //         a continuous size operation completes. This allows for smoother
  //         resizing performance during interactive resizes and animations.
  void SetFastResize(bool fast_resize);

  // Set the background color to use while resizing with a clip. This is white
  // by default.
  void SetResizeBackgroundColor(SkColor resize_background_color);

  // If provided, this View will be shown in portal of the web contents
  // when the web contents is in a crashed state. This is cleared automatically
  // if the web contents is changed.
  void SetCrashedOverlayView(View* crashed_overlay_view);

  // When used to host UI, we need to explicitly allow accelerators to be
  // processed. Default is false.
  void set_allow_accelerators(bool allow_accelerators) {
    allow_accelerators_ = allow_accelerators;
  }

  // Overridden from View:
  const char* GetClassName() const override;

  views::NativeViewHost* holder() { return holder_; }

 protected:
  // Swaps the owned WebContents |wc_owner_| with |new_web_contents|. Returns
  // the previously owned WebContents.
  std::unique_ptr<ApplicationContents> SwapApplicationContents(
      std::unique_ptr<ApplicationContents> new_app_contents);

  // Called when the web contents is successfully attached.
  virtual void OnApplicationContentsAttached() {
  }
  // Called when letterboxing (scaling the native view to preserve aspect
  // ratio) is enabled or disabled.
  virtual void OnLetterboxingChanged() {}
  bool is_letterboxing() const { return is_letterboxing_; }

  // Overridden from View:
  void OnBoundsChanged(const gfx::Rect& previous_bounds) override;
  void ViewHierarchyChanged(
      const ViewHierarchyChangedDetails& details) override;
  bool SkipDefaultKeyEventProcessing(const ui::KeyEvent& event) override;
  bool OnMousePressed(const ui::MouseEvent& event) override;
  void OnFocus() override;
  void AboutToRequestFocusFromTabTraversal(bool reverse) override;
  void GetAccessibleNodeData(ui::AXNodeData* node_data) override;
  gfx::NativeViewAccessible GetNativeViewAccessible() override;

  // Overridden from ApplicationContentsDelegate:
  bool EmbedsFullscreenWindow() const override;

  // Overridden from ApplicationContentsObserver:
  void ApplicationWindowReady() override;
  void ApplicationWindowDeleted(ApplicationWindowHost* app_view_host) override;
  void ApplicationWindowChanged(ApplicationWindowHost* old_host,
                                ApplicationWindowHost* new_host) override;
  void ApplicationContentsDestroyed() override;
  void DidShowFullscreenWindow() override;
  void DidDestroyFullscreenWindow() override;
  void DidToggleFullscreenMode(bool entered_fullscreen,
                               bool will_cause_resize) override;
  void DidAttachInterstitialPage() override;
  void DidDetachInterstitialPage() override;
  // Workaround for MSVC++ linker bug/feature that requires
  // instantiation of the inline IPC::Listener methods in all translation units.
  void OnChannelConnected(int32_t peer_id) override {}
  void OnChannelError() override {}
  void OnBadMessageReceived(const IPC::Message& message) override {}
  void OnApplicationContentsFocused(
       ApplicationWindowHost* app_dock_window) override;
  void ApplicationProcessGone(base::TerminationStatus status) override;

 private:
  //friend class WebViewUnitTest;

  void AttachApplicationContents();
  void DetachApplicationContents();
  void ReattachForFullscreenChange(bool enter_fullscreen);
  void UpdateCrashedOverlayView();
  void NotifyAccessibilityApplicationContentsChanged();

  // Create a regular or test web contents (based on whether we're running
  // in a unit test or not).
  ApplicationContents* CreateApplicationContents();
      //content::BrowserContext* browser_context);

  views::NativeViewHost* const holder_;
  // Non-NULL if |web_contents()| was created and is owned by this WebView.
  std::unique_ptr<ApplicationContents> ac_owner_;
  // When true, WebView auto-embeds fullscreen widgets as a child view.
  bool embed_fullscreen_widget_mode_enabled_;
  // Set to true while WebView is embedding a fullscreen widget view as a child
  // view instead of the normal WebContentsView render view. Note: This will be
  // false in the case of non-Flash fullscreen.
  bool is_embedding_fullscreen_widget_;
  // Set to true when |holder_| is letterboxed (scaled to be smaller than this
  // view, to preserve its aspect ratio).
  bool is_letterboxing_ = false;
  //content::BrowserContext* browser_context_;
  bool allow_accelerators_;
  View* crashed_overlay_view_ = nullptr;

  DISALLOW_COPY_AND_ASSIGN(ApplicationView);
};

}  // namespace views

#endif  // UI_VIEWS_CONTROLS_WEBVIEW_WEBVIEW_H_
