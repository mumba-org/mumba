// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/application_view.h"

#include <utility>

#include "build/build_config.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/application_contents.h"
#include "ipc/ipc_message.h"
#include "ui/accessibility/ax_enums.mojom.h"
#include "ui/accessibility/ax_node_data.h"
#include "ui/events/event.h"
#include "ui/views/controls/native/native_view_host.h"
#include "ui/views/focus/focus_manager.h"
#include "ui/views/views_delegate.h"

namespace host {

// static
const char ApplicationView::kViewClassName[] = "ApplicationView";

////////////////////////////////////////////////////////////////////////////////
// ApplicationView, public:

ApplicationView::ApplicationView()//content::BrowserContext* browser_context)
    : holder_(new views::NativeViewHost()),
      embed_fullscreen_widget_mode_enabled_(false),
      is_embedding_fullscreen_widget_(false),
      //browser_context_(browser_context),
      allow_accelerators_(true) {
  ////DLOG(INFO) << "ApplicationView: " << this;
  AddChildView(holder_);  // Takes ownership of |holder_|.
}

ApplicationView::~ApplicationView() {
  //////DLOG(INFO) << "~ApplicationView: " << this;
  SetApplicationContents(NULL);  // Make sure all necessary tear-down takes portal.
}

ApplicationContents* ApplicationView::GetApplicationContents() {
  //DLOG(INFO) << "ApplicationView::GetApplicationContents (" << this << ")";
  if (!application_contents()) {
    ac_owner_.reset(CreateApplicationContents());//browser_context_));
    ac_owner_->SetDelegate(this);
    SetApplicationContents(ac_owner_.get());
  }
  return application_contents();
}

void ApplicationView::SetApplicationContents(ApplicationContents* replacement) {
  //DLOG(INFO) << "ApplicationView::SetApplicationContents (" << this << ")";
  if (replacement == application_contents()) {
    return;
  }
  SetCrashedOverlayView(nullptr);
  DetachApplicationContents();
  ApplicationContentsObserver::Observe(replacement);
  // application_contents() now returns |replacement| from here onwards.
  UpdateCrashedOverlayView();
  if (ac_owner_.get() != replacement)
    ac_owner_.reset();
  if (embed_fullscreen_widget_mode_enabled_) {
    is_embedding_fullscreen_widget_ =
        application_contents() && application_contents()->GetFullscreenApplicationWindowHost();
  } else {
    DCHECK(!is_embedding_fullscreen_widget_);
  }
  AttachApplicationContents();
  NotifyAccessibilityApplicationContentsChanged();
}

void ApplicationView::SetEmbedFullscreenWindowMode(bool enable) {
  DCHECK(!application_contents())
      << "Cannot change mode while a WebContents is attached.";
  embed_fullscreen_widget_mode_enabled_ = enable;
}

void ApplicationView::LoadInitialURL(const GURL& url) {
  //DLOG(INFO) << "ApplicationView::LoadInitialURL (" << this << ")";
  Dock* dock = nullptr;
  NavigateParams params(dock, url, ui::PAGE_TRANSITION_AUTO_TOPLEVEL);
  GetApplicationContents()->LoadURL(url, params);
}

void ApplicationView::SetFastResize(bool fast_resize) {
  holder_->set_fast_resize(fast_resize);
}

void ApplicationView::SetResizeBackgroundColor(SkColor resize_background_color) {
  holder_->set_resize_background_color(resize_background_color);
}

void ApplicationView::SetCrashedOverlayView(View* crashed_overlay_view) {
  if (crashed_overlay_view_ == crashed_overlay_view)
    return;

  if (crashed_overlay_view_) {
    RemoveChildView(crashed_overlay_view_);
    if (!crashed_overlay_view_->owned_by_client())
      delete crashed_overlay_view_;
  }

  crashed_overlay_view_ = crashed_overlay_view;
  if (crashed_overlay_view_) {
    AddChildView(crashed_overlay_view_);
    crashed_overlay_view_->SetBoundsRect(gfx::Rect(size()));
  }

  UpdateCrashedOverlayView();
}

////////////////////////////////////////////////////////////////////////////////
// ApplicationView, View overrides:

const char* ApplicationView::GetClassName() const {
  return kViewClassName;
}

std::unique_ptr<ApplicationContents> ApplicationView::SwapApplicationContents(
    std::unique_ptr<ApplicationContents> new_app_contents) {
  if (ac_owner_)
    ac_owner_->SetDelegate(NULL);
  std::unique_ptr<ApplicationContents> old_app_contents(std::move(ac_owner_));
  ac_owner_ = std::move(new_app_contents);
  if (ac_owner_)
    ac_owner_->SetDelegate(this);
  SetApplicationContents(ac_owner_.get());
  return old_app_contents;
}

void ApplicationView::OnBoundsChanged(const gfx::Rect& previous_bounds) {
  if (crashed_overlay_view_)
    crashed_overlay_view_->SetBoundsRect(gfx::Rect(size()));

  // In most cases, the holder is simply sized to fill this ApplicationView's bounds.
  // Only WebContentses that are in fullscreen mode and being screen-captured
  // will engage the special layout/sizing behavior.
  gfx::Rect holder_bounds(bounds().size());
  if (!embed_fullscreen_widget_mode_enabled_ || !application_contents() ||
      !application_contents()->IsBeingCaptured() ||
      application_contents()->GetPreferredSize().IsEmpty() ||
      !(is_embedding_fullscreen_widget_ ||
        (application_contents()->GetDelegate() &&
         application_contents()->GetDelegate()->IsFullscreenOrPending(
             application_contents())))) {
    // Reset the native view size.
    holder_->SetNativeViewSize(gfx::Size());
    holder_->SetBoundsRect(holder_bounds);
    if (is_letterboxing_) {
      is_letterboxing_ = false;
      OnLetterboxingChanged();
    }
    return;
  }

  // For screen-captured fullscreened content, scale the |holder_| to fit within
  // this View and center it.
  const gfx::Size capture_size = application_contents()->GetPreferredSize();
  const int64_t x =
      static_cast<int64_t>(capture_size.width()) * holder_bounds.height();
  const int64_t y =
      static_cast<int64_t>(capture_size.height()) * holder_bounds.width();
  if (y < x) {
    holder_bounds.ClampToCenteredSize(gfx::Size(
        holder_bounds.width(), static_cast<int>(y / capture_size.width())));
  } else {
    holder_bounds.ClampToCenteredSize(gfx::Size(
        static_cast<int>(x / capture_size.height()), holder_bounds.height()));
  }

  if (!is_letterboxing_) {
    is_letterboxing_ = true;
    OnLetterboxingChanged();
  }
  holder_->SetNativeViewSize(capture_size);
  holder_->SetBoundsRect(holder_bounds);
}

void ApplicationView::ViewHierarchyChanged(
    const ViewHierarchyChangedDetails& details) {
  if (details.is_add) {
    //DLOG(INFO) << "ApplicationView::ViewHierarchyChanged: (" << this << ") => AttachApplicationContents()";
    AttachApplicationContents();
  }
}

bool ApplicationView::SkipDefaultKeyEventProcessing(const ui::KeyEvent& event) {
  if (allow_accelerators_)
    return views::FocusManager::IsTabTraversalKeyEvent(event);

  // Don't look-up accelerators or tab-traversal if we are showing a non-crashed
  // TabContents.
  // We'll first give the page a chance to process the key events.  If it does
  // not process them, they'll be returned to us and we'll treat them as
  // accelerators then.
  return application_contents() && !application_contents()->IsCrashed();
}

bool ApplicationView::OnMousePressed(const ui::MouseEvent& event) {
  // A left-click within ApplicationView is a request to focus.  The area within the
  // native view child is excluded since it will be handling mouse pressed
  // events itself (http://crbug.com/436192).
  if (event.IsOnlyLeftMouseButton() && HitTestPoint(event.location())) {
    gfx::Point location_in_holder = event.location();
    ConvertPointToTarget(this, holder_, &location_in_holder);
    if (!holder_->HitTestPoint(location_in_holder)) {
      RequestFocus();
      return true;
    }
  }
  return View::OnMousePressed(event);
}

void ApplicationView::OnFocus() {
  if (application_contents() && !application_contents()->IsCrashed())
    application_contents()->Focus();
}

void ApplicationView::AboutToRequestFocusFromTabTraversal(bool reverse) {
  if (application_contents() && !application_contents()->IsCrashed())
    application_contents()->FocusThroughWindowTraversal(reverse);
}

void ApplicationView::GetAccessibleNodeData(ui::AXNodeData* node_data) {
  node_data->role = ax::mojom::Role::kWebView;
  // A webview does not need an accessible name as the document title is
  // provided via other means. Providing it here would be redundant.
  // Mark the name as explicitly empty so that accessibility_checks pass.
  node_data->SetNameExplicitlyEmpty();
}

gfx::NativeViewAccessible ApplicationView::GetNativeViewAccessible() {
  // if (application_contents() && !application_contents()->IsCrashed()) {
  //   ApplicationWindowHost* host_view =
  //       application_contents()->GetApplicationWindowHost();
  //   if (host_view)
  //     return host_view->GetNativeViewAccessible();
  // }
  return View::GetNativeViewAccessible();
}

////////////////////////////////////////////////////////////////////////////////
// ApplicationView, content::WebContentsDelegate implementation:

bool ApplicationView::EmbedsFullscreenWindow() const {
  DCHECK(ac_owner_.get());
  return embed_fullscreen_widget_mode_enabled_;
}

////////////////////////////////////////////////////////////////////////////////
// ApplicationView, content::WebContentsObserver implementation:

void ApplicationView::ApplicationWindowReady() {
  UpdateCrashedOverlayView();
  NotifyAccessibilityApplicationContentsChanged();
}

void ApplicationView::ApplicationWindowDeleted(ApplicationWindowHost* app_window_host) {
  UpdateCrashedOverlayView();
  NotifyAccessibilityApplicationContentsChanged();
}

void ApplicationView::ApplicationWindowChanged(ApplicationWindowHost* old_host,
                                               ApplicationWindowHost* new_host) {
  if (HasFocus())
    OnFocus();
  NotifyAccessibilityApplicationContentsChanged();
}

void ApplicationView::ApplicationContentsDestroyed() {
  //DLOG(INFO) << "ApplicationView::ApplicationContentsDestroyed: (" << this << ")";
  NotifyAccessibilityApplicationContentsChanged();
}

void ApplicationView::DidShowFullscreenWindow() {
  if (embed_fullscreen_widget_mode_enabled_)
    ReattachForFullscreenChange(true);
}

void ApplicationView::DidDestroyFullscreenWindow() {
  if (embed_fullscreen_widget_mode_enabled_)
    ReattachForFullscreenChange(false);
}

void ApplicationView::DidToggleFullscreenMode(bool entered_fullscreen,
                                            bool will_cause_resize) {
  if (embed_fullscreen_widget_mode_enabled_)
    ReattachForFullscreenChange(entered_fullscreen);
}

void ApplicationView::DidAttachInterstitialPage() {
  NotifyAccessibilityApplicationContentsChanged();
}

void ApplicationView::DidDetachInterstitialPage() {
  NotifyAccessibilityApplicationContentsChanged();
}

void ApplicationView::OnApplicationContentsFocused(
    ApplicationWindowHost* app_window_host) {
  RequestFocus();
}

void ApplicationView::ApplicationProcessGone(base::TerminationStatus status) {
  UpdateCrashedOverlayView();
  NotifyAccessibilityApplicationContentsChanged();
}

////////////////////////////////////////////////////////////////////////////////
// ApplicationView, private:

void ApplicationView::AttachApplicationContents() {
  //DLOG(INFO) << "ApplicationView::AttachApplicationContents: (" << this << ")";
  // Prevents attachment if the ApplicationView isn't already in a Window, or it's
  // already attached.
  if (!GetWidget() || !application_contents()) {
    //DLOG(INFO) << "ApplicationView::AttachApplicationContents: (" << this << "): cancelling..";
    return;
  }

//  const gfx::NativeView view_to_attach = is_embedding_fullscreen_widget_ ?
//      application_contents()->GetApplicationWindowHostView()->GetNativeView() :
//      application_contents()->GetNativeView();
  const gfx::NativeView view_to_attach = application_contents()->GetNativeView();
      //application_contents()->GetApplicationWindowHostView()->GetNativeView();    
  OnBoundsChanged(bounds());
  if (holder_->native_view() == view_to_attach) {
    return;
  }

  holder_->Attach(view_to_attach);

  // The WebContents is not focused automatically when attached, so we need to
  // tell the WebContents it has focus if this has focus.
  if (HasFocus()) {
    OnFocus();
  }

  OnApplicationContentsAttached();
}

void ApplicationView::DetachApplicationContents() {
  if (application_contents())
    holder_->Detach();
}

void ApplicationView::ReattachForFullscreenChange(bool enter_fullscreen) {
  DCHECK(embed_fullscreen_widget_mode_enabled_);
  const bool web_contents_has_separate_fs_widget =
      application_contents() && application_contents()->GetFullscreenApplicationWindowHost();
  if (is_embedding_fullscreen_widget_ || web_contents_has_separate_fs_widget) {
    // Shutting down or starting up the embedding of the separate fullscreen
    // widget.  Need to detach and re-attach to a different native view.
    DetachApplicationContents();
    is_embedding_fullscreen_widget_ =
        enter_fullscreen && web_contents_has_separate_fs_widget;
    AttachApplicationContents();
  } else {
    // Entering or exiting "non-Flash" fullscreen mode, where the native view is
    // the same.  So, do not change attachment.
    OnBoundsChanged(bounds());
  }
  NotifyAccessibilityApplicationContentsChanged();
}

void ApplicationView::UpdateCrashedOverlayView() {
  // TODO(dmazzoni): Fix WebContents::IsCrashed() so we can call that
  // instead of checking termination status codes.
  if (application_contents() &&
      application_contents()->GetCrashedStatus() !=
          base::TERMINATION_STATUS_NORMAL_TERMINATION &&
      application_contents()->GetCrashedStatus() !=
          base::TERMINATION_STATUS_STILL_RUNNING &&
      crashed_overlay_view_) {
    SetFocusBehavior(FocusBehavior::NEVER);
    crashed_overlay_view_->SetVisible(true);
    return;
  }

  SetFocusBehavior(application_contents() ? FocusBehavior::ALWAYS
                                  : FocusBehavior::NEVER);

  if (crashed_overlay_view_)
    crashed_overlay_view_->SetVisible(false);
}

void ApplicationView::NotifyAccessibilityApplicationContentsChanged() {
  if (application_contents())
    NotifyAccessibilityEvent(ax::mojom::Event::kChildrenChanged, false);
}

ApplicationContents* ApplicationView::CreateApplicationContents() {
      //content::BrowserContext* browser_context) {
  DCHECK(false);
  ApplicationContents* contents = NULL;
  if (views::ViewsDelegate::GetInstance()) {
    contents =
        views::ViewsDelegate::GetInstance()->CreateApplicationContents();//browser_context, NULL);
  }

  if (!contents) {
    ApplicationContents::CreateParams create_params;//(NULL);
    create_params.initial_size = size(); 
        //browser_context, NULL);
    contents = ApplicationContents::Create(create_params);
  }

  return contents;
}

}  // namespace views
