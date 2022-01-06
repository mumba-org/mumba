// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/application_dialog_view.h"

#include <vector>

#include "base/strings/utf_string_conversions.h"
//#include "core/host/browser_context.h"
#include "core/host/application/native_web_keyboard_event.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/application_contents.h"
#include "core/host/notification_details.h"
#include "core/host/notification_source.h"
#include "core/host/notification_types.h"
#include "ui/events/event.h"
#include "ui/events/keycodes/keyboard_codes.h"
#include "ui/views/controls/webview/webview.h"
#include "ui/views/layout/fill_layout.h"
#include "ui/views/widget/native_widget_private.h"
#include "ui/views/widget/root_view.h"
#include "ui/views/widget/widget.h"
#include "ui/web_dialogs/web_dialog_delegate.h"
#include "ui/web_dialogs/web_dialog_ui.h"

using common::NativeWebKeyboardEvent;
//using ApplicationContents;
//using ApplicationUIMessageHandler;
using ui::WebDialogDelegate;
using ui::WebDialogUIBase;
using ui::WebDialogWebContentsDelegate;

namespace views {

////////////////////////////////////////////////////////////////////////////////
// ApplicationDialogView, public:

ApplicationDialogView::ApplicationDialogView(
  //content::BrowserContext* context,
  WebDialogDelegate* delegate,
  ApplicationContentsHandler* handler)
    : ClientView(nullptr, nullptr),
      ApplicationDialogWebContentsDelegate(handler),//context,
      delegate_(delegate),
      app_view_(new ApplicationView()) {//context)) {
  app_view_->set_allow_accelerators(true);
  AddChildView(app_view_);
  set_contents_view(app_view_);
  SetLayoutManager(std::make_unique<views::FillLayout>());
  // Pressing the ESC key will close the dialog.
  AddAccelerator(ui::Accelerator(ui::VKEY_ESCAPE, ui::EF_NONE));

  if (delegate_) {
    for (const auto& accelerator : delegate_->GetAccelerators())
      AddAccelerator(accelerator);
  }
}

ApplicationDialogView::~ApplicationDialogView() {
}

ApplicationContents* ApplicationDialogView::application_contents() {
  return app_view_->application_contents();
}

////////////////////////////////////////////////////////////////////////////////
// ApplicationDialogView, views::View implementation:

gfx::Size ApplicationDialogView::CalculatePreferredSize() const {
  gfx::Size out;
  if (delegate_)
    delegate_->GetDialogSize(&out);
  return out;
}

gfx::Size ApplicationDialogView::GetMinimumSize() const {
  gfx::Size out;
  if (delegate_)
    delegate_->GetMinimumDialogSize(&out);
  return out;
}

bool ApplicationDialogView::AcceleratorPressed(const ui::Accelerator& accelerator) {
  if (delegate_ && delegate_->AcceleratorPressed(accelerator))
    return true;

  // Pressing ESC closes the dialog.
  DCHECK_EQ(ui::VKEY_ESCAPE, accelerator.key_code());
  if (GetWidget())
    GetWidget()->Close();
  return true;
}

void ApplicationDialogView::ViewHierarchyChanged(
    const ViewHierarchyChangedDetails& details) {
  if (details.is_add && GetWidget())
    InitDialog();
}

bool ApplicationDialogView::CanClose() {
  // Don't close UI if |delegate_| does not allow users to close it by
  // clicking on "x" button or pressing Esc shortcut key on hosting dialog.
  if (!delegate_->CanCloseDialog() && !close_contents_called_)
    return false;

  // If CloseContents() is called before CanClose(), which is called by
  // RenderViewHostImpl::ClosePageIgnoringUnloadEvents, it indicates
  // beforeunload event should not be fired during closing.
  if ((is_attempting_close_dialog_ && before_unload_fired_) ||
      close_contents_called_) {
    is_attempting_close_dialog_ = false;
    before_unload_fired_ = false;
    return true;
  }

  if (!is_attempting_close_dialog_) {
    // Fire beforeunload event when user attempts to close the dialog.
    is_attempting_close_dialog_ = true;
    app_view_->web_contents()->DispatchBeforeUnload();
  }
  return false;
}

////////////////////////////////////////////////////////////////////////////////
// ApplicationDialogView, views::WidgetDelegate implementation:

bool ApplicationDialogView::CanResize() const {
  if (delegate_)
    return delegate_->CanResizeDialog();
  return true;
}

ui::ModalType ApplicationDialogView::GetModalType() const {
  return GetDialogModalType();
}

base::string16 ApplicationDialogView::GetWindowTitle() const {
  if (delegate_)
    return delegate_->GetDialogTitle();
  return base::string16();
}

std::string ApplicationDialogView::GetWindowName() const {
  if (delegate_)
    return delegate_->GetDialogName();
  return std::string();
}

void ApplicationDialogView::WindowClosing() {
  // If we still have a delegate that means we haven't notified it of the
  // dialog closing. This happens if the user clicks the Close button on the
  // dialog.
  if (delegate_)
    OnDialogClosed("");
}

views::View* ApplicationDialogView::GetContentsView() {
  return this;
}

views::ClientView* ApplicationDialogView::CreateClientView(views::Widget* widget) {
  return this;
}

views::View* ApplicationDialogView::GetInitiallyFocusedView() {
  return app_view_;
}

bool ApplicationDialogView::ShouldShowWindowTitle() const {
  return ShouldShowDialogTitle();
}

views::Widget* ApplicationDialogView::GetWidget() {
  return View::GetWidget();
}

const views::Widget* ApplicationDialogView::GetWidget() const {
  return View::GetWidget();
}

////////////////////////////////////////////////////////////////////////////////
// WebDialogDelegate implementation:

ui::ModalType ApplicationDialogView::GetDialogModalType() const {
  if (delegate_)
    return delegate_->GetDialogModalType();
  return ui::MODAL_TYPE_NONE;
}

base::string16 ApplicationDialogView::GetDialogTitle() const {
  return GetWindowTitle();
}

GURL ApplicationDialogView::GetDialogContentURL() const {
  if (delegate_)
    return delegate_->GetDialogContentURL();
  return GURL();
}

void ApplicationDialogView::GetWebUIMessageHandlers(
    std::vector<WebUIMessageHandler*>* handlers) const {
  if (delegate_)
    delegate_->GetWebUIMessageHandlers(handlers);
}

void ApplicationDialogView::GetDialogSize(gfx::Size* size) const {
  if (delegate_)
    delegate_->GetDialogSize(size);
}

void ApplicationDialogView::GetMinimumDialogSize(gfx::Size* size) const {
  if (delegate_)
    delegate_->GetMinimumDialogSize(size);
}

std::string ApplicationDialogView::GetDialogArgs() const {
  if (delegate_)
    return delegate_->GetDialogArgs();
  return std::string();
}

void ApplicationDialogView::OnDialogShown(
  //content::WebUI* webui,
  ApplicationHostWindow* app_dock_window) {
  if (delegate_)
    delegate_->OnDialogShown(app_dock_window);//webui, render_view_host);
}

void ApplicationDialogView::OnDialogClosed(const std::string& json_retval) {
  Detach();
  if (delegate_) {
    // Store the dialog content area size.
    delegate_->StoreDialogSize(GetContentsBounds().size());
  }

  if (GetWidget())
    GetWidget()->Close();

  if (delegate_) {
    delegate_->OnDialogClosed(json_retval);
    delegate_ = nullptr;  // We will not communicate further with the delegate.
  }
}

void ApplicationDialogView::OnDialogCloseFromWebUI(const std::string& json_retval) {
  closed_via_webui_ = true;
  dialog_close_retval_ = json_retval;
  if (GetWidget())
    GetWidget()->Close();
}

void ApplicationDialogView::OnCloseContents(
  ApplicationContents* source,
  bool* out_close_dialog) {
  
  DCHECK(out_close_dialog);
  if (delegate_)
    delegate_->OnCloseContents(source, out_close_dialog);
}

bool ApplicationDialogView::ShouldShowDialogTitle() const {
  if (delegate_)
    return delegate_->ShouldShowDialogTitle();
  return true;
}

bool ApplicationDialogView::HandleContextMenu(
    const common::ContextMenuParams& params) {
  if (delegate_)
    return delegate_->HandleContextMenu(params);
  return WebDialogWebContentsDelegate::HandleContextMenu(params);
}

////////////////////////////////////////////////////////////////////////////////
// ApplicationContentsDelegate implementation:

void ApplicationDialogView::MoveContents(ApplicationContents* source, const gfx::Rect& pos) {
  // The contained web page wishes to resize itself. We let it do this because
  // if it's a dialog we know about, we trust it not to be mean to the user.
  GetWidget()->SetBounds(pos);
}

// A simplified version of BrowserView::HandleKeyboardEvent().
// We don't handle global keyboard shortcuts here, but that's fine since
// they're all browser-specific. (This may change in the future.)
void ApplicationDialogView::HandleKeyboardEvent(ApplicationContents* source,
                                        const NativeWebKeyboardEvent& event) {
  if (!event.os_event)
    return;

  GetWidget()->native_widget_private()->RepostNativeEvent(event.os_event);
}

void ApplicationDialogView::CloseContents(ApplicationContents* source) {
  close_contents_called_ = true;
  bool close_dialog = false;
  OnCloseContents(source, &close_dialog);
  if (close_dialog)
    OnDialogClosed(closed_via_webui_ ? dialog_close_retval_ : std::string());
}

ApplicationContents* ApplicationDialogView::OpenURLFromTab(
    ApplicationContents* source,
    const OpenURLParams& params) {
  ApplicationContents* new_contents = nullptr;
  if (delegate_ &&
      delegate_->HandleOpenURLFromTab(source, params, &new_contents)) {
    return new_contents;
  }
  return WebDialogWebContentsDelegate::OpenURLFromTab(source, params);
}

void ApplicationDialogView::AddNewContents(
  ApplicationContents* source,
  ApplicationContents* new_contents,
  WindowOpenDisposition disposition,
  const gfx::Rect& initial_rect,
  bool user_gesture,
  bool* was_blocked) {
  
  if (delegate_ && delegate_->HandleAddNewContents(
          source, new_contents, disposition, initial_rect, user_gesture)) {
    return;
  }
  WebDialogWebContentsDelegate::AddNewContents(
      source, new_contents, disposition, initial_rect, user_gesture,
      was_blocked);
}

void ApplicationDialogView::LoadingStateChanged(ApplicationContents* source,
    bool to_different_document) {
  if (delegate_)
    delegate_->OnLoadingStateChanged(source);
}

void ApplicationDialogView::BeforeUnloadFired(
  ApplicationContents* tab,
  bool proceed,
  bool* proceed_to_fire_unload) {

  before_unload_fired_ = true;
  *proceed_to_fire_unload = proceed;
}

bool ApplicationDialogView::ShouldCreateApplicationContents(
    ApplicationContents* web_contents,
    ApplicationHostWindow* opener,
    //content::SiteInstance* source_site_instance,
    int32_t route_id,
    int32_t main_frame_route_id,
    int32_t main_frame_widget_route_id,
    common::mojom::WindowContainerType window_container_type,
    const GURL& opener_url,
    const std::string& frame_name,
    const GURL& target_url) {//,
    //const std::string& partition_id,
    //content::SessionStorageNamespace* session_storage_namespace) {
  if (delegate_)
    return delegate_->HandleShouldCreateApplicationContents();
  return true;
}

////////////////////////////////////////////////////////////////////////////////
// ApplicationDialogView, private:

void ApplicationDialogView::InitDialog() {
  ApplicationContents* app_contents = app_view_->GetApplicationContents();
  if (app_contents->GetDelegate() == this)
    return;

  app_contents->SetDelegate(this);

  // Set the delegate. This must be done before loading the page. See
  // the comment above WebDialogUI in its header file for why.
  WebDialogUIBase::SetDelegate(app_contents, this);

  app_view_->LoadInitialURL(GetDialogContentURL());
}

}  // namespace views
