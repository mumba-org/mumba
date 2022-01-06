// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_UI_APPLICATION_DIALOG_VIEW_H_
#define MUMBA_HOST_UI_APPLICATION_DIALOG_VIEW_H_

#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include "base/gtest_prod_util.h"
#include "base/macros.h"
#include "ui/gfx/geometry/size.h"
#include "ui/views/widget/widget_delegate.h"
#include "ui/views/window/client_view.h"
//#include "ui/web_dialogs/web_dialog_delegate.h"
//#include "ui/web_dialogs/web_dialog_web_contents_delegate.h"

namespace host {
class ApplicationView;

////////////////////////////////////////////////////////////////////////////////
//
// WebDialogView is a view used to display an web dialog to the user. The
// content of the dialogs is determined by the delegate
// (ui::WebDialogDelegate), but is basically a file URL along with a
// JSON input string. The HTML is supposed to show a UI to the user and is
// expected to send back a JSON file as a return value.
//
////////////////////////////////////////////////////////////////////////////////
//
// TODO(akalin): Make WebDialogView contain an WebDialogWebContentsDelegate
// instead of inheriting from it to avoid violating the "no multiple
// inheritance" rule.
class CONTENT_EXPORT ApplicationDialogView : public views::ClientView,
                                             public ui::WebDialogWebContentsDelegate,
                                             public ui::WebDialogDelegate,
                                             public views::WidgetDelegate {
 public:
  // |handler| must not be NULL and this class takes the ownership.
  ApplicationDialogView(//content::BrowserContext* context,
                ui::WebDialogDelegate* delegate,
                ApplicationContentsHandler* handler);
  ~ApplicationDialogView() override;

  // For testing.
  ApplicationContents* application_contents();

  // Overridden from views::ClientView:
  gfx::Size CalculatePreferredSize() const override;
  gfx::Size GetMinimumSize() const override;
  bool AcceleratorPressed(const ui::Accelerator& accelerator) override;
  void ViewHierarchyChanged(
      const ViewHierarchyChangedDetails& details) override;
  bool CanClose() override;

  // Overridden from views::WidgetDelegate:
  bool CanResize() const override;
  ui::ModalType GetModalType() const override;
  base::string16 GetWindowTitle() const override;
  std::string GetWindowName() const override;
  void WindowClosing() override;
  views::View* GetContentsView() override;
  ClientView* CreateClientView(views::Widget* widget) override;
  views::View* GetInitiallyFocusedView() override;
  bool ShouldShowWindowTitle() const override;
  views::Widget* GetWidget() override;
  const views::Widget* GetWidget() const override;

  // Overridden from ui::WebDialogDelegate:
  ui::ModalType GetDialogModalType() const override;
  base::string16 GetDialogTitle() const override;
  GURL GetDialogContentURL() const override;
  void GetWebUIMessageHandlers(
      std::vector<ApplicationUIMessageHandler*>* handlers) const override;
  void GetDialogSize(gfx::Size* size) const override;
  void GetMinimumDialogSize(gfx::Size* size) const override;
  std::string GetDialogArgs() const override;
  void OnDialogShown(//content::WebUI* webui,
                     ApplicationHostWindow* render_view_host) override;
  void OnDialogClosed(const std::string& json_retval) override;
  void OnDialogCloseFromWebUI(const std::string& json_retval) override;
  void OnCloseContents(ApplicationContents* source,
                       bool* out_close_dialog) override;
  bool ShouldShowDialogTitle() const override;
  bool HandleContextMenu(const common::ContextMenuParams& params) override;

  // Overridden from content::WebContentsDelegate:
  void MoveContents(ApplicationContents* source,
                    const gfx::Rect& pos) override;
  void HandleKeyboardEvent(
      ApplicationContents* source,
      const NativeWebKeyboardEvent& event) override;
  void CloseContents(ApplicationContents* source) override;
  ApplicationContents* OpenURLFromTab(
      ApplicationContents* source,
      const OpenURLParams& params) override;
  void AddNewContents(ApplicationContents* source,
                      ApplicationContents* new_contents,
                      WindowOpenDisposition disposition,
                      const gfx::Rect& initial_rect,
                      bool user_gesture,
                      bool* was_blocked) override;
  void LoadingStateChanged(ApplicationContents* source,
                           bool to_different_document) override;
  void BeforeUnloadFired(ApplicationContents* tab,
                         bool proceed,
                         bool* proceed_to_fire_unload) override;
  bool ShouldCreateWebContents(
      ApplicationContents* web_contents,
      ApplicationHostWindow* opener,
      //content::SiteInstance* source_site_instance,
      int32_t route_id,
      int32_t main_frame_route_id,
      int32_t main_frame_widget_route_id,
      common::mojom::WindowContainerType window_container_type,
      const GURL& opener_url,
      const std::string& frame_name,
      const GURL& target_url) override;//,
      //const std::string& partition_id,
      //content::SessionStorageNamespace* session_storage_namespace) override;

 private:
  //FRIEND_TEST_ALL_PREFIXES(WebDialogBrowserTest, WebContentRendered);

  // Initializes the contents of the dialog.
  void InitDialog();

  // This view is a delegate to the HTML content since it needs to get notified
  // about when the dialog is closing. For all other actions (besides dialog
  // closing) we delegate to the creator of this view, which we keep track of
  // using this variable.
  ui::WebDialogDelegate* delegate_;

  ApplicationView* app_view_;

  // Whether user is attempting to close the dialog and we are processing
  // beforeunload event.
  bool is_attempting_close_dialog_ = false;

  // Whether beforeunload event has been fired and we have finished processing
  // beforeunload event.
  bool before_unload_fired_ = false;

  // Whether the dialog is closed from WebUI in response to a "dialogClose"
  // message.
  bool closed_via_webui_ = false;

  // A json string returned to WebUI from a "dialogClose" message.
  std::string dialog_close_retval_;

  // Whether CloseContents() has been called.
  bool close_contents_called_ = false;

  DISALLOW_COPY_AND_ASSIGN(ApplicationDialogView);
};

}  // namespace views

#endif  // UI_VIEWS_CONTROLS_WEBVIEW_WEB_DIALOG_VIEW_H_
