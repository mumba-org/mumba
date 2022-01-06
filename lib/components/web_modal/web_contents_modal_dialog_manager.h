// Copyright 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_WEB_MODAL_APPLICATION_CONTENTS_MODAL_DIALOG_MANAGER_H_
#define COMPONENTS_WEB_MODAL_APPLICATION_CONTENTS_MODAL_DIALOG_MANAGER_H_

#include <memory>

#include "base/containers/circular_deque.h"
#include "base/macros.h"
#include "build/build_config.h"
#include "components/web_modal/single_application_contents_dialog_manager.h"
#include "content/public/browser/application_contents_observer.h"
#include "content/public/browser/application_contents_user_data.h"
#include "ui/gfx/native_widget_types.h"

namespace web_modal {

class ApplicationContentsModalDialogManagerDelegate;

// Per-ApplicationContents class to manage ApplicationContents-modal dialogs.
class ApplicationContentsModalDialogManager
    : public SingleApplicationContentsDialogManagerDelegate,
      public host::ApplicationContentsObserver,
      public host::ApplicationContentsUserData<ApplicationContentsModalDialogManager> {
 public:
  ~ApplicationContentsModalDialogManager() override;

  ApplicationContentsModalDialogManagerDelegate* delegate() const { return delegate_; }
  void SetDelegate(ApplicationContentsModalDialogManagerDelegate* d);

#if defined(OS_MACOSX)
  // Note: This method is not defined inside components/web_modal/ as its
  // definition (needed for Cocoa builds) depends on chrome/browser/ui/cocoa/.
  static SingleApplicationContentsDialogManager* CreateNativeWebModalManager(
      gfx::NativeWindow dialog,
      SingleApplicationContentsDialogManagerDelegate* native_delegate);
#endif

  // Allow clients to supply their own native dialog manager. Suitable for
  // bubble clients.
  void ShowDialogWithManager(
      gfx::NativeWindow dialog,
      std::unique_ptr<SingleApplicationContentsDialogManager> manager);

  // Returns true if any dialogs are active and not closed.
  bool IsDialogActive() const;

  // Focus the topmost modal dialog.  IsDialogActive() must be true when calling
  // this function.
  void FocusTopmostDialog() const;

  // SingleApplicationContentsDialogManagerDelegate:
  host::ApplicationContents* GetApplicationContents() const override;
  void WillClose(gfx::NativeWindow dialog) override;

  // For testing.
  class TestApi {
   public:
    explicit TestApi(ApplicationContentsModalDialogManager* manager)
        : manager_(manager) {}

    void CloseAllDialogs() { manager_->CloseAllDialogs(); }
    void DidAttachInterstitialPage() { manager_->DidAttachInterstitialPage(); }
    void ApplicationContentsVisibilityChanged(content::Visibility visibility) {
      manager_->OnVisibilityChanged(visibility);
    }

   private:
    ApplicationContentsModalDialogManager* manager_;

    DISALLOW_COPY_AND_ASSIGN(TestApi);
  };

 private:
  explicit ApplicationContentsModalDialogManager(host::ApplicationContents* application_contents);
  friend class host::ApplicationContentsUserData<ApplicationContentsModalDialogManager>;

  struct DialogState {
    DialogState(gfx::NativeWindow dialog,
                std::unique_ptr<SingleApplicationContentsDialogManager> manager);
    DialogState(DialogState&& state);
    ~DialogState();

    gfx::NativeWindow dialog;
    std::unique_ptr<SingleApplicationContentsDialogManager> manager;
  };

  using ApplicationContentsModalDialogList = base::circular_deque<DialogState>;

  // Blocks/unblocks interaction with renderer process.
  void BlockApplicationContentsInteraction(bool blocked);

  bool IsApplicationContentsVisible() const;

  // Closes all ApplicationContentsModalDialogs.
  void CloseAllDialogs();

  // Overridden from host::ApplicationContentsObserver:
  void DidFinishNavigation(
      content::NavigationHandle* navigation_handle) override;
  void DidGetIgnoredUIEvent() override;
  void OnVisibilityChanged(content::Visibility visibility) override;
  void ApplicationContentsDestroyed() override;
  void DidAttachInterstitialPage() override;

  // Delegate for notifying our owner about stuff. Not owned by us.
  ApplicationContentsModalDialogManagerDelegate* delegate_;

  // All active dialogs.
  ApplicationContentsModalDialogList child_dialogs_;

  // Whether the ApplicationContents' visibility is content::Visibility::HIDDEN.
  bool application_contents_is_hidden_;

  // True while closing the dialogs on ApplicationContents close.
  bool closing_all_dialogs_;

  DISALLOW_COPY_AND_ASSIGN(ApplicationContentsModalDialogManager);
};

}  // namespace web_modal

#endif  // COMPONENTS_WEB_MODAL_APPLICATION_CONTENTS_MODAL_DIALOG_MANAGER_H_
