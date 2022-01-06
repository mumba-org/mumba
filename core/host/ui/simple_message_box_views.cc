// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/simple_message_box.h"

#include <utility>

#include "base/callback.h"
#include "base/compiler_specific.h"
#include "base/macros.h"
#include "base/message_loop/message_loop.h"
#include "base/run_loop.h"
#include "build/build_config.h"
//#include "core/host/ui/browser_dialogs.h"
//#include "core/host/ui/simple_message_box_internal.h"
#include "core/host/ui/simple_message_box_views.h"
#include "mumba/grit/generated_resources.h"
#include "components/constrained_window/constrained_window_views.h"
//#include "components/startup_metric_utils/browser/startup_metric_utils.h"
#include "components/strings/grit/components_strings.h"
#include "ui/base/l10n/l10n_util.h"
#include "ui/base/resource/resource_bundle.h"
#include "ui/base/ui_features.h"
#include "ui/gfx/native_widget_types.h"
#include "ui/views/controls/message_box_view.h"
#include "ui/views/widget/widget.h"
#include "ui/views/window/dialog_delegate.h"

#if defined(OS_WIN)
#include "ui/base/win/message_box_win.h"
#include "ui/views/win/hwnd_util.h"
#endif

#if defined(OS_MACOSX)
#include "chrome/browser/ui/cocoa/simple_message_box_cocoa.h"
#endif

namespace host {

namespace {
#if defined(OS_WIN)
UINT GetMessageBoxFlagsFromType(MessageBoxType type) {
  UINT flags = MB_SETFOREGROUND;
  switch (type) {
    case MESSAGE_BOX_TYPE_WARNING:
      return flags | MB_OK | MB_ICONWARNING;
    case MESSAGE_BOX_TYPE_QUESTION:
      return flags | MB_YESNO | MB_ICONQUESTION;
  }
  NOTREACHED();
  return flags | MB_OK | MB_ICONWARNING;
}
#endif

// static
MessageBoxResult ShowSync(gfx::NativeWindow parent,
                          const base::string16& title,
                          const base::string16& message,
                          MessageBoxType type,
                          const base::string16& yes_text,
                          const base::string16& no_text,
                          const base::string16& checkbox_text) {
  MessageBoxResult result = MESSAGE_BOX_RESULT_NO;

  // TODO(pkotwicz): Exit message loop when the dialog is closed by some other
  // means than |Cancel| or |Accept|. crbug.com/404385
  base::RunLoop run_loop(base::RunLoop::Type::kNestableTasksAllowed);

  SimpleMessageBoxViews::Show(
      parent, title, message, type, yes_text, no_text, checkbox_text,
      base::Bind(
          [](base::RunLoop* run_loop, MessageBoxResult* out_result,
             MessageBoxResult messagebox_result) {
            *out_result = messagebox_result;
            run_loop->Quit();
          },
          &run_loop, &result));

  run_loop.Run();
  return result;
}
}  // namespace

////////////////////////////////////////////////////////////////////////////////
// SimpleMessageBoxViews, public:

// static
MessageBoxResult SimpleMessageBoxViews::Show(
    gfx::NativeWindow parent,
    const base::string16& title,
    const base::string16& message,
    MessageBoxType type,
    const base::string16& yes_text,
    const base::string16& no_text,
    const base::string16& checkbox_text,
    SimpleMessageBoxViews::MessageBoxResultCallback callback) {
  if (!callback)
    return ShowSync(parent, title, message, type, yes_text, no_text,
                    checkbox_text);

  //startup_metric_utils::SetNonBrowserUIDisplayed();
  //if (internal::g_should_skip_message_box_for_test) {
//    std::move(callback).Run(MESSAGE_BOX_RESULT_YES);
  //  return MESSAGE_BOX_RESULT_DEFERRED;
  //}

// Views dialogs cannot be shown outside the UI thread message loop or if the
// ResourceBundle is not initialized yet.
// Fallback to logging with a default response or a Windows MessageBox.
#if defined(OS_WIN)
  if (!base::MessageLoopForUI::IsCurrent() ||
      !base::RunLoop::IsRunningOnCurrentThread() ||
      !ui::ResourceBundle::HasSharedInstance()) {
    LOG_IF(ERROR, !checkbox_text.empty()) << "Dialog checkbox won't be shown";
    int result = ui::MessageBox(views::HWNDForNativeWindow(parent), message,
                                title, GetMessageBoxFlagsFromType(type));
    std::move(callback).Run((result == IDYES || result == IDOK)
                                ? MESSAGE_BOX_RESULT_YES
                                : MESSAGE_BOX_RESULT_NO);
    return MESSAGE_BOX_RESULT_DEFERRED;
  }
#elif defined(OS_MACOSX)
  if (!base::MessageLoopForUI::IsCurrent() ||
      !base::RunLoop::IsRunningOnCurrentThread() ||
      !ui::ResourceBundle::HasSharedInstance()) {
    // Even though this function could return a value synchronously here in
    // principle, in practice call sites do not expect any behavior other than a
    // return of DEFERRED and an invocation of the callback.
    std::move(callback).Run(
        ShowMessageBoxCocoa(message, type, checkbox_text));
    return MESSAGE_BOX_RESULT_DEFERRED;
  }
#else
  if (!base::MessageLoopForUI::IsCurrent() ||
      !ui::ResourceBundle::HasSharedInstance()) {
    LOG(ERROR) << "Unable to show a dialog outside the UI thread message loop: "
               << title << " - " << message;
    std::move(callback).Run(MESSAGE_BOX_RESULT_NO);
    return MESSAGE_BOX_RESULT_DEFERRED;
  }
#endif

  bool is_system_modal = !parent;

#if defined(OS_MACOSX)
  // Mac does not support system modals, so never ask SimpleMessageBoxViews to
  // be system modal.
  is_system_modal = false;
#endif

  SimpleMessageBoxViews* dialog = new SimpleMessageBoxViews(
      title, message, type, yes_text, no_text, checkbox_text, is_system_modal);
  views::Widget* widget =
      constrained_window::CreateBrowserModalDialogViews(dialog, parent);

#if defined(OS_MACOSX)
  // Mac does not support system modal dialogs. If there is no parent window to
  // attach to, move the dialog's widget on top so other windows do not obscure
  // it.
  if (!parent)
    widget->SetAlwaysOnTop(true);
#endif

  widget->Show();
  dialog->Run(std::move(callback));
  return MESSAGE_BOX_RESULT_DEFERRED;
}

int SimpleMessageBoxViews::GetDialogButtons() const {
  if (type_ == MESSAGE_BOX_TYPE_QUESTION)
    return ui::DIALOG_BUTTON_OK | ui::DIALOG_BUTTON_CANCEL;

  return ui::DIALOG_BUTTON_OK;
}

base::string16 SimpleMessageBoxViews::GetDialogButtonLabel(
    ui::DialogButton button) const {
  if (button == ui::DIALOG_BUTTON_CANCEL)
    return no_text_;
  return yes_text_;
}

bool SimpleMessageBoxViews::Cancel() {
  result_ = MESSAGE_BOX_RESULT_NO;
  Done();
  return true;
}

bool SimpleMessageBoxViews::Accept() {
  if (!message_box_view_->HasCheckBox() ||
      message_box_view_->IsCheckBoxSelected()) {
    result_ = MESSAGE_BOX_RESULT_YES;
  } else {
    result_ = MESSAGE_BOX_RESULT_NO;
  }

  Done();
  return true;
}

base::string16 SimpleMessageBoxViews::GetWindowTitle() const {
  return window_title_;
}

void SimpleMessageBoxViews::DeleteDelegate() {
  delete this;
}

ui::ModalType SimpleMessageBoxViews::GetModalType() const {
  return is_system_modal_ ? ui::MODAL_TYPE_SYSTEM : ui::MODAL_TYPE_WINDOW;
}

views::View* SimpleMessageBoxViews::GetContentsView() {
  return message_box_view_;
}

views::Widget* SimpleMessageBoxViews::GetWidget() {
  return message_box_view_->GetWidget();
}

const views::Widget* SimpleMessageBoxViews::GetWidget() const {
  return message_box_view_->GetWidget();
}

void SimpleMessageBoxViews::OnWidgetActivationChanged(views::Widget* widget,
                                                      bool active) {
  if (!active)
    GetWidget()->Close();
}

////////////////////////////////////////////////////////////////////////////////
// SimpleMessageBoxViews, private:

SimpleMessageBoxViews::SimpleMessageBoxViews(
    const base::string16& title,
    const base::string16& message,
    MessageBoxType type,
    const base::string16& yes_text,
    const base::string16& no_text,
    const base::string16& checkbox_text,
    bool is_system_modal)
    : window_title_(title),
      type_(type),
      yes_text_(yes_text),
      no_text_(no_text),
      result_(MESSAGE_BOX_RESULT_NO),
      message_box_view_(new views::MessageBoxView(
          views::MessageBoxView::InitParams(message))),
      is_system_modal_(is_system_modal) {
  if (yes_text_.empty()) {
    yes_text_ =
        type_ == MESSAGE_BOX_TYPE_QUESTION
            ? l10n_util::GetStringUTF16(IDS_CONFIRM_MESSAGEBOX_YES_BUTTON_LABEL)
            : l10n_util::GetStringUTF16(IDS_OK);
  }

  if (no_text_.empty() && type_ == MESSAGE_BOX_TYPE_QUESTION)
    no_text_ = l10n_util::GetStringUTF16(IDS_CANCEL);

  if (!checkbox_text.empty())
    message_box_view_->SetCheckBoxLabel(checkbox_text);
  //RecordDialogCreation(DialogIdentifier::SIMPLE_MESSAGE_BOX);
}

SimpleMessageBoxViews::~SimpleMessageBoxViews() {
  GetWidget()->RemoveObserver(this);
}

void SimpleMessageBoxViews::Run(MessageBoxResultCallback result_callback) {
  GetWidget()->AddObserver(this);
  result_callback_ = std::move(result_callback);
}

void SimpleMessageBoxViews::Done() {
  CHECK(!result_callback_.is_null());
  std::move(result_callback_).Run(result_);
}

#if !defined(OS_MACOSX) || BUILDFLAG(MAC_VIEWS_BROWSER)
void ShowWarningMessageBox(gfx::NativeWindow parent,
                           const base::string16& title,
                           const base::string16& message) {
  SimpleMessageBoxViews::Show(
      parent, title, message, MESSAGE_BOX_TYPE_WARNING,
      base::string16(), base::string16(), base::string16());
}

void ShowWarningMessageBoxWithCheckbox(
    gfx::NativeWindow parent,
    const base::string16& title,
    const base::string16& message,
    const base::string16& checkbox_text,
    base::OnceCallback<void(bool checked)> callback) {
  SimpleMessageBoxViews::Show(
      parent, title, message, MESSAGE_BOX_TYPE_WARNING,
      base::string16(), base::string16(), checkbox_text,
      base::Bind(
          [](base::OnceCallback<void(bool checked)> callback,
             MessageBoxResult message_box_result) {
            std::move(callback).Run(message_box_result ==
                                    MESSAGE_BOX_RESULT_YES);
          },
          base::Passed(std::move(callback))));
}

MessageBoxResult ShowQuestionMessageBox(gfx::NativeWindow parent,
                                        const base::string16& title,
                                        const base::string16& message) {
  return SimpleMessageBoxViews::Show(
      parent, title, message, MESSAGE_BOX_TYPE_QUESTION,
      base::string16(), base::string16(), base::string16());
}

MessageBoxResult ShowMessageBoxWithButtonText(gfx::NativeWindow parent,
                                              const base::string16& title,
                                              const base::string16& message,
                                              const base::string16& yes_text,
                                              const base::string16& no_text) {
  return SimpleMessageBoxViews::Show(parent, title, message,
                                     MESSAGE_BOX_TYPE_QUESTION,
                                     yes_text, no_text, base::string16());
}

#endif  // !OS_MACOSX || BUILDFLAG(MAC_VIEWS_BROWSER)

}  // namespace chrome
