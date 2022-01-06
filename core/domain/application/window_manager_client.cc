// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/application/window_manager_client.h"

#include "base/uuid.h"
#include "base/files/file_path.h"
#include "base/task_scheduler/post_task.h"
#include "core/domain/domain_process.h"
#include "core/domain/domain_context.h"
#include "core/domain/domain_main_thread.h"

namespace domain {

class WindowManagerClient::Handler : public base::RefCountedThreadSafe<Handler> {
public:
  Handler() {}

  common::mojom::WindowHandlePtr LaunchWindow(scoped_refptr<DomainContext> shell, const std::string& url) {
    LOG(INFO) << "shell process: received LaunchWindow: pseudo-lançando url '" << url << "'";
    return common::mojom::WindowHandlePtr{};
  }

private:
  friend class base::RefCountedThreadSafe<Handler>;

  ~Handler() {}
};

WindowManagerClient::WindowManagerClient():
 binding_(this),
 handler_(new Handler()),
 weak_factory_(this) {}
 
WindowManagerClient::~WindowManagerClient() {}

void WindowManagerClient::Bind(common::mojom::WindowManagerClientAssociatedRequest request) {
  binding_.Bind(std::move(request));
}

void WindowManagerClient::ClientWindowLaunch(const std::string& url, ClientWindowLaunchCallback callback) {
  DomainMainThread* main_thread = DomainMainThread::current();
  
  base::PostTaskWithTraitsAndReplyWithResult(
    FROM_HERE,
    { base::MayBlock(),
      base::TaskPriority::USER_BLOCKING},
     base::Bind(
       &Handler::LaunchWindow,
       handler_,
       main_thread->domain_context(), 
       url),
     base::Bind(&WindowManagerClient::ReplyWindowLaunch,
      weak_factory_.GetWeakPtr(),
      base::Passed(std::move(callback))));
}

void WindowManagerClient::ClientWindowClose(common::mojom::WindowHandlePtr handle, ClientWindowCloseCallback callback) {

}

void WindowManagerClient::ClientWindowSetParent(common::mojom::WindowHandlePtr handle, common::mojom::WindowHandlePtr parent, ClientWindowSetParentCallback callback) {

}

void WindowManagerClient::ClientWindowCanMaximize(common::mojom::WindowHandlePtr handle, ClientWindowCanMaximizeCallback callback) {

}

void WindowManagerClient::ClientWindowMaximize(common::mojom::WindowHandlePtr handle, ClientWindowMaximizeCallback callback) {

}

void WindowManagerClient::ClientWindowCanMinimize(common::mojom::WindowHandlePtr handle, ClientWindowCanMinimizeCallback callback) {

}

void WindowManagerClient::ClientWindowMinimize(common::mojom::WindowHandlePtr handle, ClientWindowMinimizeCallback callback) {

}

void WindowManagerClient::ClientWindowRestore(common::mojom::WindowHandlePtr handle, ClientWindowRestoreCallback callback) {

}

void WindowManagerClient::ClientWindowIsFullscreen(common::mojom::WindowHandlePtr handle, ClientWindowIsFullscreenCallback callback) {

}

void WindowManagerClient::ClientWindowSetFullscreen(common::mojom::WindowHandlePtr handle, bool fullscreen, ClientWindowSetFullscreenCallback callback) {

}

void WindowManagerClient::ClientWindowActivate(common::mojom::WindowHandlePtr handle, ClientWindowActivateCallback callback) {

}

void WindowManagerClient::ClientWindowSetTitle(common::mojom::WindowHandlePtr handle, const std::string& title, ClientWindowSetTitleCallback callback) {

}

void WindowManagerClient::ClientWindowGetTitle(common::mojom::WindowHandlePtr handle, ClientWindowGetTitleCallback callback) {

}

void WindowManagerClient::ClientWindowSetIcon(common::mojom::WindowHandlePtr handle, const std::string& url, ClientWindowSetIconCallback callback) {

}

void WindowManagerClient::ClientWindowGetIcon(common::mojom::WindowHandlePtr handle, ClientWindowGetIconCallback callback) {

}

void WindowManagerClient::ClientWindowMove(common::mojom::WindowHandlePtr handle, ClientWindowMoveCallback callback) {

}

void WindowManagerClient::ClientWindowCanResize(common::mojom::WindowHandlePtr handle, ClientWindowCanResizeCallback callback) {

}

void WindowManagerClient::ClientWindowGetSize(common::mojom::WindowHandlePtr handle) {

}

void WindowManagerClient::ClientWindowSetSize(common::mojom::WindowHandlePtr handle, ClientWindowSetSizeCallback callback) {

}

void WindowManagerClient::ClientWindowGetMinimumSize(common::mojom::WindowHandlePtr handle) {

}

void WindowManagerClient::ClientWindowSetMinimumSize(common::mojom::WindowHandlePtr handle, ClientWindowSetMinimumSizeCallback callback) {

}

void WindowManagerClient::ClientWindowGetMaximumSize(common::mojom::WindowHandlePtr handle) {

}

void WindowManagerClient::ClientWindowSetMaximumSize(common::mojom::WindowHandlePtr handle, ClientWindowSetMaximumSizeCallback callback) {

}

void WindowManagerClient::ClientWindowSetModal(common::mojom::WindowHandlePtr handle, ClientWindowSetModalCallback callback) {

}

void WindowManagerClient::ClientWindowSetActivatable(common::mojom::WindowHandlePtr handle, bool activatable, ClientWindowSetActivatableCallback callback) {

}

void WindowManagerClient::ClientWindowPageNew(common::mojom::WindowHandlePtr window, const std::string& url, ClientWindowPageNewCallback callback) {

}

void WindowManagerClient::ClientWindowPageClose(common::mojom::PageHandlePtr page, ClientWindowPageCloseCallback callback) {

}

void WindowManagerClient::ClientWindowPageList(common::mojom::WindowHandlePtr window, ClientWindowPageListCallback callback) {

}

void WindowManagerClient::ReplyWindowLaunch(ClientWindowLaunchCallback callback, common::mojom::WindowHandlePtr window_info) {
  common::mojom::DomainStatus status = common::mojom::DomainStatus::kOk;//window_info ? common::mojom::DomainStatus::kOk : common::mojom::DomainStatus::kError;
  std::move(callback).Run(status, std::move(window_info));
}

}