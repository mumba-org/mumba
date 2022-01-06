// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_WINDOW_DISPATCHER_H_
#define MUMBA_DOMAIN_WINDOW_DISPATCHER_H_

#include "base/macros.h"

#include "core/shared/common/mojom/objects.mojom.h"
#include "core/shared/common/mojom/window.mojom.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "mojo/public/cpp/bindings/associated_binding.h"

namespace domain {

class WindowManagerClient : public common::mojom::WindowManagerClient {
public:
  WindowManagerClient();
  ~WindowManagerClient() override;

  void Bind(common::mojom::WindowManagerClientAssociatedRequest request);

  void ClientWindowLaunch(const std::string& url, ClientWindowLaunchCallback callback) override;
  void ClientWindowClose(common::mojom::WindowHandlePtr handle, ClientWindowCloseCallback callback) override;
  void ClientWindowSetParent(common::mojom::WindowHandlePtr handle, common::mojom::WindowHandlePtr parent, ClientWindowSetParentCallback callback) override;
  void ClientWindowCanMaximize(common::mojom::WindowHandlePtr handle, ClientWindowCanMaximizeCallback callback) override;
  void ClientWindowMaximize(common::mojom::WindowHandlePtr handle, ClientWindowMaximizeCallback callback) override;
  void ClientWindowCanMinimize(common::mojom::WindowHandlePtr handle, ClientWindowCanMinimizeCallback callback) override;
  void ClientWindowMinimize(common::mojom::WindowHandlePtr handle, ClientWindowMinimizeCallback callback) override;
  void ClientWindowRestore(common::mojom::WindowHandlePtr handle, ClientWindowRestoreCallback callback) override;
  void ClientWindowIsFullscreen(common::mojom::WindowHandlePtr handle, ClientWindowIsFullscreenCallback callback) override;
  void ClientWindowSetFullscreen(common::mojom::WindowHandlePtr handle, bool fullscreen, ClientWindowSetFullscreenCallback callback) override;
  void ClientWindowActivate(common::mojom::WindowHandlePtr handle, ClientWindowActivateCallback callback) override;
  void ClientWindowSetTitle(common::mojom::WindowHandlePtr handle, const std::string& title, ClientWindowSetTitleCallback callback) override;
  void ClientWindowGetTitle(common::mojom::WindowHandlePtr handle, ClientWindowGetTitleCallback callback) override;
  void ClientWindowSetIcon(common::mojom::WindowHandlePtr handle, const std::string& url, ClientWindowSetIconCallback callback) override;
  void ClientWindowGetIcon(common::mojom::WindowHandlePtr handle, ClientWindowGetIconCallback callback) override;
  void ClientWindowMove(common::mojom::WindowHandlePtr handle, ClientWindowMoveCallback callback) override;
  void ClientWindowCanResize(common::mojom::WindowHandlePtr handle, ClientWindowCanResizeCallback callback) override;
  void ClientWindowGetSize(common::mojom::WindowHandlePtr handle) override;
  void ClientWindowSetSize(common::mojom::WindowHandlePtr handle, ClientWindowSetSizeCallback callback) override;
  void ClientWindowGetMinimumSize(common::mojom::WindowHandlePtr handle) override;
  void ClientWindowSetMinimumSize(common::mojom::WindowHandlePtr handle, ClientWindowSetMinimumSizeCallback callback) override;
  void ClientWindowGetMaximumSize(common::mojom::WindowHandlePtr handle) override;
  void ClientWindowSetMaximumSize(common::mojom::WindowHandlePtr handle, ClientWindowSetMaximumSizeCallback callback) override;
  void ClientWindowSetModal(common::mojom::WindowHandlePtr handle, ClientWindowSetModalCallback callback) override;
  void ClientWindowSetActivatable(common::mojom::WindowHandlePtr handle, bool activatable, ClientWindowSetActivatableCallback callback) override;
  void ClientWindowPageNew(common::mojom::WindowHandlePtr window, const std::string& url, ClientWindowPageNewCallback callback) override;
  void ClientWindowPageClose(common::mojom::PageHandlePtr page, ClientWindowPageCloseCallback callback) override;
  void ClientWindowPageList(common::mojom::WindowHandlePtr window, ClientWindowPageListCallback callback) override;
  
private:
  class Handler;

  void ReplyWindowLaunch(ClientWindowLaunchCallback callback, common::mojom::WindowHandlePtr window_info);

  mojo::AssociatedBinding<common::mojom::WindowManagerClient> binding_;

  scoped_refptr<Handler> handler_;

  base::WeakPtrFactory<WindowManagerClient> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(WindowManagerClient);
};

}

#endif