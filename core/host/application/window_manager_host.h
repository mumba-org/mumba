// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_DOMAIN_WINDOW_MANAGER_H_
#define MUMBA_HOST_APPLICATION_DOMAIN_WINDOW_MANAGER_H_

#include "base/macros.h"
#include "core/shared/common/mojom/window.mojom.h"
#include "mojo/public/cpp/bindings/associated_binding.h"
#include "mojo/public/cpp/bindings/associated_binding_set.h"
#include "mojo/public/cpp/bindings/interface_ptr.h"

namespace host {

/*
 * The shell process is a 'virtual' window manager
 * while host is the real window manager
 * The ping-pong here is the decision of doing anything
 * with a window is delegated to the shell, the shell then
 * asks for the real window manager (host) to actually execute 
 * the real window ops
 *
 * So we can both 'ask' some window op eg. 'minimize' from host to shell 
 * or shell can decide to minimize on its own and ask the host for the real
 * minimize op
 *
 * The shell is the window delegate (of the apps it controls) and even 
 * the host process respect that and route the ops first to the shell process.
 * 
 * at any time the host can deny a real window op request coming from the shell
 * (for instance for the lack of permissions to do so)
 *
 * Thats why the shell has the "WindowManagerHost" of this api contract
 * even when the real window manager is actually here on the host process
 */  

class WindowManagerHost : public common::mojom::WindowManagerHost {
public:
  WindowManagerHost();
  ~WindowManagerHost() override;

  common::mojom::WindowManagerClient* GetWindowManagerClientInterface();

  void AddBinding(common::mojom::WindowManagerHostAssociatedRequest request);

  void HostWindowLaunch(HostWindowLaunchCallback callback) override;
  void HostWindowClose(common::mojom::WindowHandlePtr handle, HostWindowCloseCallback callback) override;
  void HostWindowSetParent(common::mojom::WindowHandlePtr handle, common::mojom::WindowHandlePtr parent, HostWindowSetParentCallback callback) override;
  void HostWindowMaximize(common::mojom::WindowHandlePtr handle, HostWindowMaximizeCallback callback) override;
  void HostWindowMinimize(common::mojom::WindowHandlePtr handle, HostWindowMinimizeCallback callback) override;
  void HostWindowRestore(common::mojom::WindowHandlePtr handle, HostWindowRestoreCallback callback) override;
  void HostWindowSetFullscreen(common::mojom::WindowHandlePtr handle, bool fullscreen, HostWindowSetFullscreenCallback callback) override;
  void HostWindowActivate(common::mojom::WindowHandlePtr handle, HostWindowActivateCallback callback) override;
  void HostWindowSetTitle(common::mojom::WindowHandlePtr handle, const std::string& title, HostWindowSetTitleCallback callback) override;
  void HostWindowSetIcon(common::mojom::WindowHandlePtr handle, const std::string& url, HostWindowSetIconCallback callback) override;
  void HostWindowMove(common::mojom::WindowHandlePtr handle, HostWindowMoveCallback callback) override;
  void HostWindowSetSize(common::mojom::WindowHandlePtr handle, HostWindowSetSizeCallback callback) override;
  void HostWindowSetMinimumSize(common::mojom::WindowHandlePtr handle, HostWindowSetMinimumSizeCallback callback) override;
  void HostWindowSetMaximumSize(common::mojom::WindowHandlePtr handle, HostWindowSetMaximumSizeCallback callback) override;
  void HostWindowSetModal(common::mojom::WindowHandlePtr handle, HostWindowSetModalCallback callback) override;
  void HostWindowSetActivatable(common::mojom::WindowHandlePtr handle, bool activatable, HostWindowSetActivatableCallback callback) override;
  void HostWindowIsFullscreen(common::mojom::WindowHandlePtr handle, HostWindowIsFullscreenCallback callback) override;
  void HostWindowCanMaximize(common::mojom::WindowHandlePtr handle, HostWindowCanMaximizeCallback callback) override;
  void HostWindowCanMinimize(common::mojom::WindowHandlePtr handle, HostWindowCanMinimizeCallback callback) override;
  void HostWindowGetTitle(common::mojom::WindowHandlePtr handle, HostWindowGetTitleCallback callback) override;
  void HostWindowGetIcon(common::mojom::WindowHandlePtr handle, HostWindowGetIconCallback callback) override;
  void HostWindowCanResize(common::mojom::WindowHandlePtr handle, HostWindowCanResizeCallback callback) override;
  void HostWindowGetSize(common::mojom::WindowHandlePtr handle) override;
  void HostWindowGetMinimumSize(common::mojom::WindowHandlePtr handle) override;
  void HostWindowGetMaximumSize(common::mojom::WindowHandlePtr handle) override;
  void HostWindowPageNew(common::mojom::WindowHandlePtr window, const std::string& title, HostWindowPageNewCallback callback) override;
  void HostWindowPageClose(common::mojom::PageHandlePtr page, HostWindowPageCloseCallback callback) override;
  void HostWindowPageList(common::mojom::WindowHandlePtr window, HostWindowPageListCallback callback) override;

private:
  friend class DomainProcessHost;
  common::mojom::WindowManagerClientAssociatedPtr window_manager_client_interface_;
  mojo::AssociatedBinding<common::mojom::WindowManagerHost> window_manager_host_binding_;

  DISALLOW_COPY_AND_ASSIGN(WindowManagerHost);
};

}

#endif