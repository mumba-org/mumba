// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/service_worker/controller_service_worker_connector.h"

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "mojo/public/cpp/bindings/interface_request.h"

namespace domain {

ControllerServiceWorkerConnector::ControllerServiceWorkerConnector(
    common::mojom::ServiceWorkerContainerHost* container_host)
    : container_host_(container_host) {}

ControllerServiceWorkerConnector::ControllerServiceWorkerConnector(
    common::mojom::ServiceWorkerContainerHost* container_host,
    common::mojom::ControllerServiceWorkerPtr controller_ptr,
    const std::string& client_id)
    : container_host_(container_host) {
  ResetControllerConnection(std::move(controller_ptr), client_id);
}

common::mojom::ControllerServiceWorker*
ControllerServiceWorkerConnector::GetControllerServiceWorker(
    common::mojom::ControllerServiceWorkerPurpose purpose) {
  switch (state_) {
    case State::kDisconnected:
      DCHECK(!controller_service_worker_);
      DCHECK(container_host_);
      container_host_->EnsureControllerServiceWorker(
          mojo::MakeRequest(&controller_service_worker_), purpose);
      controller_service_worker_.set_connection_error_handler(base::BindOnce(
          &ControllerServiceWorkerConnector::OnControllerConnectionClosed,
          base::Unretained(this)));
      state_ = State::kConnected;
      return controller_service_worker_.get();
    case State::kConnected:
      DCHECK(controller_service_worker_.is_bound());
      return controller_service_worker_.get();
    case State::kNoController:
      DCHECK(!controller_service_worker_);
      return nullptr;
    case State::kNoContainerHost:
      DCHECK(!controller_service_worker_);
      DCHECK(!container_host_);
      return nullptr;
  }
  NOTREACHED();
  return nullptr;
}

void ControllerServiceWorkerConnector::AddObserver(Observer* observer) {
  observer_list_.AddObserver(observer);
}

void ControllerServiceWorkerConnector::RemoveObserver(Observer* observer) {
  observer_list_.RemoveObserver(observer);
}

void ControllerServiceWorkerConnector::OnContainerHostConnectionClosed() {
  state_ = State::kNoContainerHost;
  container_host_ = nullptr;
  controller_service_worker_.reset();
}

void ControllerServiceWorkerConnector::OnControllerConnectionClosed() {
  DCHECK_EQ(State::kConnected, state_);
  state_ = State::kDisconnected;
  controller_service_worker_.reset();
  for (auto& observer : observer_list_)
    observer.OnConnectionClosed();
}

void ControllerServiceWorkerConnector::ResetControllerConnection(
    common::mojom::ControllerServiceWorkerPtr controller_ptr,
    const std::string& client_id) {
  if (state_ == State::kNoContainerHost)
    return;
  controller_service_worker_ = std::move(controller_ptr);
  if (controller_service_worker_) {
    DCHECK(client_id_.empty() || client_id_ == client_id);
    client_id_ = client_id;
    state_ = State::kConnected;
    controller_service_worker_.set_connection_error_handler(base::BindOnce(
        &ControllerServiceWorkerConnector::OnControllerConnectionClosed,
        base::Unretained(this)));
  } else {
    state_ = State::kNoController;
  }
}

ControllerServiceWorkerConnector::~ControllerServiceWorkerConnector() = default;

}  // namespace domain
