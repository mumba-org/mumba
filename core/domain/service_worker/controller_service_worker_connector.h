// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CORE_DOMAIN_SERVICE_WORKER_CONTROLLER_SERVICE_WORKER_CONNECTOR_H_
#define CORE_DOMAIN_SERVICE_WORKER_CONTROLLER_SERVICE_WORKER_CONNECTOR_H_

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/observer_list.h"
#include "core/shared/common/content_export.h"
#include "core/shared/common/service_worker/controller_service_worker.mojom.h"
#include "core/shared/common/service_worker/service_worker_container.mojom.h"

namespace domain {

namespace mojom {
class ServiceWorkerContainerHost;
}  // namespace mojom

// Vends a connection to the controller service worker for a given
// ServiceWorkerContainerHost. This is co-owned by
// ServiceWorkerProviderContext::ControlleeState and
// ServiceWorkerSubresourceLoader{,Factory}.
class CONTENT_EXPORT ControllerServiceWorkerConnector
    : public base::RefCounted<ControllerServiceWorkerConnector> {
 public:
  // Observes the connection to the controller.
  class Observer {
   public:
    virtual void OnConnectionClosed() = 0;
  };

  enum class State {
    // The controller connection is dropped. Calling
    // GetControllerServiceWorker() in this state will result in trying to
    // get the new controller pointer from the browser.
    kDisconnected,

    // The controller connection is established.
    kConnected,

    // It is notified that the client lost the controller. This could only
    // happen due to an exceptional condition like the service worker could
    // no longer be read from the script cache. Calling
    // GetControllerServiceWorker() in this state will always return nullptr.
    kNoController,

    // The container host is shutting down. Calling
    // GetControllerServiceWorker() in this state will always return nullptr.
    kNoContainerHost,
  };

  // Use this ctor when no |controller_ptr| is available at creation time.
  // |state_| is set to kDisconnected.
  // TODO(bashi): Remove this one constructor. We need to update
  // WorkerFetchContextImpl to remove this constructor.
  explicit ControllerServiceWorkerConnector(
      common::mojom::ServiceWorkerContainerHost* container_host);

  // Use this ctor when |controller_ptr| is given by the browser at the
  // creation time. |state_| is set to either kConnected or kNoController.
  ControllerServiceWorkerConnector(
      common::mojom::ServiceWorkerContainerHost* container_host,
      common::mojom::ControllerServiceWorkerPtr controller_ptr,
      const std::string& client_id);

  // This may return nullptr if the connection to the ContainerHost (in the
  // browser process) is already terminated.
  common::mojom::ControllerServiceWorker* GetControllerServiceWorker(
      common::mojom::ControllerServiceWorkerPurpose purpose);

  void AddObserver(Observer* observer);
  void RemoveObserver(Observer* observer);

  void OnContainerHostConnectionClosed();
  void OnControllerConnectionClosed();

  // Resets the controller connection with the given |controller_ptr|, this
  // can be called when a new controller is given, e.g. due to claim().
  void ResetControllerConnection(
      common::mojom::ControllerServiceWorkerPtr controller_ptr,
      const std::string& client_id);

  State state() const { return state_; }

  const std::string& client_id() const { return client_id_; }

 private:
  State state_ = State::kDisconnected;

  friend class base::RefCounted<ControllerServiceWorkerConnector>;
  ~ControllerServiceWorkerConnector();

  // Connection to the ServiceWorkerProviderHost that lives in the
  // browser process. This is used to (re-)obtain Mojo connection to
  // |controller_service_worker_| when it is not established.
  // Cleared when the connection is dropped.
  common::mojom::ServiceWorkerContainerHost* container_host_;

  // Connection to the ControllerServiceWorker. The consumer of this connection
  // should not need to know which process this is connected to.
  // (Currently this is connected to BrowserSideControllerServiceWorker,
  // but will eventually be directly connected to the controller service worker
  // in the renderer process)
  common::mojom::ControllerServiceWorkerPtr controller_service_worker_;

  base::ObserverList<Observer> observer_list_;

  // The web-exposed client id, used for FetchEvent#clientId (i.e.,
  // ServiceWorkerProviderHost::client_uuid and not
  // ServiceWorkerProviderHost::provider_id).
  std::string client_id_;

  DISALLOW_COPY_AND_ASSIGN(ControllerServiceWorkerConnector);
};

}  // namespace domain

#endif  // CORE_DOMAIN_SERVICE_WORKER_CONTROLLER_SERVICE_WORKER_CONNECTOR_H_
