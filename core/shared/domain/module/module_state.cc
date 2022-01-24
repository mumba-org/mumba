// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/module/module_state.h"

namespace domain {

ModuleState::ModuleState(Delegate* delegate): 
  delegate_(delegate) {
  
}

ModuleState::~ModuleState() {

}

P2PSocketDispatcher* ModuleState::socket_dispatcher() const {
  return delegate_->socket_dispatcher();
}

StorageManager* ModuleState::storage_manager() const {
  return delegate_->storage_manager();
}

RouteDispatcher* ModuleState::route_dispatcher() const {
  return delegate_->route_dispatcher();
}

common::mojom::ChannelRegistry* ModuleState::channel_registry() const {
  return delegate_->channel_registry();
}

common::mojom::RouteRegistry* ModuleState::route_registry() const {
  return delegate_->route_registry();
}

common::mojom::ServiceRegistry* ModuleState::service_registry() const {
  return delegate_->service_registry();
}

RepoDispatcher* ModuleState::repo_dispatcher() const {
  return delegate_->repo_dispatcher();
}

AppStoreDispatcher* ModuleState::app_store_dispatcher() const {
  return delegate_->app_store_dispatcher();
}

void ModuleState::CreateP2PSocket(
    int type, 
    int id, 
    const uint8_t* local_addr, 
    int local_port,
    uint16_t port_range_min,
    uint16_t port_range_max,
    const uint8_t* remote_addr, 
    int remote_port,
    void (*on_create)(void* data, int, int),
    void* data) {

  callbacks_.emplace(std::make_pair(id, on_create));

  delegate_->CreateP2PSocket(
    type, id, local_addr, local_port, port_range_min, 
    port_range_max, remote_addr, remote_port, 
    base::Bind(&ModuleState::OnSocketCreated, 
      base::Unretained(this), 
      base::Unretained(data)));
}

void ModuleState::CloseP2PSocket(int id) {
  delegate_->CloseP2PSocket(id);
}

void ModuleState::ForeachApplication(void* state, void(*foreach)(void* state, void* app_state, const char* name, const char* uuid, const char* url)) {
  delegate_->ForeachApplication(state, foreach);
}

void ModuleState::OnSocketCreated(void* data, int handle, int err) {
  auto it = callbacks_.find(handle);
  if (it != callbacks_.end()) {
    it->second(data, err, handle);
    callbacks_.erase(it);
  }
}

}