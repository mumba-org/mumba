// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/runnable.h"

#include "core/host/application/runnable_process.h"
#include "core/common/protocol/message_serialization.h"

namespace host {

Runnable::Runnable(
  RunnableManager* manager, 
  Domain* domain,
  int id, 
  const std::string& name, 
  const std::string& url, 
  const base::UUID& uuid): 
  uuid_(uuid),
  state_(RunnableState::INIT),
  manager_(manager),
  domain_(domain) {

  proto_.set_id(id);
  proto_.set_uuid(std::string(reinterpret_cast<const char *>(uuid_.data), 16));
  proto_.set_name(name);
  proto_.set_url(url); 
}

Runnable::Runnable(RunnableManager* manager, Domain* domain, protocol::Application proto):
  proto_(std::move(proto)),
  state_(RunnableState::INIT),
  manager_(manager),
  domain_(domain) {
  bool ok = false;
  uuid_ = base::UUID::from_string(proto_.uuid(), &ok);
  //DCHECK(ok);
}

Runnable::~Runnable() {

}

int Runnable::id() const {
  return proto_.id();
}

const base::UUID& Runnable::uuid() const {
  return uuid_;
}
  
const std::string& Runnable::name() const {
  return proto_.name();
}

const std::string& Runnable::url_string() const {
  return proto_.url();
}

GURL Runnable::url() const {
  return GURL(proto_.url());
}

RunnableState Runnable::state() {
  return state_;
}

void Runnable::set_state(RunnableState state) {
  state_ = state;
}

common::mojom::Application* Runnable::GetApplicationInterface() {
  return process()->GetApplicationInterface();
}

bool Runnable::Shutdown(int exit_code) {
  return process()->Shutdown(exit_code);
}

scoped_refptr<net::IOBufferWithSize> Runnable::Serialize() const {
  return protocol::SerializeMessage(proto_);
}

}