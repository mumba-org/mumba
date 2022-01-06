// Copyright 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/application/application_instance.h"

namespace domain {

ApplicationInstance::ApplicationInstance() {

}

ApplicationInstance::~ApplicationInstance() {
  //DLOG(INFO) << "~ApplicationInstance";
  //DCHECK(false);
}

Application* ApplicationInstance::application() const {
  return application_;
}

void ApplicationInstance::set_application(Application* application) {
  application_ = application;
}

WindowInstance* ApplicationInstance::window() const {
  return window_;
}

void ApplicationInstance::set_window(WindowInstance* window) {
  window_ = window;
}

int ApplicationInstance::id() const {
  return id_;
}

void ApplicationInstance::set_id(int id) {
  id_ = id;
}

const std::string& ApplicationInstance::url() const {
  return url_;
}

void ApplicationInstance::set_url(const std::string& url) {
  url_ = url;
}

const base::UUID& ApplicationInstance::uuid() const {
  return uuid_;
}

void ApplicationInstance::set_uuid(const base::UUID& uuid) {
  uuid_ = uuid;
}

ApplicationState ApplicationInstance::state() const {
  return state_;
}

void ApplicationInstance::set_state(ApplicationState state) {
  state_ = state;
}

}