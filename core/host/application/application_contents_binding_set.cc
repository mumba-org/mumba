// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/application_contents_binding_set.h"

#include <utility>

#include "base/logging.h"
#include "core/host/application/application_contents.h"

namespace host {

void ApplicationContentsBindingSet::Binder::OnRequestForWindow(
    ApplicationWindowHost* window_host,
    mojo::ScopedInterfaceEndpointHandle handle) {
  NOTREACHED();
}

ApplicationContentsBindingSet::ApplicationContentsBindingSet(ApplicationContents* application_contents,
                                             const std::string& interface_name,
                                             std::unique_ptr<Binder> binder)
    : remove_callback_(static_cast<ApplicationContents*>(application_contents)
                           ->AddBindingSet(interface_name, this)),
      binder_(std::move(binder)) {}

ApplicationContentsBindingSet::~ApplicationContentsBindingSet() {
  remove_callback_.Run();
}

// static
ApplicationContentsBindingSet* ApplicationContentsBindingSet::GetForApplicationContents(
    ApplicationContents* application_contents,
    const char* interface_name) {
  return static_cast<ApplicationContents*>(application_contents)
      ->GetBindingSet(interface_name);
}

void ApplicationContentsBindingSet::CloseAllBindings() {
  binder_for_testing_.reset();
  binder_.reset();
}

void ApplicationContentsBindingSet::OnRequestForWindow(
    ApplicationWindowHost* app_window_host,
    mojo::ScopedInterfaceEndpointHandle handle) {
  if (binder_for_testing_) {
    binder_for_testing_->OnRequestForWindow(app_window_host,
                                            std::move(handle));
    return;
  }
  DCHECK(binder_);
  binder_->OnRequestForWindow(app_window_host, std::move(handle));
}

}  // namespace host
