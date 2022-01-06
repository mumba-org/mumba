// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/launcher/launcher_client.h"

#include "base/uuid.h"
#include "base/files/file_path.h"
#include "base/task_scheduler/post_task.h"
#include "core/domain/domain_process.h"
#include "core/domain/domain_context.h"
#include "core/domain/domain_main_thread.h"

namespace domain {

LauncherClient::LauncherClient():
 binding_(this),
 //handler_(new Handler()),
 weak_factory_(this) {}
 
LauncherClient::~LauncherClient() {}

void LauncherClient::Bind(common::mojom::LauncherClientAssociatedRequest request) {
  binding_.Bind(std::move(request));
}

void LauncherClient::Noop() {

}

}