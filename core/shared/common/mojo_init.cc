// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/common/mojo_init.h"

#include <memory>

#include "base/command_line.h"
#include "base/lazy_instance.h"
#include "core/shared/common/switches.h"
#include "ipc/ipc_channel.h"
#include "mojo/edk/embedder/configuration.h"
#include "mojo/edk/embedder/embedder.h"

namespace common {

namespace {

class MojoInitializer {
 public:
  MojoInitializer() {
    mojo::edk::Configuration config;
    config.max_message_num_bytes = IPC::Channel::kMaximumMessageSize;
    mojo::edk::Init(config);
  }
};

base::LazyInstance<MojoInitializer>::Leaky mojo_initializer;

}  //  namespace

void InitializeMojo() {
  mojo_initializer.Get();
}

}  // namespace content
