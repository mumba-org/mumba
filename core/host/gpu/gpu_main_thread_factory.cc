// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/gpu/gpu_main_thread_factory.h"

namespace host {
namespace {

GpuMainThreadFactoryFunction g_gpu_main_thread_factory = nullptr;

}  // namespace

void RegisterGpuMainThreadFactory(GpuMainThreadFactoryFunction create) {
  g_gpu_main_thread_factory = create;
}

GpuMainThreadFactoryFunction GetGpuMainThreadFactory() {
  return g_gpu_main_thread_factory;
}

}  // namespace host
