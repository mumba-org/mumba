// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/compositor/image_transport_factory.h"

#include "base/logging.h"

namespace host {
namespace {

ImageTransportFactory* g_image_transport_factory = nullptr;

}  // namespace

// static
void ImageTransportFactory::SetFactory(
    std::unique_ptr<ImageTransportFactory> factory) {
  DCHECK(!g_image_transport_factory);
  g_image_transport_factory = factory.release();
}

// static
void ImageTransportFactory::Terminate() {
  delete g_image_transport_factory;
  g_image_transport_factory = nullptr;
}

// static
ImageTransportFactory* ImageTransportFactory::GetInstance() {
  return g_image_transport_factory;
}

}  // namespace host
