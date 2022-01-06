// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/context_factory.h"

#include "base/logging.h"
#include "core/host/compositor/image_transport_factory.h"

namespace host {

ui::ContextFactory* GetContextFactory() {
  DCHECK(ImageTransportFactory::GetInstance());
  return ImageTransportFactory::GetInstance()->GetContextFactory();
}

ui::ContextFactoryPrivate* GetContextFactoryPrivate() {
  DCHECK(ImageTransportFactory::GetInstance());
  return ImageTransportFactory::GetInstance()->GetContextFactoryPrivate();
}

}  // namespace host
