// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_WEB_PLATFORM_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_WEB_PLATFORM_H_

#include "third_party/WebKit/public/platform/Platform.h"

class WebPlatform : public blink::Platform {
public:
  WebPlatform();
  ~WebPlatform() override;

  void cryptographicallyRandomValues(unsigned char* buffer, size_t length) override;

private:

 DISALLOW_COPY_AND_ASSIGN(WebPlatform);
};

#endif