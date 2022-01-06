// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "CoreShims.h"

#include "Sandbox.h"
#include "Runtime.h"

#include "base/base64url.h"

int _RuntimeInit() {
  return Runtime::Init() ? 1 : 0;
}

int _SandboxEnter(void) {
  Sandbox* sandbox = Sandbox::GetInstance();
  return sandbox->Enter() ? 1 : 0;
}

void _RuntimeMainLoopRun() {
  Runtime::RunMainLoop();
}

void _RuntimeShutdown() {
  Runtime::Shutdown();
}

char* Base64UrlDecode(const char* input, int len, int* out_len) {
  base::StringPiece data(input, len);
  std::string out_string;
  if (!base::Base64UrlDecode(data,
                             base::Base64UrlDecodePolicy::IGNORE_PADDING,
                             &out_string)) {

    return nullptr;
  }
  *out_len = out_string.size();
  char* out = (char *)malloc(out_string.size());
  memcpy(out, out_string.data(), out_string.size());
  return out;
}