// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/application/weburlresponse_extradata_impl.h"

namespace application {

WebURLResponseExtraDataImpl::WebURLResponseExtraDataImpl()
    : is_ftp_directory_listing_(false),
      effective_connection_type_(net::EFFECTIVE_CONNECTION_TYPE_UNKNOWN) {}

WebURLResponseExtraDataImpl::~WebURLResponseExtraDataImpl() {
}

}  // namespace content
