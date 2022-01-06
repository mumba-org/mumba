// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/webui/network_error_url_loader.h"

#include "base/strings/string_number_conversions.h"
#include "core/host/webui/url_data_manager_backend.h"
#include "core/shared/common/url_constants.h"
#include "net/base/net_errors.h"

namespace host {

void StartNetworkErrorsURLLoader(const network::ResourceRequest& request,
                                 network::mojom::URLLoaderClientPtr client) {
  int net_error = net::ERR_INVALID_URL;
  if (request.url.host() == kChromeUIDinoHost) {
    net_error = net::Error::ERR_INTERNET_DISCONNECTED;
  } else {
    std::string error_code_string = request.url.path().substr(1);

    int temp_code;
    if (base::StringToInt(error_code_string, &temp_code)) {
      // Check for a valid error code.
      if (URLDataManagerBackend::IsValidNetworkErrorCode(temp_code) &&
          temp_code != net::Error::ERR_IO_PENDING) {
        net_error = temp_code;
      }
    }
  }

  network::URLLoaderCompletionStatus status;
  status.error_code = net_error;
  client->OnComplete(status);
}

}  // namespace host
