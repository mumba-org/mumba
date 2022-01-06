// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_PRESENTATION_REQUEST_H_
#define MUMBA_HOST_APPLICATION_PRESENTATION_REQUEST_H_

#include <utility>
#include <vector>

#include "core/shared/common/content_export.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace host {

// Represents a presentation request made from a render frame. Contains a list
// of presentation URLs of the request, and information on the originating
// frame.
struct CONTENT_EXPORT PresentationRequest {
 public:
  PresentationRequest(const std::pair<int, int>& render_frame_host_id,
                      const std::vector<GURL>& presentation_urls,
                      const url::Origin& frame_origin);
  ~PresentationRequest();

  PresentationRequest(const PresentationRequest& other);
  PresentationRequest& operator=(const PresentationRequest& other);

  // ID of RenderFrameHost that initiated the request.
  std::pair<int, int> render_frame_host_id;

  // URLs of presentation.
  std::vector<GURL> presentation_urls;

  // Origin of frame from which the request was initiated.
  url::Origin frame_origin;
};

}  // namespace host

#endif  // CONTENT_PUBLIC_BROWSER_PRESENTATION_REQUEST_H_
