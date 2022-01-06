// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MEDIA_MEDIA_REQUEST_STATE_H_
#define MUMBA_HOST_MEDIA_MEDIA_REQUEST_STATE_H_

namespace host {

enum MediaRequestState {
  MEDIA_REQUEST_STATE_NOT_REQUESTED = 0,
  MEDIA_REQUEST_STATE_REQUESTED,
  MEDIA_REQUEST_STATE_PENDING_APPROVAL,
  MEDIA_REQUEST_STATE_OPENING,
  MEDIA_REQUEST_STATE_DONE,
  MEDIA_REQUEST_STATE_CLOSING,
  MEDIA_REQUEST_STATE_ERROR
};

}  // namespace host

#endif  // CONTENT_PUBLIC_BROWSER_MEDIA_REQUEST_STATE_H_
