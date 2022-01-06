// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MEDIA_SESSION_MEDIA_METADATA_SANITIZER_H_
#define MUMBA_HOST_MEDIA_SESSION_MEDIA_METADATA_SANITIZER_H_

namespace common {
struct MediaMetadata;  
}

namespace host {

class MediaMetadataSanitizer {
 public:
  // Check the sanity of |metadata|.
  static bool CheckSanity(const common::MediaMetadata& metadata);

  // Sanitizes |metadata| and return the result.
  static common::MediaMetadata Sanitize(const common::MediaMetadata& metadata);
};

}  // namespace host

#endif  // MUMBA_HOST_MEDIA_SESSION_MEDIA_METADATA_SANITIZER_H_
