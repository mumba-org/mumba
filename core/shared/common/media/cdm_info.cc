// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/common/media/cdm_info.h"

#include "base/guid.h"
#include "base/logging.h"

namespace common {

CdmInfo::CdmInfo(const std::string& name,
                 const std::string& guid,
                 const base::Version& version,
                 const base::FilePath& path,
                 const std::string& file_system_id,
                 const std::vector<media::VideoCodec>& supported_video_codecs,
                 bool supports_persistent_license,
                 const std::string& supported_key_system,
                 bool supports_sub_key_systems)
    : name(name),
      guid(guid),
      version(version),
      path(path),
      file_system_id(file_system_id),
      supported_video_codecs(supported_video_codecs),
      supports_persistent_license(supports_persistent_license),
      supported_key_system(supported_key_system),
      supports_sub_key_systems(supports_sub_key_systems) {
  DCHECK(base::IsValidGUID(guid));
}

CdmInfo::CdmInfo(const CdmInfo& other) = default;

CdmInfo::~CdmInfo() {}

}  // namespace common
