// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MEDIA_KEY_SYSTEM_SUPPORT_IMPL_H_
#define MUMBA_HOST_MEDIA_KEY_SYSTEM_SUPPORT_IMPL_H_

#include <memory>
#include <string>

#include "base/macros.h"
#include "core/shared/common/content_export.h"
#include "core/common/cdm_info.h"
#include "media/mojo/interfaces/key_system_support.mojom.h"

namespace host {

class CONTENT_EXPORT KeySystemSupportImpl final
    : public media::mojom::KeySystemSupport {
 public:
  KeySystemSupportImpl();
  ~KeySystemSupportImpl() final;

  // Create a KeySystemSupportImpl object and bind it to |request|.
  static void Create(media::mojom::KeySystemSupportRequest request);

  // Returns CdmInfo registered for |key_system|. Returns null if no CdmInfo is
  // registered for |key_system|, or if the CdmInfo registered is invalid.
  static std::unique_ptr<CdmInfo> GetCdmInfoForKeySystem(
      const std::string& key_system);

  // media::mojom::KeySystemSupport implementation.
  void IsKeySystemSupported(const std::string& key_system,
                            IsKeySystemSupportedCallback callback) final;

 private:
  DISALLOW_COPY_AND_ASSIGN(KeySystemSupportImpl);
};

}  // namespace host

#endif  // MUMBA_HOST_MEDIA_KEY_SYSTEM_SUPPORT_IMPL_H_
