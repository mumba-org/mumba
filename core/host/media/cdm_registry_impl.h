// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MEDIA_CDM_REGISTRY_IMPL_H_
#define MUMBA_HOST_MEDIA_CDM_REGISTRY_IMPL_H_

#include <vector>

#include "base/compiler_specific.h"
#include "base/macros.h"
#include "core/shared/common/content_export.h"
#include "core/host/media/cdm_registry.h"

namespace common {
struct CdmInfo;  
}

namespace host {

class CONTENT_EXPORT CdmRegistryImpl : public CdmRegistry {
 public:
  // Returns the CdmRegistryImpl singleton.
  static CdmRegistryImpl* GetInstance();

  // CdmRegistry implementation.
  void Init() override;
  void RegisterCdm(const common::CdmInfo& info) override;
  const std::vector<common::CdmInfo>& GetAllRegisteredCdms() override;

 private:
  friend class CdmRegistryImplTest;

  CdmRegistryImpl();
  ~CdmRegistryImpl() override;

  std::vector<common::CdmInfo> cdms_;

  DISALLOW_COPY_AND_ASSIGN(CdmRegistryImpl);
};

}  // namespace host

#endif  // MUMBA_HOST_MEDIA_CDM_REGISTRY_IMPL_H_
