// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/media/cdm_registry_impl.h"

#include <stddef.h>

#include "core/common/cdm_info.h"
#include "core/shared/common/client.h"

namespace host {

// static
CdmRegistry* CdmRegistry::GetInstance() {
  return CdmRegistryImpl::GetInstance();
}

// static
CdmRegistryImpl* CdmRegistryImpl::GetInstance() {
  static CdmRegistryImpl* registry = new CdmRegistryImpl();
  return registry;
}

CdmRegistryImpl::CdmRegistryImpl() {}

CdmRegistryImpl::~CdmRegistryImpl() {}

void CdmRegistryImpl::Init() {
  // Let embedders register CDMs.
  //common::GetClient()->AddContentDecryptionModules(&cdms_, nullptr);
}

void CdmRegistryImpl::RegisterCdm(const common::CdmInfo& info) {
  // Always register new CDMs at the end of the list, so that the behavior is
  // consistent across the browser process's lifetime. For example, we'll always
  // use the same registered CDM for a given key system. This also means that
  // some later registered CDMs (component updated) will not be used until
  // browser restart, which is fine in most cases.
  cdms_.push_back(info);
}

const std::vector<common::CdmInfo>& CdmRegistryImpl::GetAllRegisteredCdms() {
  return cdms_;
}

}  // namespace media
