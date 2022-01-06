// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_SHARE_SHARE_CONTROLLER_H_
#define MUMBA_HOST_SHARE_SHARE_CONTROLLER_H_

#include <string>

#include "base/macros.h"
#include "base/uuid.h"

namespace host {
class ShareManager;
class Share;

class ShareController {
public:
  ShareController(ShareManager* manager); 
  ~ShareController();

  void AddShare(const std::string& address);
  void RemoveShare(const std::string& address);
  void RemoveShare(const base::UUID& uuid);
  void LookupShareByAddress(const std::string& address);
  void LookupShareByName(const std::string& name);
  void LookupShareByUUID(const base::UUID& id);
  bool HaveShareByAddress(const std::string& address);
  bool HaveShareByName(const std::string& name);
  bool HaveShareByUUID(const base::UUID& id);
  std::vector<Share*> ListShares();
  std::vector<Share*> ListSharesByDomain(const std::string& domain_name);
  uint32_t CountShares();
  
private:
  
  ShareManager* manager_;
    
  DISALLOW_COPY_AND_ASSIGN(ShareController);
};

}

#endif
