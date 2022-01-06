// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_ADS_AD_CAMPAIGN_H_
#define MUMBA_HOST_ADS_AD_CAMPAIGN_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"

namespace host {

class AdCampaign {
public:
  AdCampaign();
  ~AdCampaign();
  
private:
  DISALLOW_COPY_AND_ASSIGN(AdCampaign);
};

}

#endif