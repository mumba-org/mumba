// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_ADS_ADS_DISPATCHER_H_
#define MUMBA_HOST_ADS_ADS_DISPATCHER_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"
#include "core/shared/common/mojom/ads.mojom.h"

namespace host {

/*
 *  IPC interface between applications and the api service
 */
class AdsDispatcher : public common::mojom::AdsDispatcher {
public:
  AdsDispatcher();
  ~AdsDispatcher() override;
  
private:
  DISALLOW_COPY_AND_ASSIGN(AdsDispatcher);
};

}

#endif