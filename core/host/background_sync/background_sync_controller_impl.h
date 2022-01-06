// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_BACKGROUND_SYNC_BACKGROUND_SYNC_CONTROLLER_IMPL_H_
#define CHROME_BROWSER_BACKGROUND_SYNC_BACKGROUND_SYNC_CONTROLLER_IMPL_H_

#include "core/host/background_sync_controller.h"

#include <stdint.h>

#include "base/macros.h"
#include "components/keyed_service/core/keyed_service.h"
#include "core/host/host_thread.h"

namespace host {
struct BackgroundSyncParameters;
class Domain;

class BackgroundSyncControllerImpl : public BackgroundSyncController {
 public:
  static const char kFieldTrialName[];
  static const char kDisabledParameterName[];
  static const char kMaxAttemptsParameterName[];
  static const char kInitialRetryParameterName[];
  static const char kRetryDelayFactorParameterName[];
  static const char kMinSyncRecoveryTimeName[];
  static const char kMaxSyncEventDurationName[];

  explicit BackgroundSyncControllerImpl(Domain* domain);
  ~BackgroundSyncControllerImpl() override;

  // content::BackgroundSyncController overrides.
  void GetParameterOverrides(
    BackgroundSyncParameters* parameters) const override;
  void NotifyBackgroundSyncRegistered(const GURL& origin) override;
  void RunInBackground(bool enabled, int64_t min_ms) override;

 private:
  //Domain* domain_;  // This object is owned by profile_.

  DISALLOW_COPY_AND_ASSIGN(BackgroundSyncControllerImpl);
};

}

#endif  // CHROME_BROWSER_BACKGROUND_SYNC_BACKGROUND_SYNC_CONTROLLER_IMPL_H_
