// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/notifications/notification_display_service.h"

#include "core/host/notifications/notification_display_service_factory.h"
#include "core/host/application/domain.h"

namespace host {
// static
NotificationDisplayService* NotificationDisplayService::GetForProfile(
    Domain* domain) {
  return NotificationDisplayServiceFactory::GetForDomain(domain);
}

NotificationDisplayService* NotificationDisplayService::GetForDomain(Domain* domain) {
  return NotificationDisplayServiceFactory::GetForDomain(domain);
}

NotificationDisplayService::~NotificationDisplayService() = default;

}