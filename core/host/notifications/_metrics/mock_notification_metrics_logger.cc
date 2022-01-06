// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/notifications/metrics/mock_notification_metrics_logger.h"

#include "base/memory/ptr_util.h"

// static
std::unique_ptr<KeyedService> MockNotificationMetricsLogger::FactoryForTests(
    BrowserContext* context) {
  return base::WrapUnique(new MockNotificationMetricsLogger());
}

MockNotificationMetricsLogger::MockNotificationMetricsLogger() = default;
MockNotificationMetricsLogger::~MockNotificationMetricsLogger() = default;
