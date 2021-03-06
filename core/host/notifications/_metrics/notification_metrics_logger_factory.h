// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_NOTIFICATIONS_METRICS_NOTIFICATION_METRICS_LOGGER_FACTORY_H_
#define CHROME_BROWSER_NOTIFICATIONS_METRICS_NOTIFICATION_METRICS_LOGGER_FACTORY_H_

#include "base/memory/singleton.h"
#include "core/host/notifications/metrics/notification_metrics_logger.h"
#include "components/keyed_service/content/browser_context_keyed_service_factory.h"

class NotificationMetricsLogger;

class NotificationMetricsLoggerFactory
    : public BrowserContextKeyedServiceFactory {
 public:
  static NotificationMetricsLogger* GetForBrowserContext(
      BrowserContext* browser_context);
  static NotificationMetricsLoggerFactory* GetInstance();

 private:
  friend struct base::DefaultSingletonTraits<NotificationMetricsLoggerFactory>;

  NotificationMetricsLoggerFactory();

  // BrowserContextKeyedBaseFactory implementation.
  KeyedService* BuildServiceInstanceFor(
      BrowserContext* context) const override;
  BrowserContext* GetBrowserContextToUse(
      BrowserContext* context) const override;

  DISALLOW_COPY_AND_ASSIGN(NotificationMetricsLoggerFactory);
};

#endif  // CHROME_BROWSER_NOTIFICATIONS_METRICS_NOTIFICATION_METRICS_LOGGER_FACTORY_H_
