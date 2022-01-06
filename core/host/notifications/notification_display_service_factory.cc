// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/notifications/notification_display_service_factory.h"

#include "base/command_line.h"
#include "base/memory/singleton.h"
#include "base/win/windows_version.h"
#include "build/build_config.h"
#include "core/host/host.h"
#include "core/host/notifications/notification_display_service_impl.h"
//#include "core/host/profiles/incognito_helpers.h"
#include "core/host/application/domain.h"
#include "core/host/application/domain.h"
//#include "chrome/common/buildflags.h"
//#include "chrome/common/chrome_features.h"
#include "components/keyed_service/content/browser_context_dependency_manager.h"

namespace host {
// static 
NotificationDisplayService* NotificationDisplayServiceFactory::GetForDomain(Domain* domain) {
  return GetInstance()->GetServiceForDomain(domain);
}

// static
NotificationDisplayServiceFactory*
NotificationDisplayServiceFactory::GetInstance() {
  return base::Singleton<NotificationDisplayServiceFactory>::get();
}

NotificationDisplayServiceFactory::NotificationDisplayServiceFactory() {}

// KeyedService* NotificationDisplayServiceFactory::BuildServiceInstanceFor(
//     BrowserContext* context) const {
//   // TODO(peter): Register the notification handlers here.
//   return new NotificationDisplayServiceImpl(
//       Domain::FromBrowserContext(context));
// }

NotificationDisplayService* NotificationDisplayServiceFactory::GetServiceForDomain(Domain* domain) {
  if (!notification_display_service_) {
    notification_display_service_ = std::make_unique<NotificationDisplayServiceImpl>(domain);
  }
  return notification_display_service_.get();
}

// BrowserContext*
// NotificationDisplayServiceFactory::GetBrowserContextToUse(
//     BrowserContext* context) const {
//   return chrome::GetBrowserContextOwnInstanceInIncognito(context);
// }

}