// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_NOTIFICATIONS_NOTIFIER_STATE_TRACKER_FACTORY_H_
#define CHROME_BROWSER_NOTIFICATIONS_NOTIFIER_STATE_TRACKER_FACTORY_H_

#include "base/macros.h"
#include "base/memory/singleton.h"
//#include "components/keyed_service/content/browser_context_keyed_service_factory.h"

namespace host {
class NotifierStateTracker;
class Domain;

class NotifierStateTrackerFactory {//: public BrowserContextKeyedServiceFactory {
 public:
  static NotifierStateTracker* GetForDomain(Domain* domain);
  static NotifierStateTrackerFactory* GetInstance();

 private:
  friend struct base::DefaultSingletonTraits<NotifierStateTrackerFactory>;

  NotifierStateTrackerFactory();
  ~NotifierStateTrackerFactory();

  NotifierStateTracker* GetServiceForDomain(Domain* domain);

//   // BrowserContextKeyedBaseFactory implementation.
//   KeyedService* BuildServiceInstanceFor(
//       BrowserContext* domain) const override;
//   BrowserContext* GetBrowserContextToUse(
//       BrowserContext* context) const override;

  std::unique_ptr<NotifierStateTracker> notifier_state_tracker_;

  DISALLOW_COPY_AND_ASSIGN(NotifierStateTrackerFactory);
};

}

#endif  // CHROME_BROWSER_NOTIFICATIONS_NOTIFIER_STATE_TRACKER_FACTORY_H_
