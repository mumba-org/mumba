// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/notifications/notifier_state_tracker_factory.h"

#include "core/host/notifications/notifier_state_tracker.h"
//#include "core/host/permissions/permission_manager_factory.h"
//#include "core/host/profiles/incognito_helpers.h"
#include "core/host/application/domain.h"
#include "components/keyed_service/content/browser_context_dependency_manager.h"

namespace host {
// static
NotifierStateTracker*
NotifierStateTrackerFactory::GetForDomain(Domain* domain) {
  return GetInstance()->GetServiceForDomain(domain);
}

// static
NotifierStateTrackerFactory*
NotifierStateTrackerFactory::GetInstance() {
  return base::Singleton<NotifierStateTrackerFactory>::get();
}

NotifierStateTrackerFactory::NotifierStateTrackerFactory() {}

NotifierStateTrackerFactory::~NotifierStateTrackerFactory() {}

NotifierStateTracker* NotifierStateTrackerFactory::GetServiceForDomain(Domain* domain) {
  if (!notifier_state_tracker_) {
    notifier_state_tracker_.reset(new NotifierStateTracker(domain));
  }
  return notifier_state_tracker_.get();
}

}