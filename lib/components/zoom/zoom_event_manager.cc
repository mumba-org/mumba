// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/zoom/zoom_event_manager.h"

#include <memory>

#include "base/lazy_instance.h"
#include "components/zoom/zoom_event_manager_observer.h"
//#include "core/host/browser_context.h"

namespace {
//static const char kBrowserZoomEventManager[] = "browser_zoom_event_manager";

static base::LazyInstance<zoom::ZoomEventManager>::DestructorAtExit g_instance = LAZY_INSTANCE_INITIALIZER;

}

namespace zoom {

// ZoomEventManager* ZoomEventManager::GetForBrowserContext(
//     content::BrowserContext* context) {
//   if (!context->GetUserData(kBrowserZoomEventManager)) {
//     context->SetUserData(kBrowserZoomEventManager,
//                          std::make_unique<ZoomEventManager>());
//   }
//   return static_cast<ZoomEventManager*>(
//       context->GetUserData(kBrowserZoomEventManager));
// }

ZoomEventManager* ZoomEventManager::Get() {
  return g_instance.Pointer();
}

ZoomEventManager::ZoomEventManager() : weak_ptr_factory_(this) {}

ZoomEventManager::~ZoomEventManager() {}

void ZoomEventManager::OnZoomLevelChanged(
    const host::HostZoomMap::ZoomLevelChange& change) {
  zoom_level_changed_callbacks_.Notify(change);
}

std::unique_ptr<host::HostZoomMap::Subscription>
ZoomEventManager::AddZoomLevelChangedCallback(
    const host::HostZoomMap::ZoomLevelChangedCallback& callback) {
  return zoom_level_changed_callbacks_.Add(callback);
}

void ZoomEventManager::OnDefaultZoomLevelChanged() {
  for (auto& observer : observers_)
    observer.OnDefaultZoomLevelChanged();
}

void ZoomEventManager::AddZoomEventManagerObserver(
    ZoomEventManagerObserver* observer) {
  observers_.AddObserver(observer);
}

void ZoomEventManager::RemoveZoomEventManagerObserver(
    ZoomEventManagerObserver* observer) {
  observers_.RemoveObserver(observer);
}

}  // namespace zoom
