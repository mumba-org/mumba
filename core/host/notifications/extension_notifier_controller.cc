// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/notifications/extension_notifier_controller.h"

#include "base/strings/utf_string_conversions.h"
#include "core/host/extensions/chrome_app_icon_loader.h"
#include "core/host/notifications/notifier_state_tracker.h"
#include "core/host/notifications/notifier_state_tracker_factory.h"
#include "core/host/application/domain.h"
#include "chrome/common/extensions/api/notifications.h"
#include "extensions/browser/event_router.h"
#include "extensions/common/constants.h"
#include "extensions/common/extension_set.h"
#include "extensions/common/permissions/api_permission.h"
#include "extensions/common/permissions/permissions_data.h"
#include "ui/message_center/public/cpp/notifier_id.h"

namespace host {

ExtensionNotifierController::ExtensionNotifierController(Observer* observer)
    : observer_(observer) {}

ExtensionNotifierController::~ExtensionNotifierController() {}

std::vector<ash::mojom::NotifierUiDataPtr>
ExtensionNotifierController::GetNotifierList(Domain* domain) {
  std::vector<ash::mojom::NotifierUiDataPtr> ui_data;
  const extensions::ExtensionSet& extension_set =
      extensions::ExtensionRegistry::Get(domain)->enabled_extensions();
  // The extension icon size has to be 32x32 at least to load bigger icons if
  // the icon doesn't exist for the specified size, and in that case it falls
  // back to the default icon. The fetched icon will be resized in the
  // settings dialog. See core/host/extensions/extension_icon_image.cc
  // and crbug.com/222931
  app_icon_loader_.reset(new extensions::ChromeAppIconLoader(
      domain, extension_misc::EXTENSION_ICON_SMALL, this));
  for (extensions::ExtensionSet::const_iterator iter = extension_set.begin();
       iter != extension_set.end(); ++iter) {
    const extensions::Extension* extension = iter->get();
    if (!extension->permissions_data()->HasAPIPermission(
            extensions::APIPermission::kNotifications)) {
      continue;
    }

    // Hosted apps are no longer able to affect the notifications permission
    // state for web notifications.
    // TODO(dewittj): Deprecate the 'notifications' permission for hosted
    // apps.
    if (extension->is_hosted_app())
      continue;

    message_center::NotifierId notifier_id(
        message_center::NotifierId::APPLICATION, extension->id());
    NotifierStateTracker* const notifier_state_tracker =
        NotifierStateTrackerFactory::GetForProfile(domain);
    ui_data.push_back(ash::mojom::NotifierUiData::New(
        notifier_id, base::UTF8ToUTF16(extension->name()),
        notifier_state_tracker->IsNotifierEnabled(notifier_id),
        false /* enforced */, gfx::ImageSkia()));
    app_icon_loader_->FetchImage(extension->id());
  }

  return ui_data;
}

void ExtensionNotifierController::SetNotifierEnabled(
    Domain* domain,
    const message_center::NotifierId& notifier_id,
    bool enabled) {
  NotifierStateTrackerFactory::GetForProfile(domain)->SetNotifierEnabled(
      notifier_id, enabled);
  observer_->OnNotifierEnabledChanged(notifier_id, enabled);
}

void ExtensionNotifierController::OnAppImageUpdated(
    const std::string& id,
    const gfx::ImageSkia& image) {
  observer_->OnIconImageUpdated(
      message_center::NotifierId(message_center::NotifierId::APPLICATION, id),
      image);
}

}