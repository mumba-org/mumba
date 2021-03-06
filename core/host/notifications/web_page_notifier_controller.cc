// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/notifications/web_page_notifier_controller.h"

#include "base/strings/utf_string_conversions.h"
#include "base/task/cancelable_task_tracker.h"
#include "core/host/content_settings/host_content_settings_map_factory.h"
#include "core/host/favicon/favicon_service_factory.h"
#include "core/host/notifications/desktop_notification_profile_util.h"
#include "core/host/notifications/notifier_state_tracker.h"
#include "core/host/notifications/notifier_state_tracker_factory.h"
#include "components/content_settings/core/browser/host_content_settings_map.h"
#include "components/content_settings/core/common/content_settings.h"
#include "components/favicon/core/favicon_service.h"

namespace host {

WebPageNotifierController::WebPageNotifierController(Observer* observer)
    : observer_(observer) {}

WebPageNotifierController::~WebPageNotifierController() {}

std::vector<ash::mojom::NotifierUiDataPtr>
WebPageNotifierController::GetNotifierList(Domain* domain) {
  std::vector<ash::mojom::NotifierUiDataPtr> notifiers;

  ContentSettingsForOneType settings;
  DesktopNotificationProfileUtil::GetNotificationsSettings(domain, &settings);

  favicon::FaviconService* const favicon_service =
      FaviconServiceFactory::GetForProfile(domain,
                                           ServiceAccessType::EXPLICIT_ACCESS);
  favicon_tracker_.reset(new base::CancelableTaskTracker());
  patterns_.clear();
  for (ContentSettingsForOneType::const_iterator iter = settings.begin();
       iter != settings.end(); ++iter) {
    if (iter->primary_pattern == ContentSettingsPattern::Wildcard() &&
        iter->secondary_pattern == ContentSettingsPattern::Wildcard() &&
        iter->source != "preference") {
      continue;
    }

    std::string url_pattern = iter->primary_pattern.ToString();
    base::string16 name = base::UTF8ToUTF16(url_pattern);
    GURL url(url_pattern);
    message_center::NotifierId notifier_id(url);
    NotifierStateTracker* const notifier_state_tracker =
        NotifierStateTrackerFactory::GetForProfile(domain);
    content_settings::SettingInfo info;
    HostContentSettingsMapFactory::GetForProfile(domain)->GetWebsiteSetting(
        url, GURL(), CONTENT_SETTINGS_TYPE_NOTIFICATIONS, std::string(), &info);
    notifiers.push_back(ash::mojom::NotifierUiData::New(
        notifier_id, name,
        notifier_state_tracker->IsNotifierEnabled(notifier_id),
        info.source == content_settings::SETTING_SOURCE_POLICY,
        gfx::ImageSkia()));
    patterns_[url_pattern] = iter->primary_pattern;
    // Note that favicon service obtains the favicon from history. This means
    // that it will fail to obtain the image if there are no history data for
    // that URL.
    favicon_service->GetFaviconImageForPageURL(
        url,
        base::Bind(&WebPageNotifierController::OnFaviconLoaded,
                   base::Unretained(this), url),
        favicon_tracker_.get());
  }

  return notifiers;
}

void WebPageNotifierController::SetNotifierEnabled(
    Domain* domain,
    const message_center::NotifierId& notifier_id,
    bool enabled) {
  // WEB_PAGE notifier cannot handle in DesktopNotificationService
  // since it has the exact URL pattern.
  // TODO(mukai): fix this.
  ContentSetting default_setting =
      HostContentSettingsMapFactory::GetForProfile(domain)
          ->GetDefaultContentSetting(CONTENT_SETTINGS_TYPE_NOTIFICATIONS, NULL);

  DCHECK(default_setting == CONTENT_SETTING_ALLOW ||
         default_setting == CONTENT_SETTING_BLOCK ||
         default_setting == CONTENT_SETTING_ASK);

  // The content setting for notifications needs to clear when it changes to
  // the default value or get explicitly set when it differs from the
  // default.
  bool differs_from_default_value =
      (default_setting != CONTENT_SETTING_ALLOW && enabled) ||
      (default_setting == CONTENT_SETTING_ALLOW && !enabled);

  if (differs_from_default_value) {
    if (notifier_id.url.is_valid()) {
      if (enabled) {
        DesktopNotificationProfileUtil::GrantPermission(domain,
                                                        notifier_id.url);
      } else {
        DesktopNotificationProfileUtil::DenyPermission(domain,
                                                       notifier_id.url);
      }
    } else {
      LOG(ERROR) << "Invalid url pattern: "
                 << notifier_id.url.possibly_invalid_spec();
    }
  } else {
    ContentSettingsPattern pattern;

    const auto& iter = patterns_.find(notifier_id.url.possibly_invalid_spec());
    if (iter != patterns_.end()) {
      pattern = iter->second;
    } else if (notifier_id.url.is_valid()) {
      pattern = ContentSettingsPattern::FromURLNoWildcard(notifier_id.url);
    } else {
      LOG(ERROR) << "Invalid url pattern: "
                 << notifier_id.url.possibly_invalid_spec();
    }

    if (pattern.IsValid()) {
      // Note that we don't use
      // DesktopNotificationProfileUtil::ClearSetting()
      // here because pattern might be from user manual input and not match
      // the default one used by ClearSetting().
      HostContentSettingsMapFactory::GetForProfile(domain)
          ->SetContentSettingCustomScope(
              pattern, ContentSettingsPattern::Wildcard(),
              CONTENT_SETTINGS_TYPE_NOTIFICATIONS,
              content_settings::ResourceIdentifier(), CONTENT_SETTING_DEFAULT);
    }
  }

  observer_->OnNotifierEnabledChanged(notifier_id, enabled);
}

void WebPageNotifierController::OnFaviconLoaded(
    const GURL& url,
    const favicon_base::FaviconImageResult& favicon_result) {
  observer_->OnIconImageUpdated(message_center::NotifierId(url),
                                favicon_result.image.AsImageSkia());
}

}