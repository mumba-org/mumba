// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_NOTIFICATIONS_WEB_PAGE_NOTIFIER_CONTROLLER_H_
#define CHROME_BROWSER_NOTIFICATIONS_WEB_PAGE_NOTIFIER_CONTROLLER_H_

#include "core/host/notifications/notifier_controller.h"
#include "components/content_settings/core/common/content_settings_pattern.h"

namespace base {
class CancelableTaskTracker;
}

namespace favicon_base {
struct FaviconImageResult;
}

namespace host {
class WebPageNotifierController : public NotifierController {
 public:
  explicit WebPageNotifierController(Observer* observer);
  ~WebPageNotifierController() override;

  std::vector<ash::mojom::NotifierUiDataPtr> GetNotifierList(
      Domain* domain) override;

  void SetNotifierEnabled(Domain* domain,
                          const message_center::NotifierId& notifier_id,
                          bool enabled) override;

 private:
  void OnFaviconLoaded(const GURL& url,
                       const favicon_base::FaviconImageResult& favicon_result);

  std::map<std::string, ContentSettingsPattern> patterns_;

  // The task tracker for loading favicons.
  std::unique_ptr<base::CancelableTaskTracker> favicon_tracker_;

  // Lifetime of parent must be longer than the source.
  Observer* observer_;
};
}

#endif  // CHROME_BROWSER_NOTIFICATIONS_WEB_PAGE_NOTIFIER_CONTROLLER_H_
