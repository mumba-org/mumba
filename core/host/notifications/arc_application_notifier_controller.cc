// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/notifications/arc_application_notifier_controller.h"

#include <set>

#include "base/strings/utf_string_conversions.h"
#include "core/host/application/domain.h"
#include "core/host/ui/app_list/arc/arc_app_list_prefs_factory.h"
#include "components/keyed_service/content/browser_context_keyed_service_shutdown_notifier_factory.h"
#include "ui/base/layout.h"
#include "ui/display/display.h"
#include "ui/display/screen.h"
#include "ui/message_center/public/cpp/notifier_id.h"

namespace arc {

namespace {
constexpr int kArcAppIconSizeInDp = 48;

class ArcAppNotifierShutdownNotifierFactory
    : public BrowserContextKeyedServiceShutdownNotifierFactory {
 public:
  static ArcAppNotifierShutdownNotifierFactory* GetInstance() {
    return base::Singleton<ArcAppNotifierShutdownNotifierFactory>::get();
  }

 private:
  friend struct base::DefaultSingletonTraits<
      ArcAppNotifierShutdownNotifierFactory>;

  ArcAppNotifierShutdownNotifierFactory()
      : BrowserContextKeyedServiceShutdownNotifierFactory("ArcAppNotifier") {
    DependsOn(ArcAppListPrefsFactory::GetInstance());
  }

  ~ArcAppNotifierShutdownNotifierFactory() override {}

  DISALLOW_COPY_AND_ASSIGN(ArcAppNotifierShutdownNotifierFactory);
};

}  // namespace

ArcApplicationNotifierController::ArcApplicationNotifierController(
    NotifierController::Observer* observer)
    : observer_(observer), last_profile_(nullptr) {}

ArcApplicationNotifierController::~ArcApplicationNotifierController() {
  StopObserving();
}

std::vector<ash::mojom::NotifierUiDataPtr>
ArcApplicationNotifierController::GetNotifierList(Domain* domain) {
  DCHECK(!domain->IsOffTheRecord());
  package_to_app_ids_.clear();
  icons_.clear();
  StopObserving();

  ArcAppListPrefs* const app_list = ArcAppListPrefs::Get(domain);
  std::vector<ash::mojom::NotifierUiDataPtr> results;
  // The app list can be null in unit tests.
  if (!app_list)
    return results;
  const std::vector<std::string>& app_ids = app_list->GetAppIds();

  last_profile_ = domain;
  StartObserving();

  for (const std::string& app_id : app_ids) {
    const auto app = app_list->GetApp(app_id);
    // Handle packages having multiple launcher activities.
    if (!app || package_to_app_ids_.count(app->package_name))
      continue;

    const auto package = app_list->GetPackage(app->package_name);
    if (!package || package->system)
      continue;

    // Load icons for notifier.
    std::unique_ptr<ArcAppIcon> icon(
        new ArcAppIcon(domain, app_id,
                       // ARC icon is available only for 48x48 dips.
                       kArcAppIconSizeInDp,
                       // The life time of icon must shorter than |this|.
                       this));
    // Apply icon now to set the default image.
    OnIconUpdated(icon.get());

    // Add notifiers.
    package_to_app_ids_.insert(std::make_pair(app->package_name, app_id));
    message_center::NotifierId notifier_id(
        message_center::NotifierId::ARC_APPLICATION, app_id);
    auto ui_data = ash::mojom::NotifierUiData::New(
        notifier_id, base::UTF8ToUTF16(app->name), app->notifications_enabled,
        false /* enforced */, icon->image_skia());
    icons_.push_back(std::move(icon));
    results.push_back(std::move(ui_data));
  }

  return results;
}

void ArcApplicationNotifierController::SetNotifierEnabled(
    Domain* domain,
    const message_center::NotifierId& notifier_id,
    bool enabled) {
  ArcAppListPrefs::Get(domain)->SetNotificationsEnabled(notifier_id.id,
                                                         enabled);
  // OnNotifierEnabledChanged will be invoked via ArcAppListPrefs::Observer.
}

void ArcApplicationNotifierController::OnIconUpdated(ArcAppIcon* icon) {
  observer_->OnIconImageUpdated(
      message_center::NotifierId(message_center::NotifierId::ARC_APPLICATION,
                                 icon->app_id()),
      icon->image_skia());
}

void ArcApplicationNotifierController::OnNotificationsEnabledChanged(
    const std::string& package_name,
    bool enabled) {
  auto it = package_to_app_ids_.find(package_name);
  if (it == package_to_app_ids_.end())
    return;
  observer_->OnNotifierEnabledChanged(
      message_center::NotifierId(message_center::NotifierId::ARC_APPLICATION,
                                 it->second),
      enabled);
}

void ArcApplicationNotifierController::StartObserving() {
  ArcAppListPrefs::Get(last_profile_)->AddObserver(this);
  shutdown_notifier_ = ArcAppNotifierShutdownNotifierFactory::GetInstance()
                           ->Get(last_profile_)
                           ->Subscribe(base::BindRepeating(
                               &ArcApplicationNotifierController::StopObserving,
                               base::Unretained(this)));
}

void ArcApplicationNotifierController::StopObserving() {
  if (!last_profile_)
    return;
  shutdown_notifier_.reset();
  ArcAppListPrefs::Get(last_profile_)->RemoveObserver(this);
  last_profile_ = nullptr;
}

}  // namespace arc
