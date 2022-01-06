// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/themes/theme_service_factory.h"

#include "base/logging.h"
#include "build/build_config.h"
#include "core/host/workspace/workspace.h"
#include "core/host/themes/theme_service.h"
//#include "chrome/common/pref_names.h"
//#include "components/keyed_service/content/browser_context_dependency_manager.h"
//#include "components/pref_registry/pref_registry_syncable.h"
//#include "components/prefs/pref_service.h"
//#include "extensions/browser/extension_registry.h"
//#include "extensions/browser/extension_registry_factory.h"
#include "core/host/themes/theme_service_custom.h"
#if defined(OS_WIN)
#include "core/host/themes/theme_service_win.h"
#elif defined(USE_X11)
#include "core/host/themes/theme_service_aurax11.h"
#include "ui/views/linux_ui/linux_ui.h"
#endif

namespace host {

// static
ThemeService* ThemeServiceFactory::GetForWorkspace(scoped_refptr<Workspace> workspace) {
  return GetInstance()->GetServiceForWorkspace(workspace);
}

// // static
// const extensions::Extension* ThemeServiceFactory::GetThemeForProfile(
//     Profile* profile) {
//   std::string id = GetForProfile(profile)->GetThemeID();
//   if (id == ThemeService::kDefaultThemeID)
//     return NULL;

//   return extensions::ExtensionRegistry::Get(
//       profile)->enabled_extensions().GetByID(id);
// }

// static
ThemeServiceFactory* ThemeServiceFactory::GetInstance() {
  return base::Singleton<ThemeServiceFactory>::get();
}

ThemeServiceFactory::ThemeServiceFactory() {
    //: BrowserContextKeyedServiceFactory(
    //      "ThemeService",
    //      BrowserContextDependencyManager::GetInstance()) {
  //DependsOn(extensions::ExtensionRegistryFactory::GetInstance());
}

ThemeServiceFactory::~ThemeServiceFactory() {}

ThemeService* ThemeServiceFactory::GetServiceForWorkspace(scoped_refptr<Workspace> workspace) const {
  if (!workspace->theme_service()) {
    std::unique_ptr<ThemeService> service = BuildServiceForWorkspace(workspace);
    workspace->set_theme_service(std::move(service));
  }
  return workspace->theme_service();
}

std::unique_ptr<ThemeService> ThemeServiceFactory::BuildServiceForWorkspace(scoped_refptr<Workspace> workspace) const {
  std::unique_ptr<ThemeService> provider;
/* #if defined(OS_WIN)
  provider = std::make_unique<ThemeServiceWin>();
#elif defined(USE_X11)
  provider = std::make_unique<ThemeServiceAuraX11>();
#else
  provider = std::make_unique<ThemeService>();
#endif */
  provider = std::make_unique<CustomThemeService>();
  provider->Init(workspace);

  return provider;
}

// void ThemeServiceFactory::RegisterProfilePrefs(
//     user_prefs::PrefRegistrySyncable* registry) {
// #if defined(USE_X11)
//   bool default_uses_system_theme = false;

//   const views::LinuxUI* linux_ui = views::LinuxUI::instance();
//   if (linux_ui)
//     default_uses_system_theme = linux_ui->GetDefaultUsesSystemTheme();

//   registry->RegisterBooleanPref(prefs::kUsesSystemTheme,
//                                 default_uses_system_theme);
// #endif
//   registry->RegisterFilePathPref(prefs::kCurrentThemePackFilename,
//                                  base::FilePath());
//   registry->RegisterStringPref(prefs::kCurrentThemeID,
//                                ThemeService::kDefaultThemeID);
//   registry->RegisterDictionaryPref(prefs::kCurrentThemeImages);
//   registry->RegisterDictionaryPref(prefs::kCurrentThemeColors);
//   registry->RegisterDictionaryPref(prefs::kCurrentThemeTints);
//   registry->RegisterDictionaryPref(prefs::kCurrentThemeDisplayProperties);
// }

// content::BrowserContext* ThemeServiceFactory::GetBrowserContextToUse(
//     content::BrowserContext* context) const {
//   return chrome::GetBrowserContextRedirectedInIncognito(context);
// }

// bool ThemeServiceFactory::ServiceIsCreatedWithBrowserContext() const {
//   return true;
// }

}