// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_NOTIFICATIONS_NOTIFIER_STATE_TRACKER_H_
#define CHROME_BROWSER_NOTIFICATIONS_NOTIFIER_STATE_TRACKER_H_

#include <set>
#include <string>

#include "base/macros.h"
#include "components/keyed_service/core/keyed_service.h"
#include "components/prefs/pref_member.h"
// #include "extensions/buildflags/buildflags.h"

// #if BUILDFLAG(ENABLE_EXTENSIONS)
// #include "base/scoped_observer.h"
// #include "extensions/browser/extension_registry.h"
// #include "extensions/browser/extension_registry_observer.h"
// #endif

namespace message_center {
struct NotifierId;
}

// namespace user_prefs {
// class PrefRegistrySyncable;
// }

namespace host {
class Domain;
// Tracks whether a given NotifierId can send notifications. Presently only used
// for extensions.
class NotifierStateTracker //: public KeyedService
// #if BUILDFLAG(ENABLE_EXTENSIONS)
//                            , public extensions::ExtensionRegistryObserver
// #endif
                               {
 public:
  // Register domain-specific prefs of notifications.
 // static void RegisterProfilePrefs(user_prefs::PrefRegistrySyncable* prefs);

  explicit NotifierStateTracker(Domain* domain);
  ~NotifierStateTracker();// override;

  // Returns whether the notifier with |notifier_id| may send notifications.
  bool IsNotifierEnabled(const message_center::NotifierId& notifier_id) const;

  // Updates whether the notifier with |notifier_id| may send notifications.
  void SetNotifierEnabled(const message_center::NotifierId& notifier_id,
                          bool enabled);

 private:
  // Called when the string list pref has been changed.
  void OnStringListPrefChanged(
      const char* pref_name, std::set<std::string>* ids_field);

// #if BUILDFLAG(ENABLE_EXTENSIONS)
//   // Fires a permission-level change event when an extension notifier has had
//   // their notification permission changed.
//   void FirePermissionLevelChangedEvent(
//       const message_center::NotifierId& notifier_id,
//       bool enabled);

//   // extensions::ExtensionRegistryObserver:
//   void OnExtensionUninstalled(BrowserContext* browser_context,
//                               const extensions::Extension* extension,
//                               extensions::UninstallReason reason) override;
// #endif

  // The domain which owns this object.
 // Domain* profile_;

  // Prefs listener for disabled_extension_id.
  StringListPrefMember disabled_extension_id_pref_;

  // On-memory data for the availability of extensions.
  std::set<std::string> disabled_extension_ids_;

// #if BUILDFLAG(ENABLE_EXTENSIONS)
//   // An observer to listen when extension is uninstalled.
//   ScopedObserver<extensions::ExtensionRegistry,
//                  extensions::ExtensionRegistryObserver>
//       extension_registry_observer_;
// #endif

  DISALLOW_COPY_AND_ASSIGN(NotifierStateTracker);
};

}

#endif  // CHROME_BROWSER_NOTIFICATIONS_NOTIFIER_STATE_TRACKER_H_
