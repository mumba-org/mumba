// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/prefs/pref_registry_syncable.h"

#include "base/files/file_path.h"
#include "base/prefs/default_pref_store.h"
#include "base/strings/string_number_conversions.h"
#include "base/values.h"

namespace host {

PrefRegistrySyncable::PrefRegistrySyncable() {
}

PrefRegistrySyncable::~PrefRegistrySyncable() {
}

void PrefRegistrySyncable::SetSyncableRegistrationCallback(
    const SyncableRegistrationCallback& cb) {
  callback_ = cb;
}

/*void PrefRegistrySyncable::OnPrefRegistered(const std::string& path,
                                            base::Value* default_value,
                                            uint32 flags) {
  // Tests that |flags| does not contain both SYNCABLE_PREF and
  // SYNCABLE_PRIORITY_PREF flags at the same time.
  DCHECK(!(flags & PrefRegistrySyncable::SYNCABLE_PREF) ||
         !(flags & PrefRegistrySyncable::SYNCABLE_PRIORITY_PREF));

  if (flags & PrefRegistrySyncable::SYNCABLE_PREF ||
      flags & PrefRegistrySyncable::SYNCABLE_PRIORITY_PREF) {
    if (!callback_.is_null())
      callback_.Run(path, flags);
  }
}*/

scoped_refptr<PrefRegistrySyncable> PrefRegistrySyncable::ForkForIncognito() {
  // TODO(joi): We can directly reuse the same PrefRegistry once
  // PrefService no longer registers for callbacks on registration and
  // unregistration.
  scoped_refptr<PrefRegistrySyncable> registry(new PrefRegistrySyncable());
  registry->defaults_ = defaults_;
  return registry;
}

}  // namespace user_prefs
