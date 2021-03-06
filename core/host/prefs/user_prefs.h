// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_USER_PREFS_USER_PREFS_H_
#define MUMBA_HOST_USER_PREFS_USER_PREFS_H_

#include "base/macros.h"
#include "base/supports_user_data.h"

class PrefService;

namespace host {

// Components may use preferences associated with a given user. These hang off
// of base::SupportsUserData and can be retrieved using UserPrefs::Get().
//
// It is up to the embedder to create and own the PrefService and attach it to
// base::SupportsUserData using the UserPrefs::Set() function.
class UserPrefs : public base::SupportsUserData::Data {
 public:
  // Retrieves the PrefService for a given context, or null if none is attached.
  static PrefService* Get(base::SupportsUserData* context);

  // Hangs the specified |prefs| off of |context|. Should be called
  // only once per context.
  static void Set(base::SupportsUserData* context, PrefService* prefs);

 private:
  explicit UserPrefs(PrefService* prefs);
  ~UserPrefs() override;

  // Non-owning; owned by embedder.
  PrefService* prefs_;

  DISALLOW_COPY_AND_ASSIGN(UserPrefs);
};

}  // namespace host

#endif  // MUMBA_HOST_USER_PREFS_USER_PREFS_H_
