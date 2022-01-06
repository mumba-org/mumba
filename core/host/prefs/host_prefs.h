// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_PREFS_HOST_PREFS_H_
#define MUMBA_HOST_PREFS_HOST_PREFS_H_

class PrefRegistrySimple;
class PrefService;

namespace user_prefs {
class PrefRegistrySyncable;
}

namespace host {
class HostProcess;
// Register all prefs that will be used via the local state PrefService.
void RegisterLocalState(PrefRegistrySimple* registry);

}  // namespace host

#endif  // MUMBA_MODULES_HOST_PREFS_BROWSER_PREFS_H_
