// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "gen/item.h"

#include "base/logging.h"
#include "gen/settings.h"
#include "gen/pool.h"
#include "gen/target.h"
#include "gen/config.h"
#include "gen/toolchain.h"

Item::Item(const Settings* settings,
           const Label& label,
           const std::set<SourceFile>& build_dependency_files)
    : settings_(settings),
      label_(label),
      build_dependency_files_(build_dependency_files),
      defined_from_(nullptr) {}

Item::~Item() = default;

scoped_refptr<Config> Item::AsConfig() {
  return nullptr;
}
//const Config* Item::AsConfig() const {
//  return nullptr;
//}
scoped_refptr<Pool> Item::AsPool() {
  return nullptr;
}
//const Pool* Item::AsPool() const {
//  return nullptr;
//}
scoped_refptr<Target> Item::AsTarget() {
  return nullptr;
}
//const Target* Item::AsTarget() const {
//  return nullptr;
//}
scoped_refptr<Toolchain> Item::AsToolchain() {
  return nullptr;
}

//const Toolchain* Item::AsToolchain() const {
//  return nullptr;
//}

std::string Item::GetItemTypeName() {
  if (AsConfig())
    return "config";
  if (AsTarget())
    return "target";
  if (AsToolchain())
    return "toolchain";
  if (AsPool())
    return "pool";
  NOTREACHED();
  return "this thing that I have no idea what it is";
}

bool Item::OnResolved(Err* err) {
  return true;
}
