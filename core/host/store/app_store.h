// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_STORE_APP_STORE_H_
#define MUMBA_HOST_STORE_APP_STORE_H_

#include <memory>

#include "base/macros.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/string_piece.h"
#include "base/uuid.h"
#include "core/common/proto/objects.pb.h"

namespace host {

class AppStore {
public:
  AppStore();
  ~AppStore() override

private:

  DISALLOW_COPY_AND_ASSIGN(AppStore);
};

}

#endif