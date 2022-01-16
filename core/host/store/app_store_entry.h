// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_STORE_APP_STORE_ENTRY_H_
#define MUMBA_HOST_STORE_APP_STORE_ENTRY_H_

#include <memory>

#include "base/macros.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/string_piece.h"
#include "base/uuid.h"
#include "core/common/proto/objects.pb.h"
#include "core/host/serializable.h"

namespace host {

class AppStoreEntry : public Serializable {
public:

  static char kClassName[];
  static std::unique_ptr<AppStoreEntry> Deserialize(net::IOBuffer* buffer, int size);
  
  ~AppStoreEntry() override;

  const base::UUID& id() const {
    return id_;
  }

  bool is_managed() const {
    return managed_;
  }

  void set_managed(bool managed) {
    managed_ = managed;
  }

  scoped_refptr<net::IOBufferWithSize> Serialize() const override;

private:
  Schema();
  Schema(protocol::Protocol schema);

  base::UUID id_;

  protocol::AppStoreEntry app_proto_;

  bool managed_;

  DISALLOW_COPY_AND_ASSIGN(AppStoreEntry);
};

}

#endif