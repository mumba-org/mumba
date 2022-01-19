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
#include "core/shared/common/mojom/app_store.mojom.h"

namespace host {

class AppStoreEntry : public Serializable {
public:
  static char kClassName[];
  static std::unique_ptr<AppStoreEntry> Deserialize(net::IOBuffer* buffer, int size);
  
  AppStoreEntry();
  AppStoreEntry(protocol::AppStoreEntry proto);

  ~AppStoreEntry() override;

  const base::UUID& id() const {
    return id_;
  }

  const std::string& name() const;
  const std::string& description() const;
  const std::string& version() const;
  const std::string& license() const;
  const std::string& publisher() const;
  const std::string& publisher_url() const;
  base::StringPiece publisher_public_key() const;
  const std::string& logo_path() const;
  uint64_t size() const;
  const base::UUID& repo_uuid();
  base::StringPiece repo_public_key() const;
  protocol::AppStoreInstallState install_state() const;
  protocol::AppStoreAvailabilityState availability_state() const;
  uint64_t install_counter() const;
  uint32_t rating() const;
  base::StringPiece app_public_key() const;
  const std::vector<protocol::AppStoreSupportedPlatform>& supported_platforms();
  const std::vector<std::string>& supported_languages();

  bool is_managed() const {
    return managed_;
  }

  void set_managed(bool managed) {
    managed_ = managed;
  }

  scoped_refptr<net::IOBufferWithSize> Serialize() const override;
  common::mojom::AppStoreEntryPtr ToMojom();

private:

  base::UUID id_;

  protocol::AppStoreEntry app_proto_;

  base::UUID repo_uuid_;

  std::vector<protocol::AppStoreSupportedPlatform> supported_platforms_;

  std::vector<std::string> supported_languages_;

  bool supported_platforms_populated_;

  bool supported_languages_populated_;

  bool managed_;

  DISALLOW_COPY_AND_ASSIGN(AppStoreEntry);
};

}

#endif