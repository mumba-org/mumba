// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_STORE_COLLECTION_ENTRY_H_
#define MUMBA_HOST_STORE_COLLECTION_ENTRY_H_

#include <memory>

#include "base/macros.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/string_piece.h"
#include "base/uuid.h"
#include "core/host/data/resource.h"
#include "core/common/proto/objects.pb.h"
#include "core/host/serializable.h"
#include "core/shared/common/mojom/collection.mojom.h"

namespace host {

class CollectionEntry : public Resource {
public:
  static char kClassName[];
  static std::unique_ptr<CollectionEntry> Deserialize(net::IOBuffer* buffer, int size);
  
  CollectionEntry();
  CollectionEntry(protocol::CollectionEntry proto);

  ~CollectionEntry() override;

  const base::UUID& id() const override {
    return id_;
  }

  const std::string& name() const override;
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
  protocol::CollectionEntryInstallState install_state() const;
  protocol::CollectionEntryAvailabilityState availability_state() const;
  uint64_t install_counter() const;
  uint32_t rating() const;
  base::StringPiece public_key() const;
  const std::vector<protocol::CollectionSupportedPlatform>& supported_platforms();
  const std::vector<std::string>& supported_languages();

  bool is_managed() const override {
    return managed_;
  }

  void set_managed(bool managed) {
    managed_ = managed;
  }

  scoped_refptr<net::IOBufferWithSize> Serialize() const override;
  common::mojom::CollectionEntryPtr ToMojom();

private:

  base::UUID id_;

  protocol::CollectionEntry app_proto_;

  base::UUID repo_uuid_;

  std::vector<protocol::CollectionSupportedPlatform> supported_platforms_;

  std::vector<std::string> supported_languages_;

  bool supported_platforms_populated_;

  bool supported_languages_populated_;

  bool managed_;

  DISALLOW_COPY_AND_ASSIGN(CollectionEntry);
};

}

#endif