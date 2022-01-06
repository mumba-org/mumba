// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/manifest_proto.h"

#include "base/logging.h"
#include "third_party/libxml/chromium/libxml_utils.h"

namespace storage {

namespace {

const char IdentifierKey[] = "identifier";
const char TypeKey[] = "type";
const char VersionKey[] = "version";
const char SignatureKey[] = "signature";
const char SchemeKey[] = "scheme";
const char AddressKey[] = "address";

}

// static 
std::unique_ptr<ManifestProto> ManifestProto::ParseFromEncodedProtobuf(const std::string& data) {
  std::unique_ptr<storage_proto::ManifestProto> manifest_proto(new storage_proto::ManifestProto());
  if (!manifest_proto->ParseFromString(data)) {
    return {};
  }
  return std::unique_ptr<ManifestProto>(new ManifestProto(std::move(manifest_proto)));
}

// static 
std::unique_ptr<ManifestProto> ManifestProto::ParseFromXMLString(const std::string& xml) {
  ManifestProtoBuilder builder;
  std::unique_ptr<storage_proto::ManifestProto> proto = builder.BuildProtoFromXML(xml);
  if (!proto) {
    return {};
  }
  return std::unique_ptr<ManifestProto>(new ManifestProto(std::move(proto)));
}

// static 
bool ManifestProto::ParseProtoFromXMLString(const std::string& xml, storage_proto::ManifestProto* out) {
  ManifestProtoBuilder builder;
  return builder.SerializeProtoFromXML(xml, out);
}

ManifestProto::ManifestProto(std::unique_ptr<storage_proto::ManifestProto> manifest_proto):
  manifest_proto_(std::move(manifest_proto)),
  path_(manifest_proto_->resource().path()) {
  
}

ManifestProto::~ManifestProto() {

}

storage_proto::ResourceKind ManifestProto::resource_type() const {
  return manifest_proto_->resource().kind();
}

const base::FilePath& ManifestProto::path() const {
  return path_;
}

ManifestProtoBuilder::ManifestProtoBuilder() {

}

std::unique_ptr<storage_proto::ManifestProto> ManifestProtoBuilder::BuildProtoFromXML(const std::string& xml_string) {
  std::unique_ptr<storage_proto::ManifestProto> proto(new storage_proto::ManifestProto());
  if (!ParseFromXMLString(xml_string, proto.get())) {
    return {};
  }
  return proto;
}

bool ManifestProtoBuilder::SerializeProtoFromXML(const std::string xml_string, storage_proto::ManifestProto* manifest) {
  return ParseFromXMLString(xml_string, manifest);
}

bool ManifestProtoBuilder::ParseFromXMLString(const std::string& xml_string, storage_proto::ManifestProto* proto) {
  XmlReader reader;

  if (!reader.Load(xml_string)) {
    LOG(ERROR) << "XmlReader failed to load manifest data";
    return false;
  }

  while (true) {
    std::string value;
    
    if (reader.NodeName() == IdentifierKey) {
      reader.ReadElementContent(&value);
      proto->set_identifier(value);
    } else if (reader.NodeName() == TypeKey) {
      reader.ReadElementContent(&value);
      if (value == "application") {
	      proto->set_profile(storage_proto::APPLICATION_PROFILE);
      } else if (value == "shell") {
        proto->set_profile(storage_proto::SHELL_PROFILE);
      } else if (value == "workspace") {
        proto->set_profile(storage_proto::WORKSPACE_PROFILE);
      } else {
        NOTREACHED();
      }
    } else if (reader.NodeName() == VersionKey) {
      reader.ReadElementContent(&value);
      proto->set_version(value);
    } else if (reader.NodeName() == SignatureKey) {
      reader.ReadElementContent(&value);
      auto* sign = proto->mutable_signature();
      sign->set_kind(storage_proto::Signature::PKCS11);
      sign->set_data(value);
    } else if (reader.NodeName() == SchemeKey) {
      reader.ReadElementContent(&value);
      proto->set_scheme(value);
    } else if (reader.NodeName() == AddressKey) {
      reader.ReadElementContent(&value);
      proto->set_address(value);
    }
    
    if (!reader.Read())
      break;
  }

  return true;
}


}
