// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/volume/volume_source.h"

#include "core/common/protocol/message_serialization.h"

//#include "db/sqlite3.h"
//#include "db/sqliteInt.h"

namespace host {

// static 
// std::unique_ptr<VolumeSource> VolumeSource::Deserialize(const std::string& data) {
//   std::unique_ptr<VolumeSource> source(new VolumeSource());
//   uint8_t const* d = reinterpret_cast<uint8_t const*>(data.data());
//   uint64_t name_len;

//   //d += csqliteGetVarint(d, (u64*)&source->id_);
//   source->id_ = base::UUID(d);
//   d += 16;
//   d += csqliteGetVarint(d, (u64*)&name_len);

//   source->name_ = std::string(reinterpret_cast<char const*>(d), name_len);

//   return source;
// }

std::unique_ptr<VolumeSource> VolumeSource::Deserialize(net::IOBuffer* buffer, int size) {
  protocol::VolumeSource pack_proto;
  protocol::CompoundBuffer cbuffer;
  cbuffer.Append(buffer, size);
  
  protocol::CompoundBufferInputStream stream(&cbuffer);
  
  if (!pack_proto.ParseFromZeroCopyStream(&stream)) {
    return {};
  }
  return std::unique_ptr<VolumeSource>(new VolumeSource(std::move(pack_proto)));
}

VolumeSource::VolumeSource(protocol::VolumeSource volume_proto): 
  id_(reinterpret_cast<const uint8_t *>(volume_proto.uuid().data())),
  proto_(std::move(volume_proto)), 
  managed_(false) {
  
}

VolumeSource::VolumeSource(): 
  id_(base::UUID::generate()), 
  managed_(false) {
  
}

VolumeSource::~VolumeSource() {

}

scoped_refptr<net::IOBufferWithSize> VolumeSource::Serialize() const {
  return protocol::SerializeMessage(proto_);
}

}