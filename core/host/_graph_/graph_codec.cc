// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/graph/graph_codec.h"

#include "base/logging.h"
#include "storage/db/sqlite3.h"
#include "storage/db/sqliteInt.h"

#include "core/host/graph/graph_entry.h"
#include "core/host/graph/graph_node.h"
#include "core/host/graph/graph_edge.h"
#include "core/host/graph/graph_property.h"
#include "core/host/workspace/workspace.h"
#include "core/host/schema/schema.h"
#include "core/host/schema/schema_registry.h"
#include "third_party/protobuf/src/google/protobuf/compiler/parser.h"
#include "third_party/protobuf/src/google/protobuf/io/tokenizer.h"
#include "third_party/protobuf/src/google/protobuf/io/zero_copy_stream_impl.h"
#include "third_party/protobuf/src/google/protobuf/stubs/strutil.h"
#include "third_party/protobuf/src/google/protobuf/io/zero_copy_stream_impl_lite.h"
#include "third_party/protobuf/src/google/protobuf/arena.h"
#include "third_party/protobuf/src/google/protobuf/arenastring.h"
#include "third_party/protobuf/src/google/protobuf/generated_message_table_driven.h"
#include "third_party/protobuf/src/google/protobuf/generated_message_util.h"
#include "third_party/protobuf/src/google/protobuf/inlined_string_field.h"
#include "third_party/protobuf/src/google/protobuf/metadata.h"
#include "third_party/protobuf/src/google/protobuf/message.h"
#include "third_party/protobuf/src/google/protobuf/dynamic_message.h"
#include "third_party/zlib/zlib.h"

namespace host {

namespace {

template <typename T>
std::string EncodeIntInternal(T i) {
  std::string r;
  int id_size = csqliteVarintLen(i);
  int size = csqliteVarintLen(id_size) + id_size;
  uint8_t data[size];
  uint8_t* ptr = &data[0];
  ptr += csqlitePutVarint(ptr, i);
  ptr += csqlitePutVarint(ptr, id_size);
  r.assign(reinterpret_cast<const char *>(&data[0]), size);
  return r;
}

template <typename T>
T DecodeIntInternal(const std::string& data) {
  int ilen;
  T i;
  uint8_t const* buf = reinterpret_cast<uint8_t const*>(data.data());
  buf += csqliteGetVarint(buf, (u64*)&i);
  buf += csqliteGetVarint(buf, (u64*)&ilen);
  // sanity check
  //if (buf != reinterpret_cast<uint8_t const*>(data.data()) + ilen) {
  //  DLOG(ERROR) << "bad payload: len = " << ilen << " - " << buf << " != " << (data.data() + ilen);
  //  *out = 0;
  //  return false;
  //}
  //DLOG(INFO) << "recovered id: " << i << " => encoded size: " << ilen << " payload size (len + value): " << data.size();
  return i;
}


std::string EncodeEntryInternal(const GraphEntryBase& entry) {
  std::string r;
  DCHECK(entry.Encode(&r));
  return r;
}

}

// static 
std::string GraphCodec::EncodeInt(uint64_t i) {
  return EncodeIntInternal(i);
}

// static
std::string GraphCodec::EncodeInt(int32_t i) {
  return EncodeIntInternal(i);
}

// static 
std::string GraphCodec::EncodeBlobHash(const std::string& blob) {
  uLong key = crc32(0, reinterpret_cast<const Cr_z_Bytef*>(blob.data()), blob.size());
  return EncodeIntInternal(key);
}

// static 
std::string GraphCodec::EncodeEntry(const GraphEntry& entry) {
  return EncodeEntryInternal(entry);
}

// static 
std::string GraphCodec::EncodeNode(const GraphNode& node) {
  return EncodeEntryInternal(node);
}

// static 
std::string GraphCodec::EncodeProperty(const GraphProperty& property) {
  return EncodeEntryInternal(property);
}

// static 
std::string GraphCodec::EncodeEdge(const GraphEdge& edge) {
  return EncodeEntryInternal(edge);
}

// static 
uint64_t GraphCodec::DecodeInt(const std::string& data) {
  return DecodeIntInternal<uint64_t>(data);
}

graph_t GraphCodec::DecodeId(const std::string& data) {
  return DecodeIntInternal<graph_t>(data);
}

// static 
// bool GraphCodec::PeekType(const std::string& data, protocol::GraphKind* type) {
//   Workspace* ws = Workspace::GetCurrent();
//   SchemaRegistry* protocol_registry = ws->schema_registry();
//   google::protobuf::DescriptorPool* descriptor_pool = protocol_registry->descriptor_pool();    
//   google::protobuf::DynamicMessageFactory factory(descriptor_pool);
//   Schema* schema = protocol_registry->GetSchemaByName("objects");
//   DCHECK(schema);
//   const google::protobuf::Descriptor* message_descriptor = schema->GetMessageDescriptorNamed("GraphEntry");
//   DCHECK(message_descriptor);
//   const google::protobuf::Message* message_proto = factory.GetPrototype(message_descriptor);
//   DCHECK(message_proto);
//   google::protobuf::Message* m = message_proto->New();
//   if (!m->ParseFromString(data)) {
//     DLOG(ERROR) << "GraphCodec::PeekType: failed to decode message as protobuf. forced a 'GraphEntry' maybe thats the problem";
//     return false;
//   }
//   //const google::protobuf::MessageDescriptor* m_descr = m->GetDescriptor(); 
//   const google::protobuf::Reflection* reflection = m->GetReflection();
//   for (int i = 0; i < message_descriptor->field_count(); ++i) {
//     const google::protobuf::FieldDescriptor* field_descriptor = message_descriptor->field(i);
//     if (field_descriptor && field_descriptor->name() == "kind") {
//       DCHECK(field_descriptor->cpp_type() == google::protobuf::FieldDescriptor::CPPTYPE_ENUM);
//       const google::protobuf::EnumValueDescriptor* enum_value_descr = reflection->GetEnum(*m, field_descriptor);
//       if (enum_value_descr) {
//         switch (enum_value_descr->number()) {
//           case 0: // GRAPH_DELETION
//             *type = protocol::GraphKind::GRAPH_DELETION;
//           case 1: // GRAPH_NODE
//             *type = protocol::GraphKind::GRAPH_NODE;
//           case 2: // GRAPH_EDGE
//             *type = protocol::GraphKind::GRAPH_EDGE;
//           case 3: // GRAPH_PROPERTY
//             *type = protocol::GraphKind::GRAPH_PROPERTY;
//         }
//         return true;
//       }
//     }
//   }
//   DLOG(ERROR) << "GraphCodec::PeekType: failed to infer graph type from payload";
//   return false;
// }

protocol::GraphKind GraphCodec::PeekType(const std::string& data) {
  // the kind int is the first one in any type
  // so this is easy
  int i;
  uint8_t const* buf = reinterpret_cast<uint8_t const*>(data.data());
  buf += csqliteGetVarint(buf, (u64*)&i);
  switch (i) {
    case 0: // GRAPH_DELETION
      return protocol::GRAPH_DELETION;
    case 1: // GRAPH_NODE
      return protocol::GRAPH_NODE;
    case 2: // GRAPH_EDGE
      return protocol::GRAPH_EDGE;
    case 3: // GRAPH_PROPERTY
      return protocol::GRAPH_PROPERTY;
    default:
      CHECK(false);
  }
  return protocol::GRAPH_DELETION;
}

// static 
// bool GraphCodec::DecodeInt(const std::string& data, int32_t* out) {
//   return DecodeIntInternal(data, out);
// }

}