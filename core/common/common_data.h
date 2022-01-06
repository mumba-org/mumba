// Copyright 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_CORE_COMMON_COMMON_DATA_H_
#define MUMBA_CORE_COMMON_COMMON_DATA_H_

#include <string>

#include "base/files/file_path.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "core/shared/common/url.h"
#include "base/uuid.h"
#include "crypto/sha2.h"

namespace common {

// ?? not needed anymore
enum {
 kScriptModuleDBFunction = 0,
 kScriptModuleDBTable = 1,
 kScriptModuleDBBackend = 2,
 kScriptModBlob = 3,
 kScriptModBlobBackend = 4,
 kScriptModLibrary = 5,
 kScriptModRunnable = 6
};


enum CallArgType {
  kBOOL_ARG = 0,
  kINT_ARG = 1,
  kDOUBLE_ARG = 2,
  kSTRING_ARG = 3,
  kUNDEFINED_ARG = 4,
  kOBJECT_ARG = 5,
  kNULL_ARG = 6,
};

enum class RouteType : int {
  kNONE      = 0,
  kAPP       = 1,
  kBLOB      = 2,
  kDEVICE    = 3,
  kKEY       = 4,
  kPACKAGE   = 5,
  kPEER      = 6,
  kSERVICE   = 7,
  kSQL       = 8,
  kPIPE      = 9,
  kMEDIA     = 10,
  kWEB       = 11,
  kINDEX     = 12,
  kRUNNER    = 13,
  kSHELL = 14,
  kIDENTITY  = 15,
  kREGISTRY  = 16,
  kSCHEMA    = 17,
  kCUSTOM    = 18,
};

enum class DatasetType : int {
  kNONE      = 0,
  kAPP       = 1,
  kBLOB      = 2,
  kDEVICE    = 3,
  kKEY       = 4,
  kPACKAGE   = 5,
  kPEER      = 6,
  kSERVICE   = 7,
  kSQL       = 8,
  kPIPE      = 9,
  kMEDIA     = 10,
  kWEB       = 11,
  kINDEX     = 12,
  kREGISTRY  = 13,
  kSCHEMA    = 14,
  kSHELL = 15
};

struct DatasetInfo {
 DatasetType type;
 base::UUID id;
 base::UUID shell;
 base::UUID ns;
 std::string name;

 DatasetInfo() {}
 DatasetInfo(DatasetType type): type(type) {}
};

struct BlobDatasetInfo : DatasetInfo {
  BlobDatasetInfo(): DatasetInfo(DatasetType::kBLOB) {}
};

struct SQLDatasetInfo : DatasetInfo {
  SQLDatasetInfo(): DatasetInfo(DatasetType::kSQL){}
};

struct PackageDatasetInfo : DatasetInfo {
 PackageDatasetInfo(): DatasetInfo(DatasetType::kPACKAGE) {}
};

struct KeyDatasetInfo : DatasetInfo {
 KeyDatasetInfo(): DatasetInfo(DatasetType::kKEY){}
};

struct AppDatasetInfo : DatasetInfo {
 AppDatasetInfo(): DatasetInfo(DatasetType::kAPP) {}
};

struct ServiceDatasetInfo : DatasetInfo {
 ServiceDatasetInfo(): DatasetInfo(DatasetType::kSERVICE) {}
};

struct PipeDatasetInfo : DatasetInfo {
 PipeDatasetInfo(): DatasetInfo(DatasetType::kPIPE) {}
};

struct MediaDatasetInfo : DatasetInfo {
 MediaDatasetInfo(): DatasetInfo(DatasetType::kMEDIA) {}
};

struct WebDatasetInfo : DatasetInfo {
 WebDatasetInfo(): DatasetInfo(DatasetType::kWEB) {}
};

struct IndexDatasetInfo : DatasetInfo {
 IndexDatasetInfo(): DatasetInfo(DatasetType::kINDEX) {}
};

struct RegistryDatasetInfo : DatasetInfo {
 RegistryDatasetInfo(): DatasetInfo(DatasetType::kREGISTRY) {}
};

struct SchemaDatasetInfo : DatasetInfo {
 SchemaDatasetInfo(): DatasetInfo(DatasetType::kSCHEMA) {}
};

struct DatasetCreateParams {
 base::UUID shell;
 base::UUID ns;
 std::string name;
};

struct BlobDatasetCreateParams : DatasetCreateParams {
 GURL address;
 bool readonly;
};


struct SQLDatasetCreateParams : DatasetCreateParams {
 GURL address;
 bool readonly;
 std::string query;
};


struct PackageDatasetCreateParams : DatasetCreateParams {};

struct KeyDatasetCreateParams : DatasetCreateParams {};

struct PipeDatasetCreateParams : DatasetCreateParams {};

struct MediaDatasetCreateParams : DatasetCreateParams {};

struct WebDatasetCreateParams : DatasetCreateParams {};

struct AppDatasetCreateParams : DatasetCreateParams {};

struct ServiceDatasetCreateParams : DatasetCreateParams {};

struct DeviceDatasetCreateParams : DatasetCreateParams {};

struct IndexDatasetCreateParams : DatasetCreateParams {};

struct RegistryDatasetCreateParams : DatasetCreateParams {};

struct SchemaDatasetCreateParams : DatasetCreateParams {};

struct BlobCreateParams {
  std::string name;
  base::UUID uuid; // if already exists (is a update)
  base::UUID dataset;
  std::string content_type;
  uint64_t size;
};  

struct PackageCreateParams {
 base::UUID shell;
 int type;
 URL route_url;
 base::FilePath origin;
};

struct RouteCreateParams {
 base::UUID uuid;
 std::string name;
 RouteType type;
};

struct PackageInfo {
 base::UUID id;
 base::UUID shell;
 base::UUID pack;
 uint64_t pack_size;
 std::string pack_hash;
 std::string ns;
 std::string name;
 int type;

 PackageInfo();
 PackageInfo(const PackageInfo& info);
};

struct ResourceInfo {
 base::UUID uuid;
 std::string name;

 ResourceInfo() {}
 ResourceInfo(const base::UUID& uuid, const std::string& name): uuid(uuid), name(name) {}
 ResourceInfo(base::UUID&& uuid, std::string&& name): uuid(uuid), name(name) {}
};

struct AppInfo : ResourceInfo {};

struct PipeInfo : ResourceInfo {};

struct ServiceInfo : ResourceInfo  {};

struct DeviceInfo : ResourceInfo  {};

struct IdentityInfo : ResourceInfo  {};

struct PeerInfo : ResourceInfo {};

struct PeerStreamInfo : ResourceInfo {};

struct RunnerInfo : ResourceInfo {};

struct MediaInfo : ResourceInfo {};

struct WebInfo : ResourceInfo {};

struct IndexInfo : ResourceInfo {};

struct DomainInfo : ResourceInfo {
  DomainInfo() {}
  DomainInfo(const base::UUID& uuid, const std::string& name): ResourceInfo(uuid, name) {}
};

struct CallValue {
  int type;
  union {
    bool b;
    int i;
    double d;
  } entry;
  std::string entry_string;
};  

struct CallArg {
  std::string key;
  CallValue value;
  int pos;
};

struct CallInfo {
  std::string ns;
  std::string api;
  std::string method;
  std::vector<CallArg *> args;
  bool disposed;
  // internal
  size_t _last_idx;
  //std::multimap<std::string, std::string> metadata;

  CallInfo();
  CallInfo(const std::string& ns, 
           const std::string& api, 
           const std::string& method);
  CallInfo(const std::string& method);
  ~CallInfo();

  void Init(const std::string& command_line);
  void Init(const std::vector<std::string>& args, size_t start_index);

  void PushInt(int val);
  void PushDouble(double val);
  void PushBool(bool val);
  void PushString(const std::string& val);
  void PushString(std::string&& val);

  void Dispose();
};

struct CallResult {
  std::string ns;
  std::string api;
  std::string method;
  bool is_error;
  CallValue value;

  CallResult();
  ~CallResult();
};

// A more complete view.. for creation and persistent repr..
struct ShellManifest {
 base::UUID uuid;
 std::string name;
 std::string vendor;
 std::string version;

 ShellManifest();
 ShellManifest(const base::UUID& uuid, const std::string& name);
 ShellManifest(const base::UUID& uuid, const std::string& name, const std::string& vendor, const std::string& version);
 ShellManifest(const ShellManifest&);
 ~ShellManifest();
};

enum class BlobType {
 UNDEFINED = 0,
 BINARY = 1, // unstructured binary data
 TEXT = 2, // pure textual data
 DOCUMENT = 3, // structured data (single record)
 DOCUMENT_ARRAY = 4 // structured array data
};

std::string BlobTypeString(BlobType type);

struct BlobHeader {
 base::UUID uuid;
 base::UUID disk;
 std::string name;
 std::string content_hash;
 std::string content_type;
 unsigned content_length;
 BlobType type;
 int refcount;

 BlobHeader();
 BlobHeader(const BlobHeader&);
 ~BlobHeader();

 std::string ToString() const {
  std::string uuid_str = uuid.to_string();

  return base::StringPrintf(
      "%s {\n uuid: \"%s\",\n disk: \"%s\",\n type: \"%s\",\n name: \"%s\",\n content_length: %u,\n content_hash: \"%s\",\n content-type: \"%s\",\n refcount: %d\n}", 
      uuid_str.c_str(),
      uuid_str.c_str(),
      disk.to_string().c_str(),
      BlobTypeString(static_cast<common::BlobType>(type)).c_str(),
      name.c_str(),
      content_length, 
      base::ToLowerASCII(base::HexEncode(content_hash.data(), content_hash.size())).c_str(), 
      content_type.c_str(),
      refcount);
 }

 bool empty() const { return type == BlobType::UNDEFINED; }

};



}

#endif
