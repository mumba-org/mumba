// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/bundle/bundle.h"

#include "base/files/file_util.h"
#include "base/files/file_enumerator.h"
#include "base/strings/string_util.h"
#include "base/path_service.h"
#include "base/task_scheduler/post_task.h"
#include "base/json/json_reader.h"
#include "core/common/protocol/message_serialization.h"
#include "core/host/workspace/workspace.h"
#include "core/host/schema/schema.h"
#include "core/host/schema/schema_registry.h"
#include "core/host/share/share_manager.h"
#include "core/host/share/share.h"
#include "core/host/application/domain.h"
#include "storage/storage.h"
#include "storage/storage_manager.h"
#include "storage/storage_utils.h"
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-compare"
#pragma clang diagnostic ignored "-Wignored-qualifiers"
#include "third_party/zetasql/parser/parse_tree.h"
#include "third_party/zetasql/parser/ast_node_kind.h"
#include "third_party/zetasql/parser/parser.h"
#include "third_party/zetasql/base/status.h"
#pragma clang diagnostic pop

namespace host {

namespace {

const char kCoreServices[] = "message FetchRequest {\n int64 started_time = 1;\n string content_type = 2;\n string url = 3;\n int64 size = 4;\n bytes data = 5;\n }\nmessage FetchReply {\n int64 size=1;\n  bytes data = 2;\n}\nservice FetchService {\n rpc FetchUnary(FetchRequest) returns (FetchReply);\n rpc FetchClientStream(stream FetchRequest) returns (FetchReply);\n rpc FetchServerStream(FetchRequest) returns (stream FetchReply);\n rpc FetchBidiStream(stream FetchRequest) returns (stream FetchReply);\n }\n";  

}

char Bundle::kClassName[] = "bundle";    

// static 
std::unique_ptr<Bundle> Bundle::Deserialize(net::IOBuffer* buffer, int size) {
  protocol::Bundle bundle_proto;
  protocol::CompoundBuffer cbuffer;
  cbuffer.Append(buffer, size);
  cbuffer.Lock();
  protocol::CompoundBufferInputStream stream(&cbuffer);
  
  if (!bundle_proto.ParseFromZeroCopyStream(&stream)) {
    return {};
  }
  return std::unique_ptr<Bundle>(new Bundle(std::move(bundle_proto)));
}

Bundle::Bundle(): managed_(false) {
  id_ = base::UUID::generate();
}

Bundle::Bundle(const std::string& name, const std::string& path, const std::string& executable_path, const std::string& resources_path):
  resource_package_(nullptr),
  application_package_(nullptr),
  managed_(false) {
  
  id_ = base::UUID::generate();
  bundle_proto_.set_uuid(id_.data, 16);
  bundle_proto_.set_name(name);
  bundle_proto_.set_path(path);
}

Bundle::Bundle(protocol::Bundle bundle_proto):
  resource_package_(nullptr),
  application_package_(nullptr),
  id_(reinterpret_cast<const uint8_t *>(bundle_proto.uuid().data())),
  bundle_proto_(std::move(bundle_proto)),
  managed_(false)  {
  
  for (int i = 0; i < bundle_proto_.packages_size(); i++) {
    protocol::BundlePackage proto = bundle_proto_.packages(i);
    std::unique_ptr<BundlePackage> package = std::make_unique<BundlePackage>(std::move(proto));
    if (package->type() == BundlePackageType::APPLICATION) {
      application_package_ = package.get();
    } else if (package->type() == BundlePackageType::RESOURCE) {
      resource_package_ = package.get();
    }
    packages_.push_back(std::move(package));
  }
}

Bundle::~Bundle() {
  
}

const std::string& Bundle::name() const {
  return bundle_proto_.name();
}

void Bundle::set_name(const std::string& name) {
  bundle_proto_.set_name(name);
}

const std::string& Bundle::application_path() {
  if (application_package_ == nullptr) {
    ResolveApplicationPackage();
  }
  return application_package_->path();
}

const std::string& Bundle::resources_path() {
  if (resource_package_ == nullptr) {
    ResolveResourcePackage();
  }
  return resource_package_->path();
}

const std::string& Bundle::path() const {
  return bundle_proto_.path();
}

void Bundle::set_path(const std::string& path) {
  bundle_proto_.set_path(path);
}

const std::string& Bundle::src_path() const {
  return bundle_proto_.src_path();
}

void Bundle::set_src_path(const std::string& path) {
  bundle_proto_.set_src_path(path);
}

void Bundle::AddPackage(std::unique_ptr<BundlePackage> package) {
  if (package->type() == BundlePackageType::APPLICATION) {
    application_package_ = package.get();
  } else if (package->type() == BundlePackageType::RESOURCE) {
    resource_package_ = package.get();
  }
  protocol::BundlePackage* cloned = bundle_proto_.mutable_packages()->Add();
  cloned->CopyFrom(package->package_proto_);
  packages_.push_back(std::move(package));
}

void Bundle::ResolvePackages() {
  for (auto it = packages_.begin(); it != packages_.end(); it++) {
    BundlePackage* package = it->get();
    if (package->type() == BundlePackageType::RESOURCE) {
      resource_package_ = package;
    } else if (package->type() == BundlePackageType::APPLICATION) {
      application_package_ = package;
    }
  }
}

void Bundle::ResolveResourcePackage() {
  for (auto it = packages_.begin(); it != packages_.end(); it++) {
    BundlePackage* package = it->get();
    if (package->type() == BundlePackageType::RESOURCE) {
      resource_package_ = package;
    }
  }
}

void Bundle::ResolveApplicationPackage() {
  for (auto it = packages_.begin(); it != packages_.end(); it++) {
    BundlePackage* package = it->get();
    if (package->type() == BundlePackageType::APPLICATION) {
      application_package_ = package;
    }
  }
}

scoped_refptr<net::IOBufferWithSize> Bundle::Serialize() const {
  return protocol::SerializeMessage(bundle_proto_);
}

void Bundle::PostUnpackActions(scoped_refptr<Workspace> workspace, const base::FilePath& path) {
  InstallSchemaAfterBundleUnpack(workspace, path.AppendASCII(resources_path()));
  InstallLibrariesAfterBundleUnpack(workspace, path.AppendASCII(application_path()));

  // create the filesets based on the resource deployed files
  base::FilePath files_path = path.AppendASCII(resources_path()).AppendASCII("files");
  
  base::FileEnumerator resources_files(files_path, false, base::FileEnumerator::DIRECTORIES);
  for (base::FilePath files_dir = resources_files.Next(); !files_dir.empty(); files_dir = resources_files.Next()) {
    DLOG(INFO) << "adding fileset entry from '" << files_dir << "' into disk '" << name() << "' named '" << files_dir.BaseName().value() << "'";
    CreateFileset(workspace, files_dir);
  }

  // now create the databases
  base::FilePath dbs_path = path.AppendASCII(resources_path()).AppendASCII("databases");
  base::FileEnumerator dbs_files(dbs_path, false, base::FileEnumerator::FILES);
  for (base::FilePath db_file = dbs_files.Next(); !db_file.empty(); db_file = dbs_files.Next()) {
    DLOG(INFO) << "adding database from '" << db_file << "' into disk '" << name() << "'";
    CreateDatabase(workspace, db_file);
  }
  
  // now create the shares
  base::FilePath shares_path = path.AppendASCII(resources_path()).AppendASCII("shares");
  base::FileEnumerator shares_files(shares_path, false, base::FileEnumerator::FILES);
  for (base::FilePath share_file = shares_files.Next(); !share_file.empty(); share_file = shares_files.Next()) {
    DLOG(INFO) << "adding share from '" << share_file << "' into disk '" << name() << "'";
    CreateShare(workspace, share_file);
  }
}

void Bundle::InstallSchemaAfterBundleUnpack(scoped_refptr<Workspace> workspace, const base::FilePath& path) {
  base::FilePath schema_path = path.AppendASCII("proto");
  base::FileEnumerator schema_files(schema_path, false, base::FileEnumerator::FILES, FILE_PATH_LITERAL("*.proto"));
  for (base::FilePath schema_file = schema_files.Next(); !schema_file.empty(); schema_file = schema_files.Next()) {
    std::string file_content;
#if defined (OS_WIN)
    std::string file_name = base::UTF16ToASCII(schema_file.RemoveExtension().BaseName().value());
#else
    std::string file_name = schema_file.RemoveExtension().BaseName().value();
#endif
    if (!base::ReadFileToString(schema_file, &file_content)) {
      DLOG(ERROR) << "failed to read schema file content at " << schema_file;
      return;
    }
    // FIXME: this is desirable only for main services.. if theres more than one
    // (a batch service for instance) the injection should not happen
    // BTW, this is a hacky way to insert common methods we will need
    InjectCoreMethods(&file_content);

    std::unique_ptr<Schema> schema = Schema::NewFromProtobuf(
      workspace->schema_registry(), 
      std::move(file_name), 
      std::move(file_content));
    DCHECK(schema);
    workspace->schema_registry()->InsertSchema(std::move(schema));
  }
}

void Bundle::InstallLibrariesAfterBundleUnpack(scoped_refptr<Workspace> workspace, const base::FilePath& path) {
  base::FilePath exe_path;
  base::PathService::Get(base::DIR_EXE, &exe_path); 

  base::FilePath input_dir = exe_path;
  
#if defined (OS_POSIX)
  base::FilePath input_dev("/dev");
#endif  
  base::FilePath dev_path = path.AppendASCII("dev");
  if (!base::CreateDirectory(dev_path)) {
    DLOG(ERROR) << "failed to create dev directory " << dev_path;
    return;
  }

  base::FilePath output_path = path.AppendASCII(
    storage::GetIdentifierForArchitecture(storage::GetHostArchitecture()));

std::vector<std::string> dev_access = {
  "urandom"
};

#if defined(OS_POSIX)
  for (auto it = dev_access.begin(); it != dev_access.end(); ++it) {
    base::CreateSymbolicLink(input_dev.AppendASCII(*it), dev_path.AppendASCII(*it));
  }
#endif

}

void Bundle::InjectCoreMethods(std::string* proto) const {
  proto->append("\n\n");
  proto->append(kCoreServices);
}

void Bundle::CreateFileset(scoped_refptr<Workspace> workspace, const base::FilePath& files_dir) {
  base::UUID uuid = base::UUID::generate();
  workspace->share_manager()->AddEntry(
    name(),
    files_dir,
    uuid,
    base::Bind(&Bundle::OnResourceCached, 
      base::Unretained(this), 
      files_dir,
      files_dir.BaseName().value(),
      uuid),
    files_dir.BaseName().value());
}

void Bundle::CreateDatabase(scoped_refptr<Workspace> workspace, const base::FilePath& db_file) {
  std::string sql_statement;
  if (!base::ReadFileToString(db_file, &sql_statement)) {
    DLOG(INFO) << "Bundle::CreateDatabase: failed to read file " << db_file << " to string";
    return;
  }

  std::unique_ptr<zetasql::ParserOutput> parser_output;
  if (!zetasql::ParseStatement(sql_statement, zetasql::ParserOptions(), &parser_output).ok()) {
    DLOG(INFO) << "Bundle::CreateDatabase: parsing sql statement failed:\n'" << sql_statement << "'";
    return;
  }

  const zetasql::ASTStatement* statement = parser_output->statement();
  LOG(INFO) << "Parse tree:\n" << statement->DebugString();
}

void Bundle::CreateShare(scoped_refptr<Workspace> workspace, const base::FilePath& share_file) {
  std::string json_data;
  if (!base::ReadFileToString(share_file, &json_data)) {
    DLOG(INFO) << "Bundle::CreateShare: failed to read file " << share_file << " to string";
    return;
  }
  std::unique_ptr<base::Value> value = base::JSONReader::Read(json_data);
  if (!value) {
    DLOG(INFO) << "Bundle::CreateShare: failed to parse json:\n" << json_data;
    return;
  }
  std::unique_ptr<base::ListValue> list = base::ListValue::From(std::move(value));
  if (!list) {
    DLOG(INFO) << "Bundle::CreateShare: failed to convert json to list";
    return;
  }
  for (size_t i = 0; i < list->GetSize(); i++) {
    base::DictionaryValue* dict;
    std::string infohash;
    std::string torrent_name;
    if (!list->GetDictionary(i, &dict)) {
      DLOG(INFO) << "Bundle::CreateShare: failed to get dictionary from list";
      continue;
    }
    if (!dict->GetString("infohash", &infohash)) {
      DLOG(INFO) << "Bundle::CreateShare: failed to get infohash from json object";
      continue;
    }
    if (!dict->GetString("name", &torrent_name)) {
      DLOG(INFO) << "Bundle::CreateShare: failed to get name from json object";
      continue;
    }
    DLOG(INFO) << "recovered torrent " << infohash << " - '" << torrent_name << "'. adding it to the application storage";
    base::UUID uuid = base::UUID::generate();
    workspace->share_manager()->CreateShareWithInfohash(
      name(), 
      storage_proto::InfoKind::INFO_FILE, 
      uuid, 
      torrent_name, 
      infohash, 
      base::Bind(&Bundle::OnShareAdded, 
        base::Unretained(this), 
        workspace,
        uuid, 
        infohash, 
        torrent_name));
  }
}

void Bundle::OnResourceCached(const base::FilePath& input_dir, const std::string& name, const base::UUID& uuid, int64_t result) {
  //DLOG(INFO) << "adding fileset entry from '" << input_dir << "' named '" << name << "' result = " << result;
}

void Bundle::OnShareAdded(scoped_refptr<Workspace> workspace, const base::UUID& uuid, const std::string& infohash, const std::string& torrent_name, int64_t result) {
  DLOG(INFO) << "on adding share uuid: " << uuid.to_string() << " with infohash '" << infohash << "' named '" << torrent_name << "' result = " << result;
  Domain* domain = workspace->GetDomain(name());  
  if (!domain) {
    DLOG(ERROR) << "Bundle::OnShareAdded: domain named " << name() << " not found";
    return;
  }
  Share* share = workspace->share_manager()->GetShare(name(), uuid);
  DCHECK(share);
  share->AddObserver(domain);
}

}