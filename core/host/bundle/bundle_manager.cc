// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/bundle/bundle_manager.h"

#include "base/sha1.h"
#include "base/task_scheduler/post_task.h"
#include "base/base_paths.h"
#include "base/path_service.h"
#include "base/command_line.h"
#include "base/at_exit.h"
#include "base/files/file_util.h"
#include "base/rand_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "core/host/workspace/workspace.h"
#include "core/host/bundle/bundle_model.h"
#include "core/host/bundle/bundle_creator.h"
#include "core/host/share/share_database.h"
#include "core/host/bundle/bundle.h"
#include "storage/storage_utils.h"
#include "base/sha1.h"
#ifdef LOCK_WRITE
#undef LOCK_WRITE
#endif
#include "third_party/msix/src/inc/public/AppxPackaging.hpp"
#include "third_party/msix/src/inc/shared/ComHelper.hpp"
#include "third_party/msix/src/inc/internal/StringStream.hpp"
#include "third_party/msix/src/inc/internal/VectorStream.hpp"
#include "core/host/bundle/bundle_utils.h"

namespace host {

namespace {

std::string SanitizeName(const std::string& name) {
  std::string real_name = name;
  size_t offset = real_name.find_first_of(".");
  if (offset != std::string::npos) {
    real_name = real_name.substr(0, offset);
  }
  return real_name;
}


}

BundleManager::BundleManager(scoped_refptr<Workspace> workspace): 
  workspace_(std::move(workspace)) {
  
}

BundleManager::~BundleManager() {
  
}

void BundleManager::Init(scoped_refptr<ShareDatabase> db, DatabasePolicy policy) {
  model_.reset(new BundleModel(db, policy));
  model_->Load(base::Bind(&BundleManager::OnLoad, base::Unretained(this)));
}

void BundleManager::AddObserver(BundleManagerObserver* observer) {
  observers_.push_back(observer);
}

void BundleManager::RemoveObserver(BundleManagerObserver* observer) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    if (observer == *it) {
      observers_.erase(it);
      return;
    }
  }
}

bool BundleManager::IsBundleInstalled(const std::string& name) const {
  // fixme: the BundleModel must be the real oracle about that now
  //return base::DirectoryExists(path);
  return model_->HaveBundle(name);
}

bool BundleManager::HaveBundle(const base::UUID& id) {
  return model_->HaveBundle(id);
}

bool BundleManager::HaveBundle(const std::string& name) {
  return model_->HaveBundle(name);
}

Bundle* BundleManager::GetBundle(const base::UUID& id) {
  return model_->GetBundle(id);
}

Bundle* BundleManager::GetBundle(const std::string& name) {
  return model_->GetBundle(name);
}

void BundleManager::PackBundle(const std::string& name, const base::FilePath& src, bool no_frontend, base::OnceCallback<void(int)> callback) {
  
  base::PostTaskWithTraits(
    FROM_HERE,
    { base::WithBaseSyncPrimitives(), base::MayBlock() },
    base::BindOnce(
      &BundleManager::PackBundleImpl, 
      base::Unretained(this), 
      name,
      src,
      no_frontend,
      scoped_refptr<base::SingleThreadTaskRunner>(),
      base::Passed(std::move(callback))));
}

void BundleManager::PackBundle(const std::string& name, const base::FilePath& src, bool no_frontend, scoped_refptr<base::SingleThreadTaskRunner> reply_to, base::OnceCallback<void(int)> callback) {
  base::PostTaskWithTraits(
    FROM_HERE,
    { base::WithBaseSyncPrimitives(), base::MayBlock() },
    base::BindOnce(
      &BundleManager::PackBundleImpl, 
      base::Unretained(this), 
      name,
      src,
      no_frontend,
      reply_to,
      base::Passed(std::move(callback))));
}

void BundleManager::UnpackBundle(const std::string& name, const base::FilePath& src, base::OnceCallback<void(bool)> callback) {
  base::FilePath dest = GetOutputPath();
  scoped_refptr<base::SingleThreadTaskRunner> reply_to = base::ThreadTaskRunnerHandle::Get();
  base::PostTaskWithTraits(
    FROM_HERE,
    { base::WithBaseSyncPrimitives(), base::MayBlock() },
    base::BindOnce(
      &BundleManager::UnpackBundleImpl, 
      base::Unretained(this), 
      name,
      src,
      dest,
      reply_to,
      base::Passed(std::move(callback))));
}

void BundleManager::UnpackBundle(const std::string& name, const base::FilePath& src, scoped_refptr<base::SingleThreadTaskRunner> reply_to, base::OnceCallback<void(bool)> callback) {
  base::FilePath dest = GetOutputPath();
  
  base::PostTaskWithTraits(
    FROM_HERE,
    { base::WithBaseSyncPrimitives(), base::MayBlock() },
    base::BindOnce(
      &BundleManager::UnpackBundleImpl, 
      base::Unretained(this), 
      name,
      src,
      dest,
      reply_to,
      base::Passed(std::move(callback))));
}

void BundleManager::UnpackBundleFromContents(const std::string& name, base::StringPiece contents, base::OnceCallback<void(bool)> callback) {
  base::FilePath dest = GetOutputPath();
  
  base::PostTaskWithTraits(
    FROM_HERE,
    { base::WithBaseSyncPrimitives(), base::MayBlock() },
    base::BindOnce(
      &BundleManager::UnpackBundleFromContentsImpl, 
      base::Unretained(this), 
      name,
      base::Passed(std::move(contents)),
      dest,
      base::Passed(std::move(callback))));
}

void BundleManager::SignBundle(const base::FilePath& src, const std::vector<uint8_t>& signature, base::OnceCallback<void(int)> callback) {
   base::PostTaskWithTraits(
    FROM_HERE,
    { base::WithBaseSyncPrimitives(), base::MayBlock() },
    base::BindOnce(
      &BundleManager::SignBundleImpl, 
      base::Unretained(this), 
      src,
      signature,
      scoped_refptr<base::SingleThreadTaskRunner>(),
      base::Passed(std::move(callback))));
}

void BundleManager::SignBundle(const base::FilePath& src, const std::vector<uint8_t>& signature, scoped_refptr<base::SingleThreadTaskRunner> reply_to, base::OnceCallback<void(int)> callback) {
   base::PostTaskWithTraits(
    FROM_HERE,
    { base::WithBaseSyncPrimitives(), base::MayBlock() },
    base::BindOnce(
      &BundleManager::SignBundleImpl, 
      base::Unretained(this), 
      src,
      signature,
      reply_to,
      base::Passed(std::move(callback))));
}

void BundleManager::InitBundle(const std::string& name, const base::FilePath& src, base::OnceCallback<void(int)> callback) {
  base::PostTaskWithTraits(
    FROM_HERE,
    { base::WithBaseSyncPrimitives(), base::MayBlock() },
    base::BindOnce(
      &BundleManager::InitBundleImpl, 
      base::Unretained(this), 
      name,
      src,
      scoped_refptr<base::SingleThreadTaskRunner>(),
      base::Passed(std::move(callback))));
}

void BundleManager::InitBundle(const std::string& name, const base::FilePath& src, scoped_refptr<base::SingleThreadTaskRunner> reply_to, base::OnceCallback<void(int)> callback) {
  base::PostTaskWithTraits(
    FROM_HERE,
    { base::WithBaseSyncPrimitives(), base::MayBlock() },
    base::BindOnce(
      &BundleManager::InitBundleImpl, 
      base::Unretained(this), 
      name,
      src,
      reply_to,
      base::Passed(std::move(callback))));
}

void BundleManager::UnpackBundleSync(const std::string& name, const base::FilePath& src, scoped_refptr<base::SingleThreadTaskRunner> reply_to, base::OnceCallback<void(bool)> callback) {
  base::FilePath dest = GetOutputPath();
  UnpackBundleImpl(name, src, dest, reply_to, std::move(callback));
}

void BundleManager::UnpackBundleFromContentsSync(const std::string& name, base::StringPiece contents, base::OnceCallback<void(bool)> callback) {
  base::FilePath dest = GetOutputPath();
  UnpackBundleFromContentsImpl(name, contents, dest, std::move(callback));
}

void BundleManager::UnpackBundleImpl(const std::string& name, const base::FilePath& src, const base::FilePath& dest, scoped_refptr<base::SingleThreadTaskRunner> reply_to, base::OnceCallback<void(bool)> callback) {
  std::string real_name = SanitizeName(name);
  
  if (!ValidateBundleBeforeUnpack(src)) {
    if (reply_to) {
      reply_to->PostTask(FROM_HERE,
                        base::BindOnce(std::move(callback),
                                        false));
    } else {
      std::move(callback).Run(false);
    }
    return;
  }
  
  if (!BeforeBundleUnpack(dest)) {
    if (reply_to) {
      reply_to->PostTask(FROM_HERE,
                        base::BindOnce(std::move(callback),
                                        false));
    } else {
      std::move(callback).Run(false);
    }
    return;
  }

  if (!BundleUtils::UnpackBundle(src, dest)) {
    DLOG(ERROR) << "BundleManager::UnpackBundle: failed to unpack on " << dest;
    if (reply_to) {
      reply_to->PostTask(FROM_HERE,
                        base::BindOnce(std::move(callback),
                                        false));
    } else {
      std::move(callback).Run(false);
    }
    return;  
  }

  std::unique_ptr<Bundle> bundle_info = BundleUtils::CreateBundleFromBundleFile(src);
  DCHECK(bundle_info);
  
  base::FilePath unpacked_exe_dest = dest.AppendASCII(bundle_info->application_path());
  
  if (!AfterBundleUnpack(real_name, unpacked_exe_dest)) {
    if (reply_to) {
      reply_to->PostTask(FROM_HERE,
                        base::BindOnce(std::move(callback),
                                        false));
    } else {
      std::move(callback).Run(false);
    }
    return;
  }

  model_->AddBundle(std::move(bundle_info));

  if (reply_to) {
    reply_to->PostTask(FROM_HERE, base::BindOnce(std::move(callback), true));
    return;
  } 
  std::move(callback).Run(true);
}

void BundleManager::UnpackBundleFromContentsImpl(const std::string& name, base::StringPiece contents, const base::FilePath& dest, base::OnceCallback<void(bool)> callback) {
  // uint32_t written = 0;
  // std::vector<std::uint8_t> stream_vector;
  // //LARGE_INTEGER start = {{ 0 }};

  // if (!BeforeBundleUnpack(dest)) {
  //   std::move(callback).Run(false);
  //   return;
  // }
  
  // MSIX::ComPtr<IStream> stream = MSIX::ComPtr<IStream>::Make<MSIX::VectorStream>(&stream_vector);
  // stream->Write(contents.data(), contents.size(), &written);

  // if (written != static_cast<uint32_t>(contents.size())) {
  //   DLOG(ERROR) << "BundleManager::UnpackBundleFromContents: failed to write raw contents to output stream";
  //   std::move(callback).Run(false);
  //   return;
  // }

  // // int r = UnpackPackageFromStream(MSIX_PACKUNPACK_OPTION::MSIX_PACKUNPACK_OPTION_NONE,
  // //                                 MSIX_VALIDATION_OPTION::MSIX_VALIDATION_OPTION_SKIPSIGNATURE, 
  // //                                 stream.Get(), 
  // //                                 const_cast<char*>(dest.value().c_str()));

  // MSIX_VALIDATION_OPTION validation = MSIX_VALIDATION_OPTION_SKIPSIGNATURE;
  // MSIX_PACKUNPACK_OPTION packUnpack = MSIX_PACKUNPACK_OPTION_NONE;
  // MSIX_APPLICABILITY_OPTIONS applicability = MSIX_APPLICABILITY_OPTION_FULL;

  // int r = UnpackBundleFromStream(
  //   packUnpack,
  //   validation,
  //   applicability,
  //   stream.Get(),
  //   const_cast<char*>(dest.value().c_str()));
  
  // if (r != 0) {
  //   DLOG(ERROR) << "BundleManager::UnpackBundleFromContents: failed to unpack on " << dest;
  //   std::move(callback).Run(false);
  //   return;  
  // }

  // std::string real_name = SanitizeName(name);
  // if (!AfterBundleUnpack(real_name, dest)) {
  //   std::move(callback).Run(false);
  //   return;
  // }

  // DISABLED: we dont need to pack in a chrome bundle if its a bundle in itself
  //           we only need to make sure the bundle is available in the mumba installation directory  

  DCHECK(false);
  std::move(callback).Run(true);
}

bool BundleManager::BeforeBundleUnpack(const base::FilePath& dest) const {
  if (!base::DirectoryExists(dest)) {
    if (!base::CreateDirectory(dest)) {
      DLOG(ERROR) << "failed while creating dir " << dest;
      return false;
    }
  }
  return true;
}

bool BundleManager::ValidateBundleBeforeUnpack(const base::FilePath& src) {
  // We need to validate the bundle before unpack like, signature
  // if we have a host os and architecture build too

  // if the host mumba deploy is on windows and the bundle only have
  // linux builds we need to deny installation here
  
  // the first check is to see if the file is really there
  if (!base::PathExists(src)) {
    DLOG(INFO) << "bundle installation failed: bundle file " << src << " is not there";
    return false;
  }

  return true;
}

void BundleManager::OnLoad(int r, int count) {
  NotifyBundlesLoad(r, count);
}

bool BundleManager::AfterBundleUnpack(const std::string& name, const base::FilePath& dest) const {
  // get the executable bundle directory
  // NOTE: we need a Bundle index with each bundle and
  //       we need to fix this path in there so we can reuse it
  //       for now is this
  
  // now we need to set the correct executable flips
  // at least on posix
#if defined(OS_POSIX)
  base::FilePath service_out_file = dest.Append(storage::GetPathForArchitecture(name + "_service", storage::GetHostArchitecture(), storage_proto::LIBRARY));
  base::FilePath app_out_file = dest.Append(storage::GetPathForArchitecture(name + "_app", storage::GetHostArchitecture(), storage_proto::PROGRAM));
  int current_perm = 0;
  if (!base::GetPosixFilePermissions(service_out_file, &current_perm)) {
    printf("error while getting file permission for %s\n", service_out_file.value().c_str());
    return false;
  }
  current_perm = current_perm | 
    base::FILE_PERMISSION_EXECUTE_BY_USER |
    base::FILE_PERMISSION_EXECUTE_BY_GROUP |
    base::FILE_PERMISSION_EXECUTE_BY_OTHERS;
  if (!base::SetPosixFilePermissions(service_out_file, current_perm)) {
    printf("error while setting file permission for %s\n", service_out_file.value().c_str());
    return false;
  }

  if (!base::GetPosixFilePermissions(app_out_file, &current_perm)) {
    printf("error while getting file permission for %s\n", app_out_file.value().c_str());
    return false;
  }
  
  current_perm = current_perm | 
    base::FILE_PERMISSION_EXECUTE_BY_USER |
    base::FILE_PERMISSION_EXECUTE_BY_GROUP |
    base::FILE_PERMISSION_EXECUTE_BY_OTHERS;
  
  if (!base::SetPosixFilePermissions(app_out_file, current_perm)) {
    printf("error while setting file permission for %s\n", app_out_file.value().c_str());
    return false;
  }
#endif
  return true;
}

base::FilePath BundleManager::GetOutputPath() const {
  base::FilePath out_path = workspace_->tmp_dir();
  return out_path.AppendASCII("app" + base::IntToString(base::RandInt(0, std::numeric_limits<int16_t>::max())));
}

void BundleManager::SignBundleImpl(const base::FilePath& src, const std::vector<uint8_t>& signature, scoped_refptr<base::SingleThreadTaskRunner> reply_to, base::OnceCallback<void(int)> callback) {
  // TODO: not really working yet
  bool result = false;//BundleUtils::SignBundle(src, signature);
  //std::move(callback).Run(result ? net::OK : net::ERR_FAILED);
  if (reply_to) {
    reply_to->PostTask(FROM_HERE, 
                     base::BindOnce(
                       std::move(callback),
                       result ? net::OK : net::ERR_FAILED));
  } else {
    std::move(callback).Run(result ? net::OK : net::ERR_FAILED);
  }
}

void BundleManager::PackBundleImpl(const std::string& name, const base::FilePath& src, bool no_frontend, scoped_refptr<base::SingleThreadTaskRunner> reply_to, base::OnceCallback<void(int)> callback) {
  BundleCreator creator;
  bool packed = creator.PackBundle(name, src, no_frontend);
  
  if (!packed) {
    if (reply_to) {
      reply_to->PostTask(FROM_HERE, 
                        base::BindOnce(std::move(callback),
                                        net::ERR_FAILED));
    } else {
      std::move(callback).Run(net::ERR_FAILED);
    }
    return;
  }
  
  if (reply_to) {
    reply_to->PostTask(FROM_HERE, 
                     base::BindOnce(std::move(callback),
                                      net::OK));
  } else {
    std::move(callback).Run(net::OK);
  }
}

void BundleManager::InitBundleImpl(const std::string& name, const base::FilePath& src, scoped_refptr<base::SingleThreadTaskRunner> reply_to, base::OnceCallback<void(int)> callback) {
  BundleCreator creator;
  bool init_bundle = creator.InitBundle(name, src);
  if (!init_bundle) {
    if (reply_to) {
      reply_to->PostTask(FROM_HERE, 
                         base::BindOnce(std::move(callback),
                                        net::ERR_FAILED));
    } else {
      std::move(callback).Run(net::ERR_FAILED);
    }
    return;
  }

  if (reply_to) {
    reply_to->PostTask(FROM_HERE, 
                        base::BindOnce(std::move(callback),
                                      net::OK));
    return;
  }

  std::move(callback).Run(net::OK);
}

void BundleManager::NotifyBundleAdded(Bundle* bundle) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    BundleManagerObserver* observer = *it;
    observer->OnBundleAdded(bundle);
  }
}

void BundleManager::NotifyBundleRemoved(Bundle* bundle) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    BundleManagerObserver* observer = *it;
    observer->OnBundleRemoved(bundle);
  }
}

void BundleManager::NotifyBundlesLoad(int r, int count) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    BundleManagerObserver* observer = *it;
    observer->OnBundlesLoad(r, count);
  }
}

const google::protobuf::Descriptor* BundleManager::resource_descriptor() {
  Schema* schema = workspace_->schema_registry()->GetSchemaByName("objects.proto");
  DCHECK(schema);
  return schema->GetMessageDescriptorNamed("Bundle");
}

std::string BundleManager::resource_classname() const {
  return Bundle::kClassName;
}

}