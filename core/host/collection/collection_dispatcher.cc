// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/collection/collection_dispatcher.h"

#include "base/base64.h"
#include "core/host/collection/collection.h"
#include "core/host/collection/collection_entry.h"
#include "core/host/workspace/workspace.h"

namespace host {

namespace {

// message CollectionEntry {
//   bytes uuid = 1;
//   string name = 2;
//   string description = 3;
//   string version = 4;
//   string license = 5;
//   string publisher = 6;
//   string publisher_url = 7;
//   bytes publisher_public_key = 8;
//   string logo_path = 9;
//   uint64 size = 10;
//   bytes repo_uuid = 11;
//   // this might match the publisher public key
//   // in some cases
//   bytes repo_public_key = 12;
//   CollectionInstallState install_state = 13;
//   CollectionAvailabilityState availability_state = 14;
//   uint64 install_counter = 15;
//   uint32 rating = 16;
//   // not being used right now
//   // but available for future use
//   bytes app_public_key = 17;
//   repeated CollectionSupportedPlatform supported_platforms = 18;
//   repeated string supported_languages = 19;
// }  

// struct CollectionEntry {
//   string uuid;
//   string name;
//   string description;
//   string version;
//   string license;
//   string publisher;
//   string publisher_url;  
//   string publisher_public_key;
//   string logo_path;
//   uint64 size;
//   string repo_uuid;
//   string repo_public_key;
//   CollectionInstallState install_state;
//   CollectionAvailabilityState availability_state;
//   uint64 install_counter;
//   uint32 rating;
//   string app_public_key;
//   array<string> supported_platforms;
//   array<string> supported_languages;
// };

protocol::BundlePlatform GetPlatformFromString(const std::string& platform) {
  bool is_mac = platform.find("MAC") != std::string::npos;
  bool is_ios = platform.find("IOS") != std::string::npos;
  bool is_android = platform.find("ANDROID") != std::string::npos;
  bool is_linux = platform.find("LINUX") != std::string::npos;
  bool is_web = platform.find("WEB") != std::string::npos;
  bool is_windows = platform.find("WINDOWS") != std::string::npos;
  if (is_mac) {
    return protocol::PLATFORM_MACOS;
  } else if (is_ios) {
    return protocol::PLATFORM_IOS;
  } else if (is_android) {
    return protocol::PLATFORM_ANDROID;
  } else if (is_linux) {
    return protocol::PLATFORM_LINUX;
  } else if (is_web) {
    return protocol::PLATFORM_WEB;
  } else if (is_windows) {
    return protocol::PLATFORM_WINDOWS;
  }
  return protocol::PLATFORM_WEB;
}

protocol::BundleArchitecture GetArchitectureFromString(const std::string& platform) {
  bool is_x86 = platform.find("X86") != std::string::npos;
  bool is_arm = platform.find("ARM") != std::string::npos;
  bool is_x64 = platform.find("X64") != std::string::npos;
  bool is_neutral = platform.find("NEUTRAL") != std::string::npos;
  bool is_arm64 = platform.find("ARM64") != std::string::npos;
  if (is_x86) {
    return protocol::ARCH_X86;
  } else if (is_arm) {
    return protocol::ARCH_ARM;
  } else if (is_x64) {
    return protocol::ARCH_X64;
  } else if (is_neutral) {
    return protocol::ARCH_NEUTRAL;
  } else if (is_arm64) {
    return protocol::ARCH_ARM64;
  }
  return protocol::ARCH_X64;
}    

protocol::CollectionEntry FromMojomToProto(common::mojom::CollectionEntry* entry) {
  protocol::CollectionEntry result;
  result.set_uuid(entry->uuid.data());
  result.set_name(entry->name);
  result.set_description(entry->description);
  result.set_version(entry->version);
  result.set_license(entry->license);
  result.set_publisher(entry->publisher);
  result.set_publisher_url(entry->publisher_url);
  result.set_publisher_public_key(entry->publisher_public_key);
  result.set_logo_path(entry->logo_path);
  result.set_size(entry->size);
  result.set_repo_uuid(entry->repo_uuid.data());
  result.set_repo_public_key(entry->repo_public_key.data());
  result.set_install_state(static_cast<protocol::CollectionEntryInstallState>(entry->install_state));
  result.set_availability_state(static_cast<protocol::CollectionEntryAvailabilityState>(entry->availability_state));
  result.set_install_counter(entry->install_counter);
  result.set_rating(entry->rating);
  result.set_public_key(entry->app_public_key.data());
  for (auto it = entry->supported_platforms.begin(); it != entry->supported_platforms.end(); ++it) {
    protocol::CollectionSupportedPlatform* platform = result.add_supported_platforms();
    platform->set_platforms(GetPlatformFromString(*it));
    platform->set_architectures(GetArchitectureFromString(*it));
  }
  for (auto it = entry->supported_languages.begin(); it != entry->supported_languages.end(); ++it) {
    result.add_supported_languages(*it);
  }
  return result;
}

}

CollectionDispatcher::CollectionDispatcher(scoped_refptr<Workspace> workspace, Collection* collection):
  workspace_(workspace),
  collection_(collection),
  share_controller_(workspace->share_manager()),
  controller_(collection_, &share_controller_),
  next_watcher_id_(1)  {

}

CollectionDispatcher::~CollectionDispatcher() {

}

void CollectionDispatcher::AddBinding(common::mojom::CollectionDispatcherAssociatedRequest request) {
  collection_dispatcher_binding_.AddBinding(this, std::move(request));
}

void CollectionDispatcher::Init() {

}

void CollectionDispatcher::Shutdown() {

}

void CollectionDispatcher::AddEntry(common::mojom::CollectionEntryPtr entry, AddEntryCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&CollectionDispatcher::AddEntryImpl, 
      base::Unretained(this),
      base::Passed(std::move(entry)),
      base::Passed(std::move(callback))));
}

void CollectionDispatcher::AddEntryByAddress(common::mojom::CollectionEntryDescriptorPtr descriptor, AddEntryByAddressCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&CollectionDispatcher::AddEntryByAddressImpl, 
      base::Unretained(this),
      base::Passed(std::move(descriptor)),
      base::Passed(std::move(callback))));
}

void CollectionDispatcher::RemoveEntry(const std::string& address, RemoveEntryCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&CollectionDispatcher::RemoveEntryImpl, 
      base::Unretained(this),
      address,
      base::Passed(std::move(callback))));
}

void CollectionDispatcher::RemoveEntryByUUID(const std::string& uuid, RemoveEntryByUUIDCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&CollectionDispatcher::RemoveEntryByUUIDImpl, 
      base::Unretained(this),
      uuid,
      base::Passed(std::move(callback))));
}

void CollectionDispatcher::LookupEntry(const std::string& address, LookupEntryCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&CollectionDispatcher::LookupEntryImpl, 
      base::Unretained(this),
      address,
      base::Passed(std::move(callback))));
}

void CollectionDispatcher::LookupEntryByName(const std::string& name, LookupEntryCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&CollectionDispatcher::LookupEntryByNameImpl, 
      base::Unretained(this),
      name,
      base::Passed(std::move(callback))));
}

void CollectionDispatcher::LookupEntryByUUID(const std::string& uuid, LookupEntryByUUIDCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&CollectionDispatcher::LookupEntryByUUIDImpl, 
      base::Unretained(this),
      uuid,
      base::Passed(std::move(callback))));
}

void CollectionDispatcher::HaveEntry(const std::string& address, HaveEntryCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&CollectionDispatcher::HaveEntryImpl, 
      base::Unretained(this),
      address,
      base::Passed(std::move(callback))));
}

void CollectionDispatcher::HaveEntryByName(const std::string& name, HaveEntryCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&CollectionDispatcher::HaveEntryByNameImpl, 
      base::Unretained(this),
      name,
      base::Passed(std::move(callback))));
}

void CollectionDispatcher::HaveEntryByUUID(const std::string& uuid, HaveEntryByUUIDCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&CollectionDispatcher::HaveEntryByUUIDImpl, 
      base::Unretained(this),
      uuid,
      base::Passed(std::move(callback))));
}

void CollectionDispatcher::ListEntries(ListEntriesCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&CollectionDispatcher::ListEntriesImpl, 
      base::Unretained(this),
      base::Passed(std::move(callback))));
}

void CollectionDispatcher::GetEntryCount(GetEntryCountCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&CollectionDispatcher::GetEntryCountImpl, 
      base::Unretained(this),
      base::Passed(std::move(callback))));
}

void CollectionDispatcher::AddWatcher(common::mojom::CollectionWatcherPtr watcher, AddWatcherCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&CollectionDispatcher::AddWatcherImpl, 
      base::Unretained(this),
      base::Passed(std::move(watcher)),
      base::Passed(std::move(callback))));
}

void CollectionDispatcher::RemoveWatcher(int watcher) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&CollectionDispatcher::RemoveWatcherImpl, 
      base::Unretained(this),
      watcher));
}

void CollectionDispatcher::AddEntryImpl(common::mojom::CollectionEntryPtr entry, AddEntryCallback callback) {
  std::unique_ptr<CollectionEntry> entry_ptr = std::make_unique<CollectionEntry>(FromMojomToProto(entry.get()));
  controller_.InsertEntry(std::move(entry_ptr));
  HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(
        std::move(callback), 
        common::mojom::CollectionStatusCode::kCOLLECTION_STATUS_OK));
}

void CollectionDispatcher::AddEntryByAddressImpl(common::mojom::CollectionEntryDescriptorPtr descriptor, AddEntryByAddressCallback callback) {
  // we are suppose to find this app over DHT
  if (descriptor->type == common::mojom::CollectionEntryAddressType::COLLECTION_DHT_ADDRESS) {
    controller_.InsertEntryByDHTAddress(descriptor->address, base::Bind(&CollectionDispatcher::OnStorageCloned,
                                                                         base::Unretained(this),
                                                                         base::Passed(std::move(callback))));
  } else if (descriptor->type == common::mojom::CollectionEntryAddressType::COLLECTION_TORRENT_ADDRESS) {
    controller_.InsertEntryByInfohashAddress(descriptor->address, base::Bind(&CollectionDispatcher::OnShareCreated,
                                                                         base::Unretained(this),
                                                                         base::Passed(std::move(callback))));
  } else {
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(
        std::move(callback), 
        common::mojom::CollectionStatusCode::kCOLLECTION_STATUS_ERR_FAILED));
  }
}

void CollectionDispatcher::RemoveEntryImpl(const std::string& address, RemoveEntryCallback callback) {
  bool result = controller_.RemoveEntry(address);
  HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(
        std::move(callback), 
        result ?
          common::mojom::CollectionStatusCode::kCOLLECTION_STATUS_OK : 
          common::mojom::CollectionStatusCode::kCOLLECTION_STATUS_ERR_FAILED));
}

void CollectionDispatcher::RemoveEntryByUUIDImpl(const std::string& uuid, RemoveEntryByUUIDCallback callback) {
  bool decoded = false;
  base::UUID id = base::UUID::from_string(uuid, &decoded);
  if (!decoded) {
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(
        std::move(callback), 
          common::mojom::CollectionStatusCode::kCOLLECTION_STATUS_ERR_FAILED));
    return;
  }
  bool result = controller_.RemoveEntry(id);
  HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(
        std::move(callback), 
        result ?
          common::mojom::CollectionStatusCode::kCOLLECTION_STATUS_OK : 
          common::mojom::CollectionStatusCode::kCOLLECTION_STATUS_ERR_FAILED));
}

void CollectionDispatcher::LookupEntryImpl(const std::string& address, LookupEntryCallback callback) {
  CollectionEntry* entry = controller_.LookupEntry(address);
  if (entry) {
    auto mojo_ptr = entry->ToMojom();
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(
        std::move(callback), 
        common::mojom::CollectionStatusCode::kCOLLECTION_STATUS_OK, 
        base::Passed(std::move(mojo_ptr))));
  } else { 
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(
        std::move(callback), 
          common::mojom::CollectionStatusCode::kCOLLECTION_STATUS_ERR_FAILED, nullptr));
  }
}

void CollectionDispatcher::LookupEntryByNameImpl(const std::string& name, LookupEntryCallback callback) {
  CollectionEntry* entry = controller_.LookupEntryByName(name);
  if (entry) {
    auto mojo_ptr = entry->ToMojom();
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(
        std::move(callback), 
        common::mojom::CollectionStatusCode::kCOLLECTION_STATUS_OK, 
        base::Passed(std::move(mojo_ptr))));
  } else { 
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(
        std::move(callback), 
          common::mojom::CollectionStatusCode::kCOLLECTION_STATUS_ERR_FAILED, nullptr));
  }
}

void CollectionDispatcher::LookupEntryByUUIDImpl(const std::string& uuid, LookupEntryByUUIDCallback callback) {
  bool decoded = false;
  base::UUID id = base::UUID::from_string(uuid, &decoded);
  if (!decoded) {
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(
        std::move(callback), 
          common::mojom::CollectionStatusCode::kCOLLECTION_STATUS_ERR_FAILED, nullptr));
    return;
  }
  CollectionEntry* entry = controller_.LookupEntryByUUID(id);
  if (entry) {
    auto mojo_ptr = entry->ToMojom();
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(
        std::move(callback), 
        common::mojom::CollectionStatusCode::kCOLLECTION_STATUS_OK, 
        base::Passed(std::move(mojo_ptr))));
  } else { 
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(
        std::move(callback), 
          common::mojom::CollectionStatusCode::kCOLLECTION_STATUS_ERR_FAILED, nullptr));
  }
}

void CollectionDispatcher::HaveEntryImpl(const std::string& address, HaveEntryCallback callback) {
  bool result = controller_.HaveEntry(address);
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE,
    base::BindOnce(
      std::move(callback), 
      result));
}

void CollectionDispatcher::HaveEntryByNameImpl(const std::string& name, HaveEntryCallback callback) {
  bool result = controller_.HaveEntryByName(name);
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE,
    base::BindOnce(
      std::move(callback), 
      result));
}

void CollectionDispatcher::HaveEntryByUUIDImpl(const std::string& uuid, HaveEntryByUUIDCallback callback) {
  bool decoded = false;
  base::UUID id = base::UUID::from_string(uuid, &decoded);
  if (!decoded) {
    HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(
        std::move(callback), false));
    return;
  }
  bool result = controller_.HaveEntryByUUID(id);
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE,
    base::BindOnce(
      std::move(callback), 
      result));
}

void CollectionDispatcher::ListEntriesImpl(ListEntriesCallback callback) {
  std::vector<common::mojom::CollectionEntryPtr> result;
  std::vector<CollectionEntry*> entries = controller_.ListEntries();
  for (auto* entry : entries) {
    result.push_back(entry->ToMojom());
  }
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE,
    base::BindOnce(
      std::move(callback), 
      base::Passed(std::move(result))));
}

void CollectionDispatcher::GetEntryCountImpl(GetEntryCountCallback callback) {
  size_t result = controller_.GetEntryCount();
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE,
    base::BindOnce(
      std::move(callback), 
      result));
}

void CollectionDispatcher::AddWatcherImpl(common::mojom::CollectionWatcherPtr watcher, AddWatcherCallback callback) {
  // FIXME: just adding but not triggering when the events happen
  int id = next_watcher_id_++;
  watchers_.emplace(std::make_pair(id, std::move(watcher)));
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE,
    base::BindOnce(
      std::move(callback), 
      id));
}

void CollectionDispatcher::RemoveWatcherImpl(int watcher) {
  auto found = watchers_.find(watcher);
  if (found != watchers_.end()) {
    watchers_.erase(found);
  }
}

void CollectionDispatcher::OnStorageCloned(AddEntryByAddressCallback callback, int result) {
  common::mojom::CollectionStatusCode r = (result == 0 ? common::mojom::CollectionStatusCode::kCOLLECTION_STATUS_OK : common::mojom::CollectionStatusCode::kCOLLECTION_STATUS_ERR_FAILED);
  HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(
        std::move(callback), 
        r));
}

void CollectionDispatcher::OnShareCreated(AddEntryByAddressCallback callback, int result) {
  common::mojom::CollectionStatusCode r = (result == 0 ? common::mojom::CollectionStatusCode::kCOLLECTION_STATUS_OK : common::mojom::CollectionStatusCode::kCOLLECTION_STATUS_ERR_FAILED);
  HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(
        std::move(callback), 
        r));
}

}