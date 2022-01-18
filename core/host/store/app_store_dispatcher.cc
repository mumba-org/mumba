// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/store/app_store_dispatcher.h"

#include "core/host/store/app_store.h"
#include "core/host/store/app_store_entry.h"
#include "core/host/workspace/workspace.h"

namespace host {

namespace {

// message AppStoreEntry {
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
//   AppStoreInstallState install_state = 13;
//   AppStoreAvailabilityState availability_state = 14;
//   uint64 install_counter = 15;
//   uint32 rating = 16;
//   // not being used right now
//   // but available for future use
//   bytes app_public_key = 17;
//   repeated AppStoreSupportedPlatform supported_platforms = 18;
//   repeated string supported_languages = 19;
// }  

// struct AppStoreEntry {
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
//   AppStoreInstallState install_state;
//   AppStoreAvailabilityState availability_state;
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

protocol::AppStoreEntry FromMojomToProto(common::mojom::AppStoreEntry* entry) {
  protocol::AppStoreEntry result;
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
  result.set_install_state(static_cast<protocol::AppStoreInstallState>(entry->install_state));
  result.set_availability_state(static_cast<protocol::AppStoreAvailabilityState>(entry->availability_state));
  result.set_install_counter(entry->install_counter);
  result.set_rating(entry->rating);
  result.set_app_public_key(entry->app_public_key.data());
  for (auto it = entry->supported_platforms.begin(); it != entry->supported_platforms.end(); ++it) {
    protocol::AppStoreSupportedPlatform* platform = result.add_supported_platforms();
    platform->set_platforms(GetPlatformFromString(*it));
    platform->set_architectures(GetArchitectureFromString(*it));
  }
  for (auto it = entry->supported_languages.begin(); it != entry->supported_languages.end(); ++it) {
    result.add_supported_languages(*it);
  }
  return result;
}

}

AppStoreDispatcher::AppStoreDispatcher(scoped_refptr<Workspace> workspace, AppStore* app_store):
  workspace_(workspace),
  app_store_(app_store)  {

}

AppStoreDispatcher::~AppStoreDispatcher() {

}

void AppStoreDispatcher::AddBinding(common::mojom::AppStoreDispatcherAssociatedRequest request) {
  app_store_dispatcher_binding_.AddBinding(this, std::move(request));
}

void AppStoreDispatcher::Init() {

}

void AppStoreDispatcher::Shutdown() {

}

void AppStoreDispatcher::AddEntry(common::mojom::AppStoreEntryPtr entry, AddEntryCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&AppStoreDispatcher::AddEntryImpl, 
      base::Unretained(this),
      base::Passed(std::move(entry)),
      base::Passed(std::move(callback))));
}

void AppStoreDispatcher::AddEntryByAddress(common::mojom::AppStoreEntryDescriptorPtr descriptor, AddEntryByAddressCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&AppStoreDispatcher::AddEntryByAddressImpl, 
      base::Unretained(this),
      base::Passed(std::move(descriptor)),
      base::Passed(std::move(callback))));
}

void AppStoreDispatcher::RemoveEntry(const std::string& address, RemoveEntryCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&AppStoreDispatcher::RemoveEntryImpl, 
      base::Unretained(this),
      address,
      base::Passed(std::move(callback))));
}

void AppStoreDispatcher::RemoveEntryByUUID(const std::string& uuid, RemoveEntryByUUIDCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&AppStoreDispatcher::RemoveEntryByUUIDImpl, 
      base::Unretained(this),
      uuid,
      base::Passed(std::move(callback))));
}

void AppStoreDispatcher::LookupEntry(const std::string& address, LookupEntryCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&AppStoreDispatcher::LookupEntryImpl, 
      base::Unretained(this),
      address,
      base::Passed(std::move(callback))));
}

void AppStoreDispatcher::LookupEntryByName(const std::string& name, LookupEntryCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&AppStoreDispatcher::LookupEntryByNameImpl, 
      base::Unretained(this),
      name,
      base::Passed(std::move(callback))));
}

void AppStoreDispatcher::LookupEntryByUUID(const std::string& uuid, LookupEntryByUUIDCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&AppStoreDispatcher::LookupEntryByUUIDImpl, 
      base::Unretained(this),
      uuid,
      base::Passed(std::move(callback))));
}

void AppStoreDispatcher::HaveEntry(const std::string& address, HaveEntryCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&AppStoreDispatcher::HaveEntryImpl, 
      base::Unretained(this),
      address,
      base::Passed(std::move(callback))));
}

void AppStoreDispatcher::HaveEntryByName(const std::string& name, HaveEntryCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&AppStoreDispatcher::HaveEntryByNameImpl, 
      base::Unretained(this),
      name,
      base::Passed(std::move(callback))));
}

void AppStoreDispatcher::HaveEntryByUUID(const std::string& uuid, HaveEntryByUUIDCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&AppStoreDispatcher::HaveEntryByUUIDImpl, 
      base::Unretained(this),
      uuid,
      base::Passed(std::move(callback))));
}

void AppStoreDispatcher::ListEntries(ListEntriesCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&AppStoreDispatcher::ListEntriesImpl, 
      base::Unretained(this),
      base::Passed(std::move(callback))));
}

void AppStoreDispatcher::GetEntryCount(GetEntryCountCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&AppStoreDispatcher::GetEntryCountImpl, 
      base::Unretained(this),
      base::Passed(std::move(callback))));
}

void AppStoreDispatcher::AddWatcher(common::mojom::AppStoreWatcherPtr watcher, AddWatcherCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&AppStoreDispatcher::AddWatcherImpl, 
      base::Unretained(this),
      base::Passed(std::move(watcher)),
      base::Passed(std::move(callback))));
}

void AppStoreDispatcher::RemoveWatcher(int watcher) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&AppStoreDispatcher::RemoveWatcherImpl, 
      base::Unretained(this),
      watcher));
}

void AppStoreDispatcher::AddEntryImpl(common::mojom::AppStoreEntryPtr entry, AddEntryCallback callback) {
  std::unique_ptr<AppStoreEntry> entry_ptr = std::make_unique<AppStoreEntry>(FromMojomToProto(entry.get()));
  app_store_->InsertEntry(std::move(entry_ptr));
}

void AppStoreDispatcher::AddEntryByAddressImpl(common::mojom::AppStoreEntryDescriptorPtr descriptor, AddEntryByAddressCallback callback) {

}

void AppStoreDispatcher::RemoveEntryImpl(const std::string& address, RemoveEntryCallback callback) {

}

void AppStoreDispatcher::RemoveEntryByUUIDImpl(const std::string& uuid, RemoveEntryByUUIDCallback callback) {

}

void AppStoreDispatcher::LookupEntryImpl(const std::string& address, LookupEntryCallback callback) {

}

void AppStoreDispatcher::LookupEntryByNameImpl(const std::string& name, LookupEntryCallback callback) {

}

void AppStoreDispatcher::LookupEntryByUUIDImpl(const std::string& uuid, LookupEntryByUUIDCallback callback) {

}

void AppStoreDispatcher::HaveEntryImpl(const std::string& address, HaveEntryCallback callback) {

}

void AppStoreDispatcher::HaveEntryByNameImpl(const std::string& name, HaveEntryCallback callback) {

}

void AppStoreDispatcher::HaveEntryByUUIDImpl(const std::string& uuid, HaveEntryByUUIDCallback callback) {

}

void AppStoreDispatcher::ListEntriesImpl(ListEntriesCallback callback) {

}

void AppStoreDispatcher::GetEntryCountImpl(GetEntryCountCallback callback) {

}

void AppStoreDispatcher::AddWatcherImpl(common::mojom::AppStoreWatcherPtr watcher, AddWatcherCallback callback) {

}

void AppStoreDispatcher::RemoveWatcherImpl(int watcher) {

}

}