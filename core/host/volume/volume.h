// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_CONTAINER_CONTAINER_H_
#define MUMBA_HOST_CONTAINER_CONTAINER_H_

#include "base/macros.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "base/strings/string_util.h"
#include "base/uuid.h"
#include "core/common/proto/objects.pb.h"
#include "core/host/serializable.h"
#include "storage/storage.h"
#include "storage/torrent.h"
#include "storage/storage_manager.h"
#include "core/host/data/resource.h"

namespace host {
class VolumeSource;
class VolumeReader;
class Bundle;

// Note: this is a good case to use flags instead
enum class VolumeState : int {
  kINIT = 0,
  kSYNCING = 1, // partial and downloading from source
  kPAUSED = 2, // partial and stopped
  kFULL = 3, // fully downloaded, but not being seeded
  kFULL_AND_SERVING = 4 // fully downloaded and seeding/serving it
};
/*
 * A Volume is a 'proto-domain'
 * Something that can become a app-host with one or more apps in it
 */
class Volume : public Resource {
public:
  static char kClassName[];
  
  class Observer {
  public:
    virtual ~Observer() {}
    virtual void OnStateChanged(VolumeState old_state, VolumeState new_state) = 0;  
  };

  static std::unique_ptr<Volume> Deserialize(storage::Storage* volume_storage, Bundle* bundle, net::IOBuffer* buffer, int size);
  static std::unique_ptr<Volume> New(storage::Storage* volume_storage, Bundle* bundle);
  //static std::unique_ptr<Volume> New();

  Volume(storage::Storage* volume_storage, Bundle* bundle);
  ~Volume() override;

  const base::UUID& id() const override {
    return id_;
  }

  bool is_valid() const {
    return valid_;
  }

  const std::string& name() const override {
    return volume_proto_.name();
  }

  base::FilePath path() const {
  #if defined(OS_WIN)  
    return base::FilePath(base::ASCIIToUTF16(volume_proto_.path()));
  #else
    return base::FilePath(volume_proto_.path());
  #endif
  }

  const base::UUID& root_tree() const {
    return root_tree_;
  }

  int64_t size() const {
    return volume_proto_.size();
  }

  const std::string& pubkey() const {
    return volume_proto_.pubkey();
  }

  const std::string& creator() const {
    return volume_proto_.creator();
  }

  VolumeState state() const {
    return state_;
  }

  void set_state(VolumeState state) {
    VolumeState old = state_;
    state_ = state;
    NotifyStateChanged(old, state);
  }

  bool is_partial() const {
    return state_ == VolumeState::kINIT || 
      state_ == VolumeState::kSYNCING || 
      state_ == VolumeState::kPAUSED;
  }

  bool is_complete() const {
    return state_ == VolumeState::kFULL || 
      state_ == VolumeState::kFULL_AND_SERVING;
  }

  bool is_serving() const {
    return state_ == VolumeState::kFULL_AND_SERVING;
  }

  storage::Storage* volume_storage() const {
    return volume_storage_;
  }

  Bundle* bundle() const {
    return bundle_;
  }

  bool GetUUID(const std::string& name, base::UUID* id);

  void AddObserver(Observer* observer) {
    observers_.push_back(observer);
  }

  void RemoveObserver(Observer* observer) {
    for (auto it = observers_.begin(); it != observers_.end(); it++) {
      if (observer == *it) {
        observers_.erase(it);
        break;
      }
    }
  }

  // managed = persisted on DB
  bool is_managed() const override {
    return managed_;
  }

  void set_managed(bool managed) {
    managed_ = managed;
  }

  // associated source if any
  VolumeSource* source() const {
    return source_;
  }

  void set_source(VolumeSource* source) {
    source_ = source;
  }

  scoped_refptr<net::IOBufferWithSize> Serialize() const override;

  void CheckoutApp(const base::FilePath& to,
                   storage::CompletionCallback callback);

  void CheckoutEntry(const std::string& name,
                     const base::FilePath& to,
                     storage::CompletionCallback callback);

  void Shutdown(storage::CompletionCallback on_volume_shutdown);

private:
  //Volume();
  Volume(storage::Storage* volume_storage, Bundle* bundle, protocol::Volume volume_proto);
  
  void NotifyStateChanged(VolumeState old_state, VolumeState new_state) {
    for (auto it = observers_.begin(); it != observers_.end(); it++) {
      (*it)->OnStateChanged(old_state, new_state);
    }
  }

  storage::Storage* volume_storage_;

  Bundle* bundle_;

  std::vector<Observer*> observers_;

  base::UUID id_;

  base::UUID root_tree_;

  protocol::Volume volume_proto_;

  VolumeState state_;

  VolumeSource* source_;

  bool valid_;

  bool managed_;

  DISALLOW_COPY_AND_ASSIGN(Volume);
};
  
}

#endif