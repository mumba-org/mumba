// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/store/pkcs11_data_store.h"

#include <iterator>

#include <base/strings/string_util.h>
#include <chaps/isolate.h>
#include <chaps/token_manager_client.h>

namespace shill {

// An arbitrary application ID to identify PKCS #11 objects.
const char kApplicationID[] =
    "CrOS_shill_bee161e513a44bda9d4e64a09cd64f529b44008e";

// A helper class to scope a PKCS #11 session.
class ScopedSession {
 public:
  explicit ScopedSession(CK_SLOT_ID slot) {
    CK_RV rv = C_Initialize(nullptr);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
      // This may be normal in a test environment.
      LOG(INFO) << "PKCS #11 is not available. C_Initialize rv: " << rv;
      return;
    }
    CK_FLAGS flags = CKF_RW_SESSION | CKF_SERIAL_SESSION;
    rv = C_OpenSession(slot, flags, nullptr, nullptr, &handle_);
    if (rv != CKR_OK) {
      LOG(ERROR) << "Failed to open PKCS #11 session. C_OpenSession rv: " << rv;
      return;
    }
  }
  ScopedSession(const ScopedSession&) = delete;
  ScopedSession& operator=(const ScopedSession&) = delete;

  ~ScopedSession() {
    if (IsValid() && (C_CloseSession(handle_) != CKR_OK)) {
      LOG(WARNING) << "Failed to close PKCS #11 session.";
    }
    handle_ = CK_INVALID_HANDLE;
  }

  CK_SESSION_HANDLE handle() const { return handle_; }

  bool IsValid() const { return (handle_ != CK_INVALID_HANDLE); }

 private:
  CK_SESSION_HANDLE handle_ = CK_INVALID_HANDLE;
};

Pkcs11DataStore::Pkcs11DataStore() {}

Pkcs11DataStore::~Pkcs11DataStore() {}

bool Pkcs11DataStore::Read(CK_SLOT_ID slot,
                           const std::string& key_name,
                           std::string* key_data) {
  CHECK(key_data);
  ScopedSession session(slot);
  if (!session.IsValid()) {
    LOG(ERROR) << "Pkcs11DataStore: Failed to open token session with slot "
               << slot;
    return false;
  }
  CK_OBJECT_HANDLE key_handle = FindObject(session.handle(), key_name);
  if (key_handle == CK_INVALID_HANDLE) {
    LOG(WARNING) << "Pkcs11DataStore: Key does not exist: " << key_name;
    return false;
  }
  // First get the attribute with a NULL buffer which will give us the length.
  CK_ATTRIBUTE attribute = {CKA_VALUE, nullptr, 0};
  if (C_GetAttributeValue(session.handle(), key_handle, &attribute, 1) !=
      CKR_OK) {
    LOG(ERROR) << "Pkcs11DataStore: Failed to read key data: " << key_name;
    return false;
  }
  key_data->resize(attribute.ulValueLen);
  attribute.pValue = std::data(*key_data);
  if (C_GetAttributeValue(session.handle(), key_handle, &attribute, 1) !=
      CKR_OK) {
    LOG(ERROR) << "Pkcs11DataStore: Failed to read key data: " << key_name;
    return false;
  }
  return true;
}

bool Pkcs11DataStore::Write(CK_SLOT_ID slot,
                            const std::string& key_name,
                            const std::string& key_data) {
  // Delete any existing key with the same name.
  if (!Delete(slot, key_name)) {
    return false;
  }
  ScopedSession session(slot);
  if (!session.IsValid()) {
    LOG(ERROR) << "Pkcs11DataStore: Failed to open token session with slot "
               << slot;
    return false;
  }
  std::string mutable_key_name(key_name);
  std::string mutable_key_data(key_data);
  std::string mutable_application_id(kApplicationID);
  // Create a new data object for the key.
  CK_OBJECT_CLASS object_class = CKO_DATA;
  CK_BBOOL true_value = CK_TRUE;
  CK_BBOOL false_value = CK_FALSE;
  CK_ATTRIBUTE attributes[] = {
      {CKA_CLASS, &object_class, sizeof(object_class)},
      {CKA_LABEL, std::data(mutable_key_name), mutable_key_name.size()},
      {CKA_VALUE, std::data(mutable_key_data), mutable_key_data.size()},
      {CKA_APPLICATION, std::data(mutable_application_id),
       mutable_application_id.size()},
      {CKA_TOKEN, &true_value, sizeof(true_value)},
      {CKA_PRIVATE, &true_value, sizeof(true_value)},
      {CKA_MODIFIABLE, &false_value, sizeof(false_value)}};
  CK_OBJECT_HANDLE key_handle = CK_INVALID_HANDLE;
  if (C_CreateObject(session.handle(), attributes, std::size(attributes),
                     &key_handle) != CKR_OK) {
    LOG(ERROR) << "Pkcs11DataStore: Failed to write key data: " << key_name;
    return false;
  }
  return true;
}

bool Pkcs11DataStore::Delete(CK_SLOT_ID slot, const std::string& key_name) {
  ScopedSession session(slot);
  if (!session.IsValid()) {
    LOG(ERROR) << "Pkcs11DataStore: Failed to open token session with slot "
               << slot;
    return false;
  }
  CK_OBJECT_HANDLE key_handle = FindObject(session.handle(), key_name);
  if (key_handle != CK_INVALID_HANDLE) {
    if (C_DestroyObject(session.handle(), key_handle) != CKR_OK) {
      LOG(ERROR) << "Pkcs11DataStore: Failed to delete key data.";
      return false;
    }
  }
  return true;
}

bool Pkcs11DataStore::DeleteByPrefix(CK_SLOT_ID slot,
                                     const std::string& key_prefix) {
  ScopedSession session(slot);
  if (!session.IsValid()) {
    LOG(ERROR) << "Pkcs11DataStore: Failed to open token session with slot "
               << slot;
    return false;
  }
  EnumObjectsCallback callback =
      base::BindRepeating(&Pkcs11DataStore::DeleteIfMatchesPrefix,
                          base::Unretained(this), session.handle(), key_prefix);
  if (!EnumObjects(session.handle(), callback)) {
    LOG(ERROR) << "Pkcs11DataStore: Failed to delete key data.";
    return false;
  }
  return true;
}

CK_OBJECT_HANDLE Pkcs11DataStore::FindObject(CK_SESSION_HANDLE session_handle,
                                             const std::string& key_name) {
  // Assemble a search template.
  std::string mutable_key_name(key_name);
  std::string mutable_application_id(kApplicationID);
  CK_OBJECT_CLASS object_class = CKO_DATA;
  CK_BBOOL true_value = CK_TRUE;
  CK_BBOOL false_value = CK_FALSE;
  CK_ATTRIBUTE attributes[] = {
      {CKA_CLASS, &object_class, sizeof(object_class)},
      {CKA_LABEL, std::data(mutable_key_name), mutable_key_name.size()},
      {CKA_APPLICATION, std::data(mutable_application_id),
       mutable_application_id.size()},
      {CKA_TOKEN, &true_value, sizeof(true_value)},
      {CKA_PRIVATE, &true_value, sizeof(true_value)},
      {CKA_MODIFIABLE, &false_value, sizeof(false_value)}};
  CK_OBJECT_HANDLE key_handle = CK_INVALID_HANDLE;
  CK_ULONG count = 0;
  if ((C_FindObjectsInit(session_handle, attributes, std::size(attributes)) !=
       CKR_OK) ||
      (C_FindObjects(session_handle, &key_handle, 1, &count) != CKR_OK) ||
      (C_FindObjectsFinal(session_handle) != CKR_OK)) {
    LOG(ERROR) << "Key search failed: " << key_name;
    return CK_INVALID_HANDLE;
  }
  if (count == 1)
    return key_handle;
  return CK_INVALID_HANDLE;
}

bool Pkcs11DataStore::EnumObjects(
    CK_SESSION_HANDLE session_handle,
    const Pkcs11DataStore::EnumObjectsCallback& callback) {
  std::string mutable_application_id(kApplicationID);
  // Assemble a search template.
  CK_OBJECT_CLASS object_class = CKO_DATA;
  CK_BBOOL true_value = CK_TRUE;
  CK_BBOOL false_value = CK_FALSE;
  CK_ATTRIBUTE attributes[] = {
      {CKA_CLASS, &object_class, sizeof(object_class)},
      {CKA_APPLICATION, std::data(mutable_application_id),
       mutable_application_id.size()},
      {CKA_TOKEN, &true_value, sizeof(true_value)},
      {CKA_PRIVATE, &true_value, sizeof(true_value)},
      {CKA_MODIFIABLE, &false_value, sizeof(false_value)}};
  const CK_ULONG kMaxHandles = 100;  // Arbitrary.
  CK_OBJECT_HANDLE handles[kMaxHandles];
  CK_ULONG count = 0;
  if ((C_FindObjectsInit(session_handle, attributes, std::size(attributes)) !=
       CKR_OK) ||
      (C_FindObjects(session_handle, handles, kMaxHandles, &count) != CKR_OK)) {
    LOG(ERROR) << "Key search failed.";
    return false;
  }
  bool success = true;
  while (count > 0) {
    for (CK_ULONG i = 0; i < count; ++i) {
      std::string key_name;
      if (!GetKeyName(session_handle, handles[i], &key_name)) {
        LOG(WARNING) << "Found key object but failed to get name.";
        continue;
      }
      if (!callback.Run(key_name, handles[i])) {
        success = false;
        break;
      }
    }
    if (C_FindObjects(session_handle, handles, kMaxHandles, &count) != CKR_OK) {
      LOG(ERROR) << "Key search continuation failed.";
      success = false;
      break;
    }
  }
  if (C_FindObjectsFinal(session_handle) != CKR_OK) {
    LOG(WARNING) << "Failed to finalize key search.";
  }
  return success;
}

bool Pkcs11DataStore::GetKeyName(CK_SESSION_HANDLE session_handle,
                                 CK_OBJECT_HANDLE object_handle,
                                 std::string* key_name) {
  CHECK(key_name);
  CK_ATTRIBUTE attribute = {CKA_LABEL, nullptr, 0};
  if (C_GetAttributeValue(session_handle, object_handle, &attribute, 1) !=
      CKR_OK) {
    LOG(ERROR) << "C_GetAttributeValue(CKA_LABEL) [length] failed.";
    return false;
  }
  key_name->resize(attribute.ulValueLen);
  attribute.pValue = std::data(*key_name);
  if (C_GetAttributeValue(session_handle, object_handle, &attribute, 1) !=
      CKR_OK) {
    LOG(ERROR) << "C_GetAttributeValue(CKA_LABEL) failed.";
    return false;
  }
  return true;
}

bool Pkcs11DataStore::DeleteIfMatchesPrefix(CK_SESSION_HANDLE session_handle,
                                            const std::string& key_prefix,
                                            const std::string& key_name,
                                            CK_OBJECT_HANDLE object_handle) {
  if (base::StartsWith(key_name, key_prefix, base::CompareCase::SENSITIVE)) {
    if (C_DestroyObject(session_handle, object_handle) != CKR_OK) {
      LOG(ERROR) << "C_DestroyObject failed.";
      return false;
    }
  }
  return true;
}

bool Pkcs11DataStore::GetUserSlot(const std::string& user_hash,
                                  CK_SLOT_ID_PTR slot) {
  const char kChapsSystemToken[] = "/var/lib/chaps";
  const char kChapsDaemonStore[] = "/run/daemon-store/chaps";
  base::FilePath token_path =
      user_hash.empty() ? base::FilePath(kChapsSystemToken)
                        : base::FilePath(kChapsDaemonStore).Append(user_hash);
  CK_RV rv;
  rv = C_Initialize(nullptr);
  if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
    LOG(WARNING) << __func__ << ": C_Initialize failed. rv: " << rv;
    return false;
  }
  CK_ULONG num_slots = 0;
  rv = C_GetSlotList(CK_TRUE, nullptr, &num_slots);
  if (rv != CKR_OK) {
    LOG(WARNING) << __func__ << ": C_GetSlotList(nullptr) failed. rv: " << rv;
    return false;
  }
  std::unique_ptr<CK_SLOT_ID[]> slot_list(new CK_SLOT_ID[num_slots]);
  rv = C_GetSlotList(CK_TRUE, slot_list.get(), &num_slots);
  if (rv != CKR_OK) {
    LOG(WARNING) << __func__ << ": C_GetSlotList failed. rv: " << rv;
    return false;
  }
  chaps::TokenManagerClient token_manager;
  // Look through all slots for |token_path|.
  for (CK_ULONG i = 0; i < num_slots; ++i) {
    base::FilePath slot_path;
    if (token_manager.GetTokenPath(
            chaps::IsolateCredentialManager::GetDefaultIsolateCredential(),
            slot_list[i], &slot_path) &&
        (token_path == slot_path)) {
      *slot = slot_list[i];
      return true;
    }
  }
  LOG(WARNING) << __func__ << ": Path not found.";
  return false;
}

}  // namespace shill
