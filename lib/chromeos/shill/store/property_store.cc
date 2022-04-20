// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/store/property_store.h"

#include <map>
#include <string>
#include <utility>
#include <vector>

//#include <base/check.h>
#include <base/containers/contains.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <dbus/object_path.h>

#include "shill/error.h"
#include "shill/logging.h"
#include "shill/store/property_accessor.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kProperty;
static std::string ObjectID(const PropertyStore* p) {
  return "(property_store)";
}
}  // namespace Logging

namespace {
// Helper function encapsulating the property access pattern used for
// implementing PropertyStore::GetProperties()
template <class V>
void CopyReadableProperties(
    brillo::VariantDictionary* out,
    const std::map<std::string, std::unique_ptr<AccessorInterface<V>>>&
        properties) {
  for (const auto& [key, value] : properties) {
    Error error;
    V v = value.get()->Get(&error);
    if (error.IsSuccess()) {
      (*out)[key] = brillo::Any(v);
    }
  }
}
}  // namespace

PropertyStore::PropertyStore() = default;

PropertyStore::PropertyStore(PropertyChangeCallback on_property_changed)
    : property_changed_callback_(on_property_changed) {}

PropertyStore::~PropertyStore() = default;

bool PropertyStore::Contains(const std::string& prop) const {
  return (base::Contains(bool_properties_, prop) ||
          base::Contains(int16_properties_, prop) ||
          base::Contains(int32_properties_, prop) ||
          base::Contains(key_value_store_properties_, prop) ||
          base::Contains(key_value_stores_properties_, prop) ||
          base::Contains(string_properties_, prop) ||
          base::Contains(stringmap_properties_, prop) ||
          base::Contains(stringmaps_properties_, prop) ||
          base::Contains(strings_properties_, prop) ||
          base::Contains(uint8_properties_, prop) ||
          base::Contains(bytearray_properties_, prop) ||
          base::Contains(uint16_properties_, prop) ||
          base::Contains(uint16s_properties_, prop) ||
          base::Contains(uint32_properties_, prop) ||
          base::Contains(uint64_properties_, prop) ||
          base::Contains(rpc_identifier_properties_, prop) ||
          base::Contains(rpc_identifiers_properties_, prop));
}

void PropertyStore::SetAnyProperty(const std::string& name,
                                   const brillo::Any& value,
                                   Error* error) {
  if (value.IsTypeCompatible<bool>()) {
    SetBoolProperty(name, value.Get<bool>(), error);
  } else if (value.IsTypeCompatible<uint8_t>()) {
    SetUint8Property(name, value.Get<uint8_t>(), error);
  } else if (value.IsTypeCompatible<int16_t>()) {
    SetInt16Property(name, value.Get<int16_t>(), error);
  } else if (value.IsTypeCompatible<int32_t>()) {
    SetInt32Property(name, value.Get<int32_t>(), error);
  } else if (value.IsTypeCompatible<dbus::ObjectPath>()) {
    SetRpcIdentifierProperty(name, value.Get<dbus::ObjectPath>(), error);
  } else if (value.IsTypeCompatible<std::string>()) {
    SetStringProperty(name, value.Get<std::string>(), error);
  } else if (value.IsTypeCompatible<Stringmap>()) {
    SetStringmapProperty(name, value.Get<Stringmap>(), error);
  } else if (value.IsTypeCompatible<Stringmaps>()) {
    SLOG(nullptr, 1) << " can't yet handle setting type "
                     << value.GetUndecoratedTypeName();
    error->Populate(Error::kInternalError);
  } else if (value.IsTypeCompatible<Strings>()) {
    SetStringsProperty(name, value.Get<Strings>(), error);
  } else if (value.IsTypeCompatible<ByteArray>()) {
    SetByteArrayProperty(name, value.Get<ByteArray>(), error);
  } else if (value.IsTypeCompatible<uint16_t>()) {
    SetUint16Property(name, value.Get<uint16_t>(), error);
  } else if (value.IsTypeCompatible<Uint16s>()) {
    SetUint16sProperty(name, value.Get<Uint16s>(), error);
  } else if (value.IsTypeCompatible<uint32_t>()) {
    SetUint32Property(name, value.Get<uint32_t>(), error);
  } else if (value.IsTypeCompatible<uint64_t>()) {
    SetUint64Property(name, value.Get<uint64_t>(), error);
  } else if (value.IsTypeCompatible<brillo::VariantDictionary>()) {
    KeyValueStore store = KeyValueStore::ConvertFromVariantDictionary(
        value.Get<brillo::VariantDictionary>());
    SetKeyValueStoreProperty(name, store, error);
  } else if (value.IsTypeCompatible<std::vector<brillo::VariantDictionary>>()) {
    KeyValueStores dicts;
    for (const auto& d : value.Get<std::vector<brillo::VariantDictionary>>()) {
      KeyValueStore store = KeyValueStore::ConvertFromVariantDictionary(d);
      dicts.push_back(store);
    }
    SetKeyValueStoresProperty(name, dicts, error);
  } else {
    NOTREACHED() << " unknown type: " << value.GetUndecoratedTypeName();
    error->Populate(Error::kInternalError);
  }
}

void PropertyStore::SetProperties(const brillo::VariantDictionary& in,
                                  Error* error) {
  for (const auto& kv : in) {
    SetAnyProperty(kv.first, kv.second, error);
  }
}

bool PropertyStore::GetProperties(brillo::VariantDictionary* out,
                                  Error* ignored) const {
  CopyReadableProperties(out, bool_properties_);
  CopyReadableProperties(out, int16_properties_);
  CopyReadableProperties(out, int32_properties_);
  CopyReadableProperties(out, rpc_identifier_properties_);
  CopyReadableProperties(out, rpc_identifiers_properties_);
  CopyReadableProperties(out, string_properties_);
  CopyReadableProperties(out, strings_properties_);
  CopyReadableProperties(out, stringmap_properties_);
  CopyReadableProperties(out, stringmaps_properties_);
  CopyReadableProperties(out, uint8_properties_);
  CopyReadableProperties(out, bytearray_properties_);
  CopyReadableProperties(out, uint16_properties_);
  CopyReadableProperties(out, uint16s_properties_);
  CopyReadableProperties(out, uint32_properties_);
  CopyReadableProperties(out, uint64_properties_);
  for (const auto& [key, value] : key_value_store_properties_) {
    Error error;
    auto v =
        KeyValueStore::ConvertToVariantDictionary(value.get()->Get(&error));
    if (error.IsSuccess()) {
      (*out)[key] = brillo::Any(v);
    }
  }
  for (const auto& [key, value] : key_value_stores_properties_) {
    Error error;
    std::vector<brillo::VariantDictionary> dicts;
    auto stores = value.get()->Get(&error);
    if (error.IsSuccess()) {
      for (const auto& store : stores) {
        dicts.push_back(KeyValueStore::ConvertToVariantDictionary(store));
      }
      (*out)[key] = dicts;
    }
  }
  return true;
}

bool PropertyStore::GetBoolProperty(const std::string& name,
                                    bool* value,
                                    Error* error) const {
  return GetProperty(name, value, error, bool_properties_, "a bool");
}

bool PropertyStore::GetInt16Property(const std::string& name,
                                     int16_t* value,
                                     Error* error) const {
  return GetProperty(name, value, error, int16_properties_, "an int16_t");
}

bool PropertyStore::GetInt32Property(const std::string& name,
                                     int32_t* value,
                                     Error* error) const {
  return GetProperty(name, value, error, int32_properties_, "an int32_t");
}

bool PropertyStore::GetKeyValueStoreProperty(const std::string& name,
                                             KeyValueStore* value,
                                             Error* error) const {
  return GetProperty(name, value, error, key_value_store_properties_,
                     "a key value store");
}

bool PropertyStore::GetKeyValueStoresProperty(const std::string& name,
                                              KeyValueStores* value,
                                              Error* error) const {
  return GetProperty(name, value, error, key_value_stores_properties_,
                     "a key value stores");
}

bool PropertyStore::GetRpcIdentifierProperty(const std::string& name,
                                             RpcIdentifier* value,
                                             Error* error) const {
  return GetProperty(name, value, error, rpc_identifier_properties_,
                     "an rpc_identifier");
}

bool PropertyStore::GetStringProperty(const std::string& name,
                                      std::string* value,
                                      Error* error) const {
  return GetProperty(name, value, error, string_properties_, "a string");
}

bool PropertyStore::GetStringmapProperty(const std::string& name,
                                         Stringmap* values,
                                         Error* error) const {
  return GetProperty(name, values, error, stringmap_properties_,
                     "a string map");
}

bool PropertyStore::GetStringmapsProperty(const std::string& name,
                                          Stringmaps* values,
                                          Error* error) const {
  return GetProperty(name, values, error, stringmaps_properties_,
                     "a string map list");
}

bool PropertyStore::GetStringsProperty(const std::string& name,
                                       Strings* values,
                                       Error* error) const {
  return GetProperty(name, values, error, strings_properties_, "a string list");
}

bool PropertyStore::GetUint8Property(const std::string& name,
                                     uint8_t* value,
                                     Error* error) const {
  return GetProperty(name, value, error, uint8_properties_, "a uint8_t");
}

bool PropertyStore::GetByteArrayProperty(const std::string& name,
                                         ByteArray* value,
                                         Error* error) const {
  return GetProperty(name, value, error, bytearray_properties_, "a byte array");
}

bool PropertyStore::GetUint16Property(const std::string& name,
                                      uint16_t* value,
                                      Error* error) const {
  return GetProperty(name, value, error, uint16_properties_, "a uint16_t");
}

bool PropertyStore::GetUint16sProperty(const std::string& name,
                                       Uint16s* value,
                                       Error* error) const {
  return GetProperty(name, value, error, uint16s_properties_,
                     "a uint16_t list");
}

bool PropertyStore::GetUint32Property(const std::string& name,
                                      uint32_t* value,
                                      Error* error) const {
  return GetProperty(name, value, error, uint32_properties_, "a uint32_t");
}

bool PropertyStore::GetUint64Property(const std::string& name,
                                      uint64_t* value,
                                      Error* error) const {
  return GetProperty(name, value, error, uint64_properties_, "a uint64_t");
}

void PropertyStore::SetBoolProperty(const std::string& name,
                                    bool value,
                                    Error* error) {
  SetProperty(name, value, error, &bool_properties_, "a bool");
}

void PropertyStore::SetInt16Property(const std::string& name,
                                     int16_t value,
                                     Error* error) {
  SetProperty(name, value, error, &int16_properties_, "an int16_t");
}

void PropertyStore::SetInt32Property(const std::string& name,
                                     int32_t value,
                                     Error* error) {
  SetProperty(name, value, error, &int32_properties_, "an int32_t.");
}

void PropertyStore::SetKeyValueStoreProperty(const std::string& name,
                                             const KeyValueStore& value,
                                             Error* error) {
  SetProperty(name, value, error, &key_value_store_properties_,
              "a key value store");
}

void PropertyStore::SetKeyValueStoresProperty(const std::string& name,
                                              const KeyValueStores& value,
                                              Error* error) {
  SetProperty(name, value, error, &key_value_stores_properties_,
              "a key value stores");
}

void PropertyStore::SetStringProperty(const std::string& name,
                                      const std::string& value,
                                      Error* error) {
  SetProperty(name, value, error, &string_properties_, "a string");
}

void PropertyStore::SetStringmapProperty(
    const std::string& name,
    const std::map<std::string, std::string>& values,
    Error* error) {
  SetProperty(name, values, error, &stringmap_properties_, "a string map");
}

void PropertyStore::SetStringmapsProperty(
    const std::string& name,
    const std::vector<std::map<std::string, std::string>>& values,
    Error* error) {
  SetProperty(name, values, error, &stringmaps_properties_, "a stringmaps");
}

void PropertyStore::SetStringsProperty(const std::string& name,
                                       const std::vector<std::string>& values,
                                       Error* error) {
  SetProperty(name, values, error, &strings_properties_, "a string list");
}

void PropertyStore::SetUint8Property(const std::string& name,
                                     uint8_t value,
                                     Error* error) {
  SetProperty(name, value, error, &uint8_properties_, "a uint8_t");
}

void PropertyStore::SetByteArrayProperty(const std::string& name,
                                         const ByteArray& value,
                                         Error* error) {
  SetProperty(name, value, error, &bytearray_properties_, "a byte array");
}

void PropertyStore::SetUint16Property(const std::string& name,
                                      uint16_t value,
                                      Error* error) {
  SetProperty(name, value, error, &uint16_properties_, "a uint16_t");
}

void PropertyStore::SetUint16sProperty(const std::string& name,
                                       const std::vector<uint16_t>& value,
                                       Error* error) {
  SetProperty(name, value, error, &uint16s_properties_, "a uint16_t list");
}

void PropertyStore::SetUint32Property(const std::string& name,
                                      uint32_t value,
                                      Error* error) {
  SetProperty(name, value, error, &uint32_properties_, "a uint32_t");
}

void PropertyStore::SetUint64Property(const std::string& name,
                                      uint64_t value,
                                      Error* error) {
  SetProperty(name, value, error, &uint64_properties_, "a uint64_t");
}

void PropertyStore::SetRpcIdentifierProperty(const std::string& name,
                                             const RpcIdentifier& value,
                                             Error* error) {
  SetProperty(name, value, error, &rpc_identifier_properties_,
              "an rpc_identifier");
}

bool PropertyStore::ClearProperty(const std::string& name, Error* error) {
  SLOG(this, 2) << "Clearing " << name << ".";

  if (base::Contains(bool_properties_, name)) {
    bool_properties_[name]->Clear(error);
  } else if (base::Contains(int16_properties_, name)) {
    int16_properties_[name]->Clear(error);
  } else if (base::Contains(int32_properties_, name)) {
    int32_properties_[name]->Clear(error);
  } else if (base::Contains(key_value_store_properties_, name)) {
    key_value_store_properties_[name]->Clear(error);
  } else if (base::Contains(key_value_stores_properties_, name)) {
    key_value_stores_properties_[name]->Clear(error);
  } else if (base::Contains(string_properties_, name)) {
    string_properties_[name]->Clear(error);
  } else if (base::Contains(stringmap_properties_, name)) {
    stringmap_properties_[name]->Clear(error);
  } else if (base::Contains(stringmaps_properties_, name)) {
    stringmaps_properties_[name]->Clear(error);
  } else if (base::Contains(strings_properties_, name)) {
    strings_properties_[name]->Clear(error);
  } else if (base::Contains(uint8_properties_, name)) {
    uint8_properties_[name]->Clear(error);
  } else if (base::Contains(uint16_properties_, name)) {
    uint16_properties_[name]->Clear(error);
  } else if (base::Contains(uint16s_properties_, name)) {
    uint16s_properties_[name]->Clear(error);
  } else if (base::Contains(uint32_properties_, name)) {
    uint32_properties_[name]->Clear(error);
  } else if (base::Contains(uint64_properties_, name)) {
    uint64_properties_[name]->Clear(error);
  } else if (base::Contains(rpc_identifier_properties_, name)) {
    rpc_identifier_properties_[name]->Clear(error);
  } else if (base::Contains(rpc_identifiers_properties_, name)) {
    rpc_identifiers_properties_[name]->Clear(error);
  } else {
    error->Populate(Error::kInvalidProperty,
                    "Property " + name + " does not exist.");
  }
  if (error->IsSuccess()) {
    if (!property_changed_callback_.is_null()) {
      property_changed_callback_.Run(name);
    }
  }
  return error->IsSuccess();
}

void PropertyStore::RegisterBool(const std::string& name, bool* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  bool_properties_[name].reset(new PropertyAccessor<bool>(prop));
}

void PropertyStore::RegisterConstBool(const std::string& name,
                                      const bool* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  bool_properties_[name].reset(new ConstPropertyAccessor<bool>(prop));
}

void PropertyStore::RegisterWriteOnlyBool(const std::string& name, bool* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  bool_properties_[name].reset(new WriteOnlyPropertyAccessor<bool>(prop));
}

void PropertyStore::RegisterInt16(const std::string& name, int16_t* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  int16_properties_[name].reset(new PropertyAccessor<int16_t>(prop));
}

void PropertyStore::RegisterConstInt16(const std::string& name,
                                       const int16_t* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  int16_properties_[name].reset(new ConstPropertyAccessor<int16_t>(prop));
}

void PropertyStore::RegisterWriteOnlyInt16(const std::string& name,
                                           int16_t* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  int16_properties_[name].reset(new WriteOnlyPropertyAccessor<int16_t>(prop));
}
void PropertyStore::RegisterInt32(const std::string& name, int32_t* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  int32_properties_[name].reset(new PropertyAccessor<int32_t>(prop));
}

void PropertyStore::RegisterConstInt32(const std::string& name,
                                       const int32_t* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  int32_properties_[name].reset(new ConstPropertyAccessor<int32_t>(prop));
}

void PropertyStore::RegisterWriteOnlyInt32(const std::string& name,
                                           int32_t* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  int32_properties_[name].reset(new WriteOnlyPropertyAccessor<int32_t>(prop));
}

void PropertyStore::RegisterUint64(const std::string& name, uint64_t* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  uint64_properties_[name].reset(new PropertyAccessor<uint64_t>(prop));
}

void PropertyStore::RegisterString(const std::string& name, std::string* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  string_properties_[name].reset(new PropertyAccessor<std::string>(prop));
}

void PropertyStore::RegisterConstString(const std::string& name,
                                        const std::string* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  string_properties_[name].reset(new ConstPropertyAccessor<std::string>(prop));
}

void PropertyStore::RegisterWriteOnlyString(const std::string& name,
                                            std::string* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  string_properties_[name].reset(
      new WriteOnlyPropertyAccessor<std::string>(prop));
}

void PropertyStore::RegisterStringmap(const std::string& name,
                                      Stringmap* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  stringmap_properties_[name].reset(new PropertyAccessor<Stringmap>(prop));
}

void PropertyStore::RegisterConstStringmap(const std::string& name,
                                           const Stringmap* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  stringmap_properties_[name].reset(new ConstPropertyAccessor<Stringmap>(prop));
}

void PropertyStore::RegisterWriteOnlyStringmap(const std::string& name,
                                               Stringmap* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  stringmap_properties_[name].reset(
      new WriteOnlyPropertyAccessor<Stringmap>(prop));
}

void PropertyStore::RegisterStringmaps(const std::string& name,
                                       Stringmaps* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  stringmaps_properties_[name].reset(new PropertyAccessor<Stringmaps>(prop));
}

void PropertyStore::RegisterConstStringmaps(const std::string& name,
                                            const Stringmaps* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  stringmaps_properties_[name].reset(
      new ConstPropertyAccessor<Stringmaps>(prop));
}

void PropertyStore::RegisterWriteOnlyStringmaps(const std::string& name,
                                                Stringmaps* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  stringmaps_properties_[name].reset(
      new WriteOnlyPropertyAccessor<Stringmaps>(prop));
}

void PropertyStore::RegisterStrings(const std::string& name, Strings* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  strings_properties_[name].reset(new PropertyAccessor<Strings>(prop));
}

void PropertyStore::RegisterConstStrings(const std::string& name,
                                         const Strings* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  strings_properties_[name].reset(new ConstPropertyAccessor<Strings>(prop));
}

void PropertyStore::RegisterWriteOnlyStrings(const std::string& name,
                                             Strings* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  strings_properties_[name].reset(new WriteOnlyPropertyAccessor<Strings>(prop));
}

void PropertyStore::RegisterUint8(const std::string& name, uint8_t* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  uint8_properties_[name].reset(new PropertyAccessor<uint8_t>(prop));
}

void PropertyStore::RegisterConstUint8(const std::string& name,
                                       const uint8_t* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  uint8_properties_[name].reset(new ConstPropertyAccessor<uint8_t>(prop));
}

void PropertyStore::RegisterWriteOnlyUint8(const std::string& name,
                                           uint8_t* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  uint8_properties_[name].reset(new WriteOnlyPropertyAccessor<uint8_t>(prop));
}

void PropertyStore::RegisterByteArray(const std::string& name,
                                      ByteArray* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  bytearray_properties_[name].reset(new PropertyAccessor<ByteArray>(prop));
}

void PropertyStore::RegisterConstByteArray(const std::string& name,
                                           const ByteArray* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  bytearray_properties_[name].reset(new ConstPropertyAccessor<ByteArray>(prop));
}

void PropertyStore::RegisterWriteOnlyByteArray(const std::string& name,
                                               ByteArray* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  bytearray_properties_[name].reset(
      new WriteOnlyPropertyAccessor<ByteArray>(prop));
}

void PropertyStore::RegisterKeyValueStore(const std::string& name,
                                          KeyValueStore* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  key_value_store_properties_[name].reset(
      new PropertyAccessor<KeyValueStore>(prop));
}

void PropertyStore::RegisterConstKeyValueStore(const std::string& name,
                                               const KeyValueStore* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  key_value_store_properties_[name].reset(
      new ConstPropertyAccessor<KeyValueStore>(prop));
}

void PropertyStore::RegisterKeyValueStores(const std::string& name,
                                           KeyValueStores* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  key_value_stores_properties_[name].reset(
      new PropertyAccessor<KeyValueStores>(prop));
}

void PropertyStore::RegisterConstKeyValueStores(const std::string& name,
                                                const KeyValueStores* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  key_value_stores_properties_[name].reset(
      new ConstPropertyAccessor<KeyValueStores>(prop));
}

void PropertyStore::RegisterUint16(const std::string& name, uint16_t* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  uint16_properties_[name].reset(new PropertyAccessor<uint16_t>(prop));
}

void PropertyStore::RegisterUint16s(const std::string& name, Uint16s* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  uint16s_properties_[name].reset(new PropertyAccessor<Uint16s>(prop));
}

void PropertyStore::RegisterUint32(const std::string& name, uint32_t* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  uint32_properties_[name].reset(new PropertyAccessor<uint32_t>(prop));
}

void PropertyStore::RegisterConstUint32(const std::string& name,
                                        const uint32_t* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  uint32_properties_[name].reset(new ConstPropertyAccessor<uint32_t>(prop));
}

void PropertyStore::RegisterConstUint16(const std::string& name,
                                        const uint16_t* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  uint16_properties_[name].reset(new ConstPropertyAccessor<uint16_t>(prop));
}

void PropertyStore::RegisterConstUint16s(const std::string& name,
                                         const Uint16s* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  uint16s_properties_[name].reset(new ConstPropertyAccessor<Uint16s>(prop));
}

void PropertyStore::RegisterWriteOnlyUint16(const std::string& name,
                                            uint16_t* prop) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  uint16_properties_[name].reset(new WriteOnlyPropertyAccessor<uint16_t>(prop));
}

void PropertyStore::RegisterDerivedBool(const std::string& name,
                                        BoolAccessor accessor) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  bool_properties_[name] = std::move(accessor);
}

void PropertyStore::RegisterDerivedInt32(const std::string& name,
                                         Int32Accessor accessor) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  int32_properties_[name] = std::move(accessor);
}

void PropertyStore::RegisterDerivedKeyValueStore(
    const std::string& name, KeyValueStoreAccessor accessor) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  key_value_store_properties_[name] = std::move(accessor);
}

void PropertyStore::RegisterDerivedKeyValueStores(
    const std::string& name, KeyValueStoresAccessor accessor) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  key_value_stores_properties_[name] = std::move(accessor);
}

void PropertyStore::RegisterDerivedRpcIdentifier(
    const std::string& name, RpcIdentifierAccessor accessor) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  rpc_identifier_properties_[name] = std::move(accessor);
}

void PropertyStore::RegisterDerivedRpcIdentifiers(
    const std::string& name, RpcIdentifiersAccessor accessor) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  rpc_identifiers_properties_[name] = std::move(accessor);
}

void PropertyStore::RegisterDerivedString(const std::string& name,
                                          StringAccessor accessor) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  string_properties_[name] = std::move(accessor);
}

void PropertyStore::RegisterDerivedStrings(const std::string& name,
                                           StringsAccessor accessor) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  strings_properties_[name] = std::move(accessor);
}

void PropertyStore::RegisterDerivedStringmap(const std::string& name,
                                             StringmapAccessor accessor) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  stringmap_properties_[name] = std::move(accessor);
}

void PropertyStore::RegisterDerivedStringmaps(const std::string& name,
                                              StringmapsAccessor accessor) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  stringmaps_properties_[name] = std::move(accessor);
}

void PropertyStore::RegisterDerivedUint16(const std::string& name,
                                          Uint16Accessor accessor) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  uint16_properties_[name] = std::move(accessor);
}

void PropertyStore::RegisterDerivedUint64(const std::string& name,
                                          Uint64Accessor accessor) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  uint64_properties_[name] = std::move(accessor);
}

void PropertyStore::RegisterDerivedUint16s(const std::string& name,
                                           Uint16sAccessor accessor) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  uint16s_properties_[name] = std::move(accessor);
}

void PropertyStore::RegisterDerivedByteArray(const std::string& name,
                                             ByteArrayAccessor accessor) {
  DCHECK(!Contains(name)) << "(Already registered " << name << ")";
  bytearray_properties_[name] = std::move(accessor);
}

// private methods

template <class V>
bool PropertyStore::GetProperty(const std::string& name,
                                V* value,
                                Error* error,
                                const AccessorMap<V>& collection,
                                const std::string& value_type_english) const {
  SLOG(this, 2) << "Getting " << name << " as " << value_type_english << ".";
  auto it = collection.find(name);
  if (it != collection.end()) {
    V val = it->second->Get(error);
    if (error->IsSuccess()) {
      *value = val;
    }
  } else {
    if (Contains(name)) {
      error->Populate(
          Error::kInvalidArguments,
          "Property " + name + " is not " + value_type_english + ".");
    } else {
      error->Populate(Error::kInvalidProperty,
                      "Property " + name + " does not exist.");
    }
  }
  return error->IsSuccess();
}

template <class V>
bool PropertyStore::SetProperty(const std::string& name,
                                const V& value,
                                Error* error,
                                AccessorMap<V>* collection,
                                const std::string& value_type_english) {
  bool ret = false;
  SLOG(this, 2) << "Setting " << name << " as " << value_type_english << ".";
  if (base::Contains(*collection, name)) {
    ret = (*collection)[name]->Set(value, error);
    if (ret) {
      if (!property_changed_callback_.is_null()) {
        property_changed_callback_.Run(name);
      }
    }
  } else {
    if (Contains(name)) {
      error->Populate(
          Error::kInvalidArguments,
          "Property " + name + " is not " + value_type_english + ".");
    } else {
      error->Populate(Error::kInvalidProperty,
                      "Property " + name + " does not exist.");
    }
  }
  return ret;
}

}  // namespace shill
