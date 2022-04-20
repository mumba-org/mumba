// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_STORE_PROPERTY_STORE_H_
#define SHILL_STORE_PROPERTY_STORE_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/callback.h>
#include <brillo/any.h>
#include <brillo/variant_dictionary.h>

#include "shill/store/accessor_interface.h"
#include "shill/store/key_value_store.h"

namespace shill {

class Error;

class PropertyStore {
 public:
  using PropertyChangeCallback =
      base::RepeatingCallback<void(const std::string&)>;
  PropertyStore();
  explicit PropertyStore(PropertyChangeCallback property_change_callback);
  PropertyStore(const PropertyStore&) = delete;
  PropertyStore& operator=(const PropertyStore&) = delete;

  ~PropertyStore();

  bool Contains(const std::string& property) const;

  // Setting properties using brillo::Any variant type.
  void SetAnyProperty(const std::string& name,
                      const brillo::Any& value,
                      Error* error);
  void SetProperties(const brillo::VariantDictionary& in, Error* error);

  // Retrieve all properties and store them in a brillo::VariantDictionary
  // (std::map<std::string, brillo::Any>).
  bool GetProperties(brillo::VariantDictionary* out, Error* error) const;

  // Methods to allow the getting of properties stored in the referenced
  // |store_| by name. Upon success, these methods return true and return the
  // property value in |value|. Upon failure, they return false and
  // leave |value| untouched.
  bool GetBoolProperty(const std::string& name,
                       bool* value,
                       Error* error) const;
  bool GetInt16Property(const std::string& name,
                        int16_t* value,
                        Error* error) const;
  bool GetInt32Property(const std::string& name,
                        int32_t* value,
                        Error* error) const;
  bool GetKeyValueStoreProperty(const std::string& name,
                                KeyValueStore* value,
                                Error* error) const;
  bool GetKeyValueStoresProperty(const std::string& name,
                                 KeyValueStores* value,
                                 Error* error) const;
  bool GetStringProperty(const std::string& name,
                         std::string* value,
                         Error* error) const;
  bool GetStringmapProperty(const std::string& name,
                            Stringmap* values,
                            Error* error) const;
  bool GetStringmapsProperty(const std::string& name,
                             Stringmaps* values,
                             Error* error) const;
  bool GetStringsProperty(const std::string& name,
                          Strings* values,
                          Error* error) const;
  bool GetUint8Property(const std::string& name,
                        uint8_t* value,
                        Error* error) const;
  bool GetByteArrayProperty(const std::string& name,
                            ByteArray* value,
                            Error* error) const;
  bool GetUint16Property(const std::string& name,
                         uint16_t* value,
                         Error* error) const;
  bool GetUint16sProperty(const std::string& name,
                          Uint16s* value,
                          Error* error) const;
  bool GetUint32Property(const std::string& name,
                         uint32_t* value,
                         Error* error) const;
  bool GetUint64Property(const std::string& name,
                         uint64_t* value,
                         Error* error) const;
  bool GetRpcIdentifierProperty(const std::string& name,
                                RpcIdentifier* value,
                                Error* error) const;

  // Methods to allow the setting, by name, of properties stored in this object.
  // The property names are declared in chromeos/dbus/service_constants.h,
  // so that they may be shared with libcros.
  // If the property is successfully changed, these methods leave |error|
  // untouched.
  // If the property is unchanged because it already has the desired value,
  // these methods leave |error| untouched.
  // If the property change fails, these methods update |error|. However,
  // updating |error| is skipped if |error| is NULL.
  void SetBoolProperty(const std::string& name, bool value, Error* error);

  void SetInt16Property(const std::string& name, int16_t value, Error* error);

  void SetInt32Property(const std::string& name, int32_t value, Error* error);

  void SetKeyValueStoreProperty(const std::string& name,
                                const KeyValueStore& value,
                                Error* error);

  void SetKeyValueStoresProperty(const std::string& name,
                                 const KeyValueStores& value,
                                 Error* error);

  void SetStringProperty(const std::string& name,
                         const std::string& value,
                         Error* error);

  void SetStringmapProperty(const std::string& name,
                            const std::map<std::string, std::string>& values,
                            Error* error);

  void SetStringmapsProperty(
      const std::string& name,
      const std::vector<std::map<std::string, std::string>>& values,
      Error* error);

  void SetStringsProperty(const std::string& name,
                          const std::vector<std::string>& values,
                          Error* error);

  void SetUint8Property(const std::string& name, uint8_t value, Error* error);

  void SetByteArrayProperty(const std::string& name,
                            const ByteArray& value,
                            Error* error);

  void SetUint16Property(const std::string& name, uint16_t value, Error* error);

  void SetUint16sProperty(const std::string& name,
                          const std::vector<uint16_t>& value,
                          Error* error);

  void SetUint32Property(const std::string& name, uint32_t value, Error* error);

  void SetUint64Property(const std::string& name, uint64_t value, Error* error);

  void SetRpcIdentifierProperty(const std::string& name,
                                const RpcIdentifier& value,
                                Error* error);

  // Clearing a property resets it to its "factory" value. This value
  // is generally the value that it (the property) had when it was
  // registered with PropertyStore.
  //
  // The exception to this rule is write-only derived properties. For
  // such properties, the property owner explicitly provides a
  // "factory" value at registration time. This is necessary because
  // PropertyStore can't read the current value at registration time.
  //
  // |name| is the key used to access the property. If the property
  // cannot be cleared, |error| is set, and the method returns false.
  // Otherwise, |error| is unchanged, and the method returns true.
  bool ClearProperty(const std::string& name, Error* error);

  // Methods for registering a property.
  //
  // It is permitted to re-register a property (in which case the old
  // binding is forgotten). However, the newly bound object must be of
  // the same type.
  //
  // Note that types do not encode read-write permission.  Hence, it
  // is possible to change permissions by rebinding a property to the
  // same object.
  //
  // (Corollary of the rebinding-to-same-type restriction: a
  // PropertyStore cannot hold two properties of the same name, but
  // differing types.)
  void RegisterBool(const std::string& name, bool* prop);
  void RegisterConstBool(const std::string& name, const bool* prop);
  void RegisterWriteOnlyBool(const std::string& name, bool* prop);
  void RegisterInt16(const std::string& name, int16_t* prop);
  void RegisterConstInt16(const std::string& name, const int16_t* prop);
  void RegisterWriteOnlyInt16(const std::string& name, int16_t* prop);
  void RegisterInt32(const std::string& name, int32_t* prop);
  void RegisterConstInt32(const std::string& name, const int32_t* prop);
  void RegisterWriteOnlyInt32(const std::string& name, int32_t* prop);
  void RegisterUint32(const std::string& name, uint32_t* prop);
  void RegisterConstUint32(const std::string& name, const uint32_t* prop);
  void RegisterUint64(const std::string& name, uint64_t* prop);
  void RegisterString(const std::string& name, std::string* prop);
  void RegisterConstString(const std::string& name, const std::string* prop);
  void RegisterWriteOnlyString(const std::string& name, std::string* prop);
  void RegisterStringmap(const std::string& name, Stringmap* prop);
  void RegisterConstStringmap(const std::string& name, const Stringmap* prop);
  void RegisterWriteOnlyStringmap(const std::string& name, Stringmap* prop);
  void RegisterStringmaps(const std::string& name, Stringmaps* prop);
  void RegisterConstStringmaps(const std::string& name, const Stringmaps* prop);
  void RegisterWriteOnlyStringmaps(const std::string& name, Stringmaps* prop);
  void RegisterStrings(const std::string& name, Strings* prop);
  void RegisterConstStrings(const std::string& name, const Strings* prop);
  void RegisterWriteOnlyStrings(const std::string& name, Strings* prop);
  void RegisterUint8(const std::string& name, uint8_t* prop);
  void RegisterConstUint8(const std::string& name, const uint8_t* prop);
  void RegisterWriteOnlyUint8(const std::string& name, uint8_t* prop);
  void RegisterUint16(const std::string& name, uint16_t* prop);
  void RegisterUint16s(const std::string& name, Uint16s* prop);
  void RegisterConstUint16(const std::string& name, const uint16_t* prop);
  void RegisterConstUint16s(const std::string& name, const Uint16s* prop);
  void RegisterWriteOnlyUint16(const std::string& name, uint16_t* prop);
  void RegisterByteArray(const std::string& name, ByteArray* prop);
  void RegisterConstByteArray(const std::string& name, const ByteArray* prop);
  void RegisterWriteOnlyByteArray(const std::string& name, ByteArray* prop);
  void RegisterKeyValueStore(const std::string& name, KeyValueStore* prop);
  void RegisterConstKeyValueStore(const std::string& name,
                                  const KeyValueStore* prop);
  void RegisterKeyValueStores(const std::string& name, KeyValueStores* prop);
  void RegisterConstKeyValueStores(const std::string& name,
                                   const KeyValueStores* prop);

  void RegisterDerivedBool(const std::string& name, BoolAccessor accessor);
  void RegisterDerivedInt32(const std::string& name, Int32Accessor accessor);
  void RegisterDerivedKeyValueStore(const std::string& name,
                                    KeyValueStoreAccessor accessor);
  void RegisterDerivedKeyValueStores(const std::string& name,
                                     KeyValueStoresAccessor accessor);
  void RegisterDerivedRpcIdentifier(const std::string& name,
                                    RpcIdentifierAccessor acc);
  void RegisterDerivedRpcIdentifiers(const std::string& name,
                                     RpcIdentifiersAccessor accessor);
  void RegisterDerivedString(const std::string& name, StringAccessor accessor);
  void RegisterDerivedStringmap(const std::string& name,
                                StringmapAccessor accessor);
  void RegisterDerivedStringmaps(const std::string& name,
                                 StringmapsAccessor accessor);
  void RegisterDerivedStrings(const std::string& name,
                              StringsAccessor accessor);
  void RegisterDerivedUint16(const std::string& name, Uint16Accessor accessor);
  void RegisterDerivedUint64(const std::string& name, Uint64Accessor accessor);
  void RegisterDerivedUint16s(const std::string& name,
                              Uint16sAccessor accessor);
  void RegisterDerivedByteArray(const std::string& name,
                                ByteArrayAccessor accessor);

 private:
  template <class V>
  bool GetProperty(const std::string& name,
                   V* value,
                   Error* error,
                   const AccessorMap<V>& collection,
                   const std::string& value_type_english) const;

  template <class V>
  bool SetProperty(const std::string& name,
                   const V& value,
                   Error* error,
                   AccessorMap<V>* collection,
                   const std::string& value_type_english);

  // These are std::maps instead of something cooler because the common
  // operation is iterating through them and returning all properties.
  std::map<std::string, BoolAccessor> bool_properties_;
  std::map<std::string, Int16Accessor> int16_properties_;
  std::map<std::string, Int32Accessor> int32_properties_;
  std::map<std::string, KeyValueStoreAccessor> key_value_store_properties_;
  std::map<std::string, KeyValueStoresAccessor> key_value_stores_properties_;
  std::map<std::string, RpcIdentifierAccessor> rpc_identifier_properties_;
  std::map<std::string, RpcIdentifiersAccessor> rpc_identifiers_properties_;
  std::map<std::string, StringAccessor> string_properties_;
  std::map<std::string, StringmapAccessor> stringmap_properties_;
  std::map<std::string, StringmapsAccessor> stringmaps_properties_;
  std::map<std::string, StringsAccessor> strings_properties_;
  std::map<std::string, Uint8Accessor> uint8_properties_;
  std::map<std::string, ByteArrayAccessor> bytearray_properties_;
  std::map<std::string, Uint16Accessor> uint16_properties_;
  std::map<std::string, Uint16sAccessor> uint16s_properties_;
  std::map<std::string, Uint32Accessor> uint32_properties_;
  std::map<std::string, Uint64Accessor> uint64_properties_;

  PropertyChangeCallback property_changed_callback_;
};

}  // namespace shill

#endif  // SHILL_STORE_PROPERTY_STORE_H_
