// Copyright 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROMEOS_DBUS_BINDINGS_DBUS_SIGNATURE_H_
#define CHROMEOS_DBUS_BINDINGS_DBUS_SIGNATURE_H_

#include <memory>
#include <string>
#include <vector>

#include <base/macros.h>
#include "chromeos-dbus-bindings/interface.h"

namespace chromeos_dbus_bindings {

class DBusType {
 public:
  enum class Direction {
    kExtract,
    kAppend,
  };

  enum class Receiver {
    kAdaptor,
    kProxy,
  };
  virtual ~DBusType() = default;

  // Some types might not be allowed in properties because libchrome bindings
  // don't support them, or they don't make any sense as properties. One
  // example would be file descriptors.
  virtual bool IsValidPropertyType() const = 0;

  // Methods for getting the C++ type corresponding to a D-Bus type.
  // If you are reading the argument from a message, use kExtract; otherwise,
  // use kAppend.
  virtual std::string GetBaseType(Direction direction) const = 0;

  // Use these if possible, they will give you e.g. the correct reffiness.
  // The |receiver| should be kAdaptor if you are generating an adaptor, and
  // kProxy if you are generating a proxy.
  virtual std::string GetInArgType(Receiver receiver) const = 0;
  std::string GetOutArgType(Receiver receiver) const;

  // CallbackArg types are a bit special because they are out-arguments but
  // the D-Bus bindings call a callback with them, so they have the same
  // reffiness as in-arguments.
  virtual std::string GetCallbackArgType() const = 0;
};

class DBusSignature {
 public:
  DBusSignature();
  DBusSignature(const DBusSignature&) = delete;
  DBusSignature& operator=(const DBusSignature&) = delete;

  virtual ~DBusSignature() = default;

  // Returns a DBusType corresponding to the D-Bus signature given in
  // |signature|. If the signature fails to parse, returns nullptr.
  std::unique_ptr<DBusType> Parse(const std::string& signature);

 private:
  // Returns an intermediate-representation type for the next D-Bus signature
  // in the string at |signature|, as well as the next position within the
  // string that parsing should continue |next|. Returns nullptr on failure.
  std::unique_ptr<DBusType> GetTypenameForSignature(
      std::string::const_iterator signature,
      std::string::const_iterator end,
      std::string::const_iterator* next);

  // Parses multiple types out of a D-Bus signature until it encounters an
  // |end_char| and places them in |children|. Returns true on success.
  bool ParseChildTypes(std::string::const_iterator signature,
                       std::string::const_iterator end,
                       std::string::value_type end_char,
                       std::string::const_iterator* next,
                       std::vector<std::unique_ptr<DBusType>>* children);

  // Utility task for GetTypenameForSignature() which handles array objects
  // and decodes them into a map or vector depending on the encoded sub-elements
  // in the array. The arguments and return values are the same
  // as GetTypenameForSignature().
  std::unique_ptr<DBusType> GetArrayTypenameForSignature(
      std::string::const_iterator signature,
      std::string::const_iterator end,
      std::string::const_iterator* next);

  // Utility task for GetArrayTypenameForSignature() which handles dict objects.
  std::unique_ptr<DBusType> GetDictTypenameForSignature(
      std::string::const_iterator signature,
      std::string::const_iterator end,
      std::string::const_iterator* next);

  // Utility task for GetTypenameForSignature() which handles structs.
  // The arguments and return values are the same as GetTypenameForSignature().
  std::unique_ptr<DBusType> GetStructTypenameForSignature(
      std::string::const_iterator signature,
      std::string::const_iterator end,
      std::string::const_iterator* next);
};

}  // namespace chromeos_dbus_bindings

#endif  // CHROMEOS_DBUS_BINDINGS_DBUS_SIGNATURE_H_
