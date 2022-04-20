// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DBUS_DBUS_ADAPTOR_H_
#define SHILL_DBUS_DBUS_ADAPTOR_H_

#include <memory>
#include <string>

#include <base/callback.h>
#include <base/memory/weak_ptr.h>
#include <brillo/dbus/dbus_object.h>
#include <brillo/dbus/exported_object_manager.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "shill/callbacks.h"

namespace shill {

class Error;
class PropertyStore;

template <typename... Types>
using DBusMethodResponsePtr =
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<Types...>>;

// Superclass for all DBus-backed Adaptor objects
class DBusAdaptor {
 public:
  static const char kNullPath[];

  DBusAdaptor(const scoped_refptr<dbus::Bus>& bus,
              const std::string& object_path);
  DBusAdaptor(const DBusAdaptor&) = delete;
  DBusAdaptor& operator=(const DBusAdaptor&) = delete;

  ~DBusAdaptor();

  const dbus::ObjectPath& dbus_path() const { return dbus_path_; }

 protected:
  FRIEND_TEST(DBusAdaptorTest, SanitizePathElement);

  // Callback to wrap around DBus method response.
  ResultCallback GetMethodReplyCallback(DBusMethodResponsePtr<> response);

  // Adaptors call this method just before returning. If |error|
  // indicates that the operation has completed, with no asynchronously
  // delivered result expected, then a DBus method reply is immediately
  // sent to the client that initiated the method invocation. Otherwise,
  // the operation is ongoing, and the result will be sent to the client
  // when the operation completes at some later time.
  //
  // Adaptors should always construct an Error initialized to the value
  // Error::kOperationInitiated. A pointer to this Error is passed down
  // through the call stack. Any layer that determines that the operation
  // has completed, either because of a failure that prevents carrying it
  // out, or because it was possible to complete it without sending a request
  // to an external server, should call error.Reset() to indicate success,
  // or to some error type to reflect the kind of failure that occurred.
  // Otherwise, they should leave the Error alone.
  //
  // The general structure of an adaptor method is
  //
  // void XXXXDBusAdaptor::SomeMethod(<args...>, DBusMethodResponsePtr<> resp) {
  //   Error e(Error::kOperationInitiated);
  //   ResultCallback callback = GetMethodReplyCallback(resp);
  //   xxxx_->SomeMethod(<args...>, &e, callback);
  //   ReturnResultOrDefer(callback, e);
  // }
  //
  void ReturnResultOrDefer(const ResultCallback& callback, const Error& error);

  brillo::dbus_utils::DBusObject* dbus_object() const {
    return dbus_object_.get();
  }

  // Set the property with |name| through |store|. Returns true if and
  // only if the property was changed. Updates |error| if a) an error
  // was encountered, and b) |error| is non-NULL. Otherwise, |error| is
  // unchanged.
  static bool SetProperty(PropertyStore* store,
                          const std::string& name,
                          const brillo::Any& value,
                          brillo::ErrorPtr* error);
  static bool GetProperties(const PropertyStore& store,
                            brillo::VariantDictionary* out_properties,
                            brillo::ErrorPtr* error);
  // Look for a property with |name| in |store|. If found, reset the
  // property to its "factory" value. If the property can not be
  // found, or if it can not be cleared (e.g., because it is
  // read-only), set |error| accordingly.
  //
  // Returns true if the property was found and cleared; returns false
  // otherwise.
  static bool ClearProperty(PropertyStore* store,
                            const std::string& name,
                            brillo::ErrorPtr* error);

  // Returns an object path fragment that conforms to D-Bus specifications.
  static std::string SanitizePathElement(const std::string& object_path);

 private:
  void MethodReplyCallback(DBusMethodResponsePtr<> response,
                           const Error& error);

  dbus::ObjectPath dbus_path_;
  std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object_;
  base::WeakPtrFactory<DBusAdaptor> weak_factory_{this};
};

}  // namespace shill

#endif  // SHILL_DBUS_DBUS_ADAPTOR_H_
