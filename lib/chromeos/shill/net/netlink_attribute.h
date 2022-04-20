// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NET_NETLINK_ATTRIBUTE_H_
#define SHILL_NET_NETLINK_ATTRIBUTE_H_

#include <map>
#include <memory>
#include <string>
#include <utility>

#include <base/callback.h>

#include "shill/net/attribute_list.h"
#include "shill/net/byte_string.h"
#include "shill/net/netlink_message.h"

namespace shill {

// NetlinkAttribute is an abstract base class that describes an attribute in a
// netlink-80211 message.  Child classes are type-specific and will define
// Get*Value and Set*Value methods (where * is the type).  A second-level of
// child classes exist for each individual attribute type.
//
// An attribute has an id (which is really an enumerated value), a data type,
// and a value.  In an nlattr (the underlying format for an attribute in a
// message), the data is stored as a blob without type information; the writer
// and reader of the attribute must agree on the data type.
class SHILL_EXPORT NetlinkAttribute {
 public:
  enum Type {
    kTypeU8,
    kTypeU16,
    kTypeU32,
    kTypeU64,
    kTypeFlag,
    kTypeString,
    kTypeNested,
    kTypeRaw,
    kTypeError
  };

  NetlinkAttribute(int id,
                   const char* id_string,
                   Type datatype,
                   const char* datatype_string);
  NetlinkAttribute(const NetlinkAttribute&) = delete;
  NetlinkAttribute& operator=(const NetlinkAttribute&) = delete;

  virtual ~NetlinkAttribute() = default;

  // Static factories generate the appropriate attribute object from the
  // raw nlattr data.
  static std::unique_ptr<NetlinkAttribute> NewControlAttributeFromId(int id);
  static std::unique_ptr<NetlinkAttribute> NewNl80211AttributeFromId(
      NetlinkMessage::MessageContext context, int id);

  virtual bool InitFromValue(const ByteString& input);

  // Accessors for the attribute's id and datatype information.
  int id() const { return id_; }
  virtual const char* id_string() const { return id_string_.c_str(); }
  Type datatype() const { return datatype_; }
  const char* datatype_string() const { return datatype_string_; }

  // Accessors.  Return false if request is made on wrong type of attribute.
  virtual bool GetU8Value(uint8_t* value) const;
  virtual bool SetU8Value(uint8_t new_value);

  virtual bool GetU16Value(uint16_t* value) const;
  virtual bool SetU16Value(uint16_t value);

  virtual bool GetU32Value(uint32_t* value) const;
  virtual bool SetU32Value(uint32_t value);

  virtual bool GetU64Value(uint64_t* value) const;
  virtual bool SetU64Value(uint64_t value);

  virtual bool GetFlagValue(bool* value) const;
  virtual bool SetFlagValue(bool value);

  virtual bool GetStringValue(std::string* value) const;
  virtual bool SetStringValue(const std::string& value);

  virtual bool GetNestedAttributeList(AttributeListRefPtr* value);
  virtual bool ConstGetNestedAttributeList(
      AttributeListConstRefPtr* value) const;
  virtual bool SetNestedHasAValue();

  virtual bool GetRawValue(ByteString* value) const;
  virtual bool SetRawValue(const ByteString value);

  // Prints the attribute info -- for debugging.
  virtual void Print(int log_level, int indent) const;

  // Fill a string with characters that represents the value of the attribute.
  // If no attribute is found or if the datatype isn't trivially stringizable,
  // this method returns 'false' and |value| remains unchanged.
  virtual bool ToString(std::string* value) const = 0;

  // Writes the raw attribute data to a string.  For debug.
  std::string RawToString() const;

  // Encodes the attribute suitably for the attributes in the payload portion
  // of a netlink message suitable for Sockets::Send.  Return value is empty on
  // failure.
  virtual ByteString Encode() const = 0;

  bool has_a_value() const { return has_a_value_; }

 protected:
  // Builds a string to precede a printout of this attribute.
  std::string HeaderToPrint(int indent) const;

  // Encodes the attribute suitably for the attributes in the payload portion
  // of a netlink message suitable for Sockets::Send.  Return value is empty on
  // failure.
  ByteString EncodeGeneric(const unsigned char* data, size_t num_bytes) const;

  // Attribute data (NOT including the nlattr header) corresponding to the
  // value in any of the child classes.
  ByteString data_;

  // True if a value has been assigned to the attribute; false, otherwise.
  bool has_a_value_;

 private:
  int id_;
  std::string id_string_;
  Type datatype_;
  const char* datatype_string_;
};

class NetlinkU8Attribute : public NetlinkAttribute {
 public:
  static const char kMyTypeString[];
  static const Type kType;
  NetlinkU8Attribute(int id, const char* id_string)
      : NetlinkAttribute(id, id_string, kType, kMyTypeString) {}
  NetlinkU8Attribute(const NetlinkU8Attribute&) = delete;
  NetlinkU8Attribute& operator=(const NetlinkU8Attribute&) = delete;

  bool InitFromValue(const ByteString& data) override;
  bool GetU8Value(uint8_t* value) const override;
  bool SetU8Value(uint8_t new_value) override;
  bool ToString(std::string* value) const override;
  ByteString Encode() const override;

 private:
  uint8_t value_;
};

class NetlinkU16Attribute : public NetlinkAttribute {
 public:
  static const char kMyTypeString[];
  static const Type kType;
  NetlinkU16Attribute(int id, const char* id_string)
      : NetlinkAttribute(id, id_string, kType, kMyTypeString) {}
  NetlinkU16Attribute(const NetlinkU16Attribute&) = delete;
  NetlinkU16Attribute& operator=(const NetlinkU16Attribute&) = delete;

  bool InitFromValue(const ByteString& data) override;
  bool GetU16Value(uint16_t* value) const override;
  bool SetU16Value(uint16_t new_value) override;
  bool ToString(std::string* value) const override;
  ByteString Encode() const override;

 private:
  uint16_t value_;
};

// Set SHILL_EXPORT to allow unit tests to instantiate these.
class SHILL_EXPORT NetlinkU32Attribute : public NetlinkAttribute {
 public:
  static const char kMyTypeString[];
  static const Type kType;
  NetlinkU32Attribute(int id, const char* id_string)
      : NetlinkAttribute(id, id_string, kType, kMyTypeString) {}
  NetlinkU32Attribute(const NetlinkU32Attribute&) = delete;
  NetlinkU32Attribute& operator=(const NetlinkU32Attribute&) = delete;

  bool InitFromValue(const ByteString& data) override;
  bool GetU32Value(uint32_t* value) const override;
  bool SetU32Value(uint32_t new_value) override;
  bool ToString(std::string* value) const override;
  ByteString Encode() const override;

 private:
  uint32_t value_;
};

class NetlinkU64Attribute : public NetlinkAttribute {
 public:
  static const char kMyTypeString[];
  static const Type kType;
  NetlinkU64Attribute(int id, const char* id_string)
      : NetlinkAttribute(id, id_string, kType, kMyTypeString) {}
  NetlinkU64Attribute(const NetlinkU64Attribute&) = delete;
  NetlinkU64Attribute& operator=(const NetlinkU64Attribute&) = delete;

  bool InitFromValue(const ByteString& data) override;
  bool GetU64Value(uint64_t* value) const override;
  bool SetU64Value(uint64_t new_value) override;
  bool ToString(std::string* value) const override;
  ByteString Encode() const override;

 private:
  uint64_t value_;
};

class NetlinkFlagAttribute : public NetlinkAttribute {
 public:
  static const char kMyTypeString[];
  static const Type kType;
  NetlinkFlagAttribute(int id, const char* id_string)
      : NetlinkAttribute(id, id_string, kType, kMyTypeString) {}
  NetlinkFlagAttribute(const NetlinkFlagAttribute&) = delete;
  NetlinkFlagAttribute& operator=(const NetlinkFlagAttribute&) = delete;

  bool InitFromValue(const ByteString& data) override;
  bool GetFlagValue(bool* value) const override;
  bool SetFlagValue(bool new_value) override;
  bool ToString(std::string* value) const override;
  ByteString Encode() const override;

 private:
  bool value_;
};

// Set SHILL_EXPORT to allow unit tests to instantiate these.
class SHILL_EXPORT NetlinkStringAttribute : public NetlinkAttribute {
 public:
  static const char kMyTypeString[];
  static const Type kType;
  NetlinkStringAttribute(int id, const char* id_string)
      : NetlinkAttribute(id, id_string, kType, kMyTypeString) {}
  NetlinkStringAttribute(const NetlinkStringAttribute&) = delete;
  NetlinkStringAttribute& operator=(const NetlinkStringAttribute&) = delete;

  bool InitFromValue(const ByteString& data) override;
  bool GetStringValue(std::string* value) const override;
  bool SetStringValue(const std::string& new_value) override;
  bool ToString(std::string* value) const override;
  ByteString Encode() const override;
  std::string value() const { return value_; }
  void set_value(const std::string& value) { value_ = value; }

 private:
  std::string value_;
};

// SSID attributes are just string attributes with different output semantics.
class NetlinkSsidAttribute : public NetlinkStringAttribute {
 public:
  NetlinkSsidAttribute(int id, const char* id_string)
      : NetlinkStringAttribute(id, id_string) {}
  NetlinkSsidAttribute(const NetlinkSsidAttribute&) = delete;
  NetlinkSsidAttribute& operator=(const NetlinkSsidAttribute&) = delete;

  // NOTE: |ToString| or |Print| must be used for logging to allow scrubbing.
  bool ToString(std::string* output) const override;
};

class NetlinkNestedAttribute : public NetlinkAttribute {
 public:
  static const char kMyTypeString[];
  static const Type kType;
  NetlinkNestedAttribute(int id, const char* id_string);
  NetlinkNestedAttribute(const NetlinkNestedAttribute&) = delete;
  NetlinkNestedAttribute& operator=(const NetlinkNestedAttribute&) = delete;

  bool InitFromValue(const ByteString& data) override;
  bool GetNestedAttributeList(AttributeListRefPtr* value) override;
  bool ConstGetNestedAttributeList(
      AttributeListConstRefPtr* value) const override;
  bool SetNestedHasAValue() override;
  void Print(int log_level, int indent) const override;
  bool ToString(std::string* value) const override;
  ByteString Encode() const override;

 protected:
  // Describes a single nested attribute.  Provides the expected values and
  // type (including further nesting).  Normally, an array of these, one for
  // each attribute at one level of nesting is presented, along with the data
  // to be parsed, to |InitNestedFromValue|.  If the attributes on one level
  // represent an array, a single |NestedData| is provided and |is_array| is
  // set (note that one level of nesting either contains _only_ an array or
  // _no_ array).
  struct NestedData {
    using AttributeParser =
        base::Callback<bool(AttributeList* list,
                            size_t id,
                            const std::string& attribute_name,
                            ByteString data)>;
    using NestedDataMap = std::map<size_t, NestedData>;

    NestedData();
    NestedData(Type type, std::string attribute_name, bool is_array);
    NestedData(Type type,
               std::string attribute_name,
               bool is_array,
               const AttributeParser& parse_attribute);
    Type type;
    std::string attribute_name;
    NestedDataMap deeper_nesting;
    bool is_array;
    // Closure that overrides the usual parsing of this attribute.  A non-NULL
    // value for |parse_attribute| will cause the software to ignore the other
    // members of the |NestedData| structure.
    AttributeParser parse_attribute;
  };

  using AttrDataPair = std::pair<size_t, NestedData>;

  // Some Nl80211 nested attributes are containers that do not have an actual
  // attribute id, but are nested in another attribute as array elements.
  // In the underlying netlink message, these attributes exist in their own
  // nested layer, and take on attribute ids equal to their index in the array.
  // For purposes of parsing these attributes, assign them an arbitrary
  // attribute id.
  static const size_t kArrayAttrEnumVal;

  // Builds an AttributeList (|list|) that contains all of the attriubtes in
  // |value|.  |value| should contain the payload of the nested attribute
  // and not the nested attribute header itself; for the example of the nested
  // attribute NL80211_ATTR_CQM should contain:
  //    nlattr::nla_type: NL80211_ATTR_CQM
  //    nlattr::nla_len: 12 bytes
  //      nlattr::nla_type: PKT_LOSS_EVENT (1st and only nested attribute)
  //      nlattr::nla_len: 8 bytes
  //      <data>: 0x32
  // One can assemble (hence, disassemble) a set of child attributes under a
  // nested attribute parent as an array of elements or as a structure.
  //
  // The data is parsed using the expected configuration in |nested_template|.
  // If the code expects an array, it will pass a single template element and
  // mark that as an array.
  static bool InitNestedFromValue(const AttributeListRefPtr& list,
                                  const NestedData::NestedDataMap& templates,
                                  const ByteString& value);

  AttributeListRefPtr value_;
  NestedData::NestedDataMap nested_template_;

 private:
  // Helper functions used by InitNestedFromValue to add a single child
  // attribute to a nested attribute.
  static bool AddAttributeToNestedMap(
      const NetlinkNestedAttribute::NestedData::NestedDataMap& templates,
      const AttributeListRefPtr& list,
      int id,
      const ByteString& value);
  static bool AddAttributeToNestedArray(
      const NetlinkNestedAttribute::NestedData& array_template,
      const AttributeListRefPtr& list,
      int id,
      const ByteString& value);
  static bool AddAttributeToNestedInner(
      const NetlinkNestedAttribute::NestedData& nested_template,
      const std::string& attribute_name,
      const AttributeListRefPtr& list,
      int id,
      const ByteString& value);
};

class NetlinkRawAttribute : public NetlinkAttribute {
 public:
  static const char kMyTypeString[];
  static const Type kType;
  NetlinkRawAttribute(int id, const char* id_string)
      : NetlinkAttribute(id, id_string, kType, kMyTypeString) {}
  NetlinkRawAttribute(const NetlinkRawAttribute&) = delete;
  NetlinkRawAttribute& operator=(const NetlinkRawAttribute&) = delete;

  bool InitFromValue(const ByteString& data) override;
  // Gets the value of the data (the header is not stored).
  bool GetRawValue(ByteString* value) const override;
  // Should set the value of the data (not the attribute header).
  bool SetRawValue(const ByteString value) override;
  bool ToString(std::string* value) const override;
  ByteString Encode() const override;
};

class NetlinkAttributeGeneric : public NetlinkRawAttribute {
 public:
  explicit NetlinkAttributeGeneric(int id);
  NetlinkAttributeGeneric(const NetlinkAttributeGeneric&) = delete;
  NetlinkAttributeGeneric& operator=(const NetlinkAttributeGeneric&) = delete;

  const char* id_string() const override;

 private:
  std::string id_string_;
};

}  // namespace shill

#endif  // SHILL_NET_NETLINK_ATTRIBUTE_H_
