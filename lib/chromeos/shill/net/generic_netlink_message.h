// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NET_GENERIC_NETLINK_MESSAGE_H_
#define SHILL_NET_GENERIC_NETLINK_MESSAGE_H_

#include <memory>
#include <string>

#include "shill/net/attribute_list.h"
#include "shill/net/byte_string.h"
#include "shill/net/netlink_message.h"
#include "shill/net/shill_export.h"

namespace shill {

class NetlinkPacket;

// Objects of the |GenericNetlinkMessage| type represent messages that contain
// a |genlmsghdr| after a |nlmsghdr|.  These messages seem to all contain a
// payload that consists of a list of structured attributes (it's possible that
// some messages might have a genlmsghdr and a different kind of payload but I
// haven't seen one, yet).  The genlmsghdr contains a command id that, when
// combined with the family_id (from the nlmsghdr), describes the ultimate use
// for the netlink message.
//
// An attribute contains a header and a chunk of data. The header contains an
// id which is an enumerated value that describes the use of the attribute's
// data (the datatype of the attribute's data is implied by the attribute id)
// and the length of the header+data in bytes.  The attribute id is,
// confusingly, called the type (or nla_type -- this is _not_ the data type of
// the attribute).  Each family defines the meaning of the nla_types in the
// context of messages in that family (for example, the nla_type with the
// value 3 will always mean the same thing for attributes in the same family).
// EXCEPTION: Some attributes are nested (that is, they contain a list of other
// attributes rather than a single value).  Each nested attribute defines the
// meaning of the nla_types in the context of attributes that are nested under
// this attribute (for example, the nla_type with the value 3 will have a
// different meaning when nested under another attribute -- that meaning is
// defined by the attribute under which it is nested).  Fun.
//
// The GenericNetlink messages look like this:
//
// -----+-----+-+-------------------------------------------------+-+--
//  ... |     | |              message payload                    | |
//      |     | +------+-+----------------------------------------+ |
//      | nl  | |      | |                attributes              | |
//      | msg |p| genl |p+-----------+-+---------+-+--------+-----+p| ...
//      | hdr |a| msg  |a|  struct   |p| attrib  |p| struct | ... |a|
//      |     |d| hdr  |d|  nlattr   |a| payload |a| nlattr |     |d|
//      |     | |      | |           |d|         |d|        |     | |
// -----+-----+-+------+-+-----------+-+---------+-+--------+-----+-+--
//                       |              ^        | |
//                       |<-NLA_HDRLEN->|        | |
//                       |<-----hdr.nla_len----->| |
//                       |<NLA_ALIGN(hdr.nla_len)->|

class SHILL_EXPORT GenericNetlinkMessage : public NetlinkMessage {
 public:
  GenericNetlinkMessage(uint16_t my_message_type,
                        uint8_t command,
                        const char* command_string)
      : NetlinkMessage(my_message_type),
        attributes_(new AttributeList),
        command_(command),
        command_string_(command_string) {}
  GenericNetlinkMessage(const GenericNetlinkMessage&) = delete;
  GenericNetlinkMessage& operator=(const GenericNetlinkMessage&) = delete;

  ~GenericNetlinkMessage() override = default;

  ByteString Encode(uint32_t sequence_number) override;

  uint8_t command() const { return command_; }
  const char* command_string() const { return command_string_; }
  AttributeListConstRefPtr const_attributes() const { return attributes_; }
  AttributeListRefPtr attributes() { return attributes_; }
  std::string ToString() const override;
  void Print(int header_log_level, int detail_log_level) const override;

 protected:
  // Returns a string of bytes representing _both_ an |nlmsghdr| and a
  // |genlmsghdr|, filled-in, and its padding.
  ByteString EncodeHeader(uint32_t sequence_number) override;
  // Reads the |nlmsghdr| and |genlmsghdr| headers and consumes the latter
  // from the payload of |packet|.
  bool InitAndStripHeader(NetlinkPacket* packet) override;

  AttributeListRefPtr attributes_;
  const uint8_t command_;
  const char* command_string_;
};

// Control Messages

class SHILL_EXPORT ControlNetlinkMessage : public GenericNetlinkMessage {
 public:
  static const uint16_t kMessageType;
  ControlNetlinkMessage(uint8_t command, const char* command_string)
      : GenericNetlinkMessage(kMessageType, command, command_string) {}
  ControlNetlinkMessage(const ControlNetlinkMessage&) = delete;
  ControlNetlinkMessage& operator=(const ControlNetlinkMessage&) = delete;

  static uint16_t GetMessageType() { return kMessageType; }

  bool InitFromPacket(NetlinkPacket* packet, MessageContext context);

  // Message factory for all types of Control netlink message.
  static std::unique_ptr<NetlinkMessage> CreateMessage(
      const NetlinkPacket& packet);
};

class SHILL_EXPORT NewFamilyMessage : public ControlNetlinkMessage {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  NewFamilyMessage() : ControlNetlinkMessage(kCommand, kCommandString) {}
  NewFamilyMessage(const NewFamilyMessage&) = delete;
  NewFamilyMessage& operator=(const NewFamilyMessage&) = delete;
};

class SHILL_EXPORT GetFamilyMessage : public ControlNetlinkMessage {
 public:
  static const uint8_t kCommand;
  static const char kCommandString[];

  GetFamilyMessage();
  GetFamilyMessage(const GetFamilyMessage&) = delete;
  GetFamilyMessage& operator=(const GetFamilyMessage&) = delete;
};

class SHILL_EXPORT UnknownControlMessage : public ControlNetlinkMessage {
 public:
  explicit UnknownControlMessage(uint8_t command)
      : ControlNetlinkMessage(command, "<UNKNOWN CONTROL MESSAGE>") {}
  UnknownControlMessage(const UnknownControlMessage&) = delete;
  UnknownControlMessage& operator=(const UnknownControlMessage&) = delete;
};

}  // namespace shill

#endif  // SHILL_NET_GENERIC_NETLINK_MESSAGE_H_
