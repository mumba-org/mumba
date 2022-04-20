// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/net/netlink_packet.h"

#include <algorithm>

//#include <base/check.h>
#include <base/logging.h>

#include "shill/net/byte_string.h"

namespace shill {

NetlinkPacket::NetlinkPacket(const unsigned char* buf, size_t len)
    : consumed_bytes_(0) {
  if (!buf || len < sizeof(header_)) {
    LOG(ERROR) << "Cannot retrieve header.";
    return;
  }

  memcpy(&header_, buf, sizeof(header_));
  if (len < header_.nlmsg_len || header_.nlmsg_len < sizeof(header_)) {
    LOG(ERROR) << "Discarding incomplete / invalid message.";
    return;
  }

  payload_.reset(new ByteString(buf + sizeof(header_), len - sizeof(header_)));
}

NetlinkPacket::~NetlinkPacket() {}

bool NetlinkPacket::IsValid() const {
  return payload_ != nullptr;
}

size_t NetlinkPacket::GetLength() const {
  return GetNlMsgHeader().nlmsg_len;
}

uint16_t NetlinkPacket::GetMessageType() const {
  return GetNlMsgHeader().nlmsg_type;
}

uint32_t NetlinkPacket::GetMessageSequence() const {
  return GetNlMsgHeader().nlmsg_seq;
}

size_t NetlinkPacket::GetRemainingLength() const {
  return GetPayload().GetLength() - consumed_bytes_;
}

const ByteString& NetlinkPacket::GetPayload() const {
  CHECK(IsValid());
  return *payload_;
}

bool NetlinkPacket::ConsumeAttributes(
    const AttributeList::NewFromIdMethod& factory,
    const AttributeListRefPtr& attributes) {
  bool result = attributes->Decode(GetPayload(), consumed_bytes_, factory);
  consumed_bytes_ = GetPayload().GetLength();
  return result;
}

bool NetlinkPacket::ConsumeData(size_t len, void* data) {
  if (GetRemainingLength() < len) {
    LOG(ERROR) << "Not enough bytes remaining.";
    return false;
  }

  memcpy(data, payload_->GetData() + consumed_bytes_, len);
  consumed_bytes_ =
      std::min(payload_->GetLength(), consumed_bytes_ + NLMSG_ALIGN(len));
  return true;
}

const nlmsghdr& NetlinkPacket::GetNlMsgHeader() const {
  CHECK(IsValid());
  return header_;
}

bool NetlinkPacket::GetGenlMsgHdr(genlmsghdr* header) const {
  if (GetPayload().GetLength() < sizeof(*header)) {
    return false;
  }
  memcpy(header, payload_->GetConstData(), sizeof(*header));
  return true;
}

MutableNetlinkPacket::MutableNetlinkPacket(const unsigned char* buf, size_t len)
    : NetlinkPacket(buf, len) {}

MutableNetlinkPacket::~MutableNetlinkPacket() {}

void MutableNetlinkPacket::ResetConsumedBytes() {
  set_consumed_bytes(0);
}

nlmsghdr* MutableNetlinkPacket::GetMutableHeader() {
  CHECK(IsValid());
  return mutable_header();
}

ByteString* MutableNetlinkPacket::GetMutablePayload() {
  CHECK(IsValid());
  return mutable_payload();
}

void MutableNetlinkPacket::SetMessageType(uint16_t type) {
  mutable_header()->nlmsg_type = type;
}

void MutableNetlinkPacket::SetMessageSequence(uint32_t sequence) {
  mutable_header()->nlmsg_seq = sequence;
}

}  // namespace shill.
