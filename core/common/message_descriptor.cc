// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/common/message_descriptor.h"

namespace common {

MessageDescriptor::MessageDescriptor(): 
    handle(base::SharedMemory::NULLHandle()), 
    shared(false), 
    body_size(0), 
    body_encoding(kENCODING_NONE) {
    
}

MessageDescriptor(MessageDescriptor& other): 
    handle(other.handle), 
    shared(other.shared), 
    body_size(other.body_size), 
    body_encoding(other.body_encoding) {

}

MessageDescriptor::MessageDescriptor(uint8_t* buffer, uint32_t size, MessageEncoding encoding): 
    handle(base::SharedMemory::NULLHandle()), 
    shared(false), 
    body(reinterpret_cast<char *>(buffer), size),
    body_size(size),
    body_encoding(encoding) {
  CalculateHash();
}

MessageDescriptor::~MessageDescriptor() {
  
}

}