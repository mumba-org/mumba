// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/entry_node.h"

#include "core/host/application/entry_channel.h"
#include "core/host/rpc/server/host_rpc_service.h"

namespace host {

// static
EntryContentType EntryContentTypeFromEnumValue(int value) {
  switch (value) {
    case 0:
      return EntryContentType::kUNDEFINED;
    case 1:
      return EntryContentType::kBINARY;
    case 2:
      return EntryContentType::kTEXT_ASCII;
    case 3:
      return EntryContentType::kTEXT_UTF8;
    case 4:
      return EntryContentType::kTEXT_UTF8;
    case 5:
      return EntryContentType::kTEXT_XML;
    case 6:
      return EntryContentType::kTEXT_HTML;
    case 7:
      return EntryContentType::kTEXT_JSON; 
  }
  return EntryContentType::kUNDEFINED;
}

EntryContentMode EntryContentModeFromEnumValue(int value) {
  switch (value) {
    case 0:
      return EntryContentMode::kUNDEFINED;
    case 1:
      return EntryContentMode::kSTATIC;
    case 2:
      return EntryContentMode::kDINAMIC;
  }
  return EntryContentMode::kUNDEFINED; 
}

EntryOutputType EntryOutputTypeFromEnumValue(int value) {
  switch (value) {
    case 0:
      return EntryOutputType::kUNDEFINED;
    case 1:
      return EntryOutputType::kNORMAL;
    case 2:
      return EntryOutputType::kSTREAM;
  }
  return EntryOutputType::kUNDEFINED;
}

EntryNode::EntryNode() {

}

EntryNode::~EntryNode() {

}

void EntryNode::AddObserver(EntryNode::Observer* observer) {
  
}

void EntryNode::RemoveObserver(EntryNode::Observer* observer) {

}

EntryContent::EntryContent() {}
EntryContent::~EntryContent() {}

}