// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_CORE_HOST_APPLICATION_PAGE_ENTRY_H_
#define MUMBA_CORE_HOST_APPLICATION_PAGE_ENTRY_H_

#include "base/macros.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/memory/ref_counted_memory.h"
#include "net/rpc/rpc.h"
#include "url/gurl.h"


namespace host {
class HostRpcService;
class EntryChannel;

enum class EntryContentType {
  kUNDEFINED = 0,
  kBINARY = 1,
  kTEXT_ASCII = 2,
  kTEXT_UTF8 = 3,
  kTEXT_UTF16 = 4,
  kTEXT_XML = 5,
  kTEXT_HTML = 6,
  kTEXT_JSON = 7
};

enum class EntryContentMode {
  kUNDEFINED = 0,
  kSTATIC = 1,
  kDINAMIC = 2
};

enum class EntryOutputType {
  kUNDEFINED = 0,
  kNORMAL = 1,
  kSTREAM = 2
};

EntryContentType EntryContentTypeFromEnumValue(int value);
EntryContentMode EntryContentModeFromEnumValue(int value);
EntryOutputType EntryOutputTypeFromEnumValue(int value);

// TODO: this should become "PageContent"
// while the index data should move to "EntryInfo"

class EntryNode {
public:
  class Observer {
  public:
    virtual ~Observer() {}
    virtual void OnDataAvailable(
      EntryNode* node,
      EntryChannel* event_channel,
      const std::string& content_type, 
      const void* data, 
      size_t data_size) = 0;
  };
  EntryNode();
  ~EntryNode();

  const std::string& name() const {
    return name_;
  }

  void set_name(const std::string& name) {
    name_ = base::ToLowerASCII(name);
  }

  const std::string& title() const {
    return title_;
  }

  const base::string16& title_utf16() const {
    return title_utf16_;
  }

  void set_title(const std::string& title) {
    title_ = title;
    title_utf16_ = base::ASCIIToUTF16(title_);
  }

  const GURL& url() const {
    return url_;
  }

  void set_url(const GURL& url) {
    url_ = url;
  }

  EntryContentType content_type() const {
    return content_type_;
  }

  void set_content_type(EntryContentType content_type) {
    content_type_ = content_type;
  }

  EntryContentMode content_mode() const {
    return content_mode_;
  }

  void set_content_mode(EntryContentMode content_mode) {
    content_mode_ = content_mode;
  }

  EntryOutputType output_type() const {
    return output_type_;
  }

  void set_output_type(EntryOutputType output_type) {
    output_type_ = output_type;
  }

  // this has more value for rpc methods, so i dont
  // know how well this will map to a page entry
  const std::string& full_name() {
    return full_name_;
  }

  void set_fullname(const std::string& fullname) {
    full_name_ = fullname;
  }

  const std::string& path() {
    return path_;
  }

  void set_path(const std::string& path) {
    path_ = path;
  }

  const std::string& input_message() {
    return input_message_;
  }

  void set_input_message(const std::string& input_message) {
    input_message_ = input_message;
  }

  net::RpcMethodType method_type() const {
    return method_type_;
  }

  void set_method_type(net::RpcMethodType method_type) {
    method_type_ = method_type;
  }
  
  const std::string& mime_type() const {
    return mime_type_;
  }

  void set_mime_type(const std::string& mime_type) {
    mime_type_ = mime_type;
  }

  HostRpcService* service() const {
    return service_;
  }

  void set_service(HostRpcService* service) {
    service_ = service;
  }

  scoped_refptr<base::RefCountedBytes> icon_data() const {
    return icon_data_;
  }

  void set_icon_data(scoped_refptr<base::RefCountedBytes> icon_data) {
    icon_data_ = icon_data;
  }

  void AddObserver(Observer* observer);
  void RemoveObserver(Observer* observer);
  
private:

  HostRpcService* service_ = nullptr;
  std::string name_;
  std::string title_;
  base::string16 title_utf16_;
  std::string full_name_;
  std::string path_;
  std::string input_message_;
  net::RpcMethodType method_type_;
  scoped_refptr<base::RefCountedBytes> icon_data_;
  EntryContentType content_type_ = EntryContentType::kUNDEFINED;
  EntryContentMode content_mode_ = EntryContentMode::kUNDEFINED;
  EntryOutputType output_type_ = EntryOutputType::kUNDEFINED;
  GURL url_;
  std::string mime_type_;

  std::unique_ptr<EntryChannel> channel_;

  DISALLOW_COPY_AND_ASSIGN(EntryNode);
};

class EntryContent {
public:
  EntryContent();
  ~EntryContent();

  int32_t offset() const {
    return offset_;
  }

  void set_offset(int32_t offset) {
    offset_ = offset;
  }

  int64_t size() const {
    return size_;
  }

  void set_size(int64_t size) {
    size_ = size; 
  }

  EntryContentType content_type() const {
    return content_type_;
  }

  void set_content_type(EntryContentType content_type) {
    content_type_ = content_type;
  }
  
  // TODO: see if we can change this in a way that avoid copy
  // eg. we can abstract this as DataSourceBackend and leave to
  //     specializations to implement how the data should behave
  //     according to its real data source 
  // idea: use the same EntryDataSource as used for EntryFeed
  scoped_refptr<base::RefCountedString> data() const {
    return data_;
  }

  void set_data(scoped_refptr<base::RefCountedString> data) {
    data_ = data;
  }
  

private:
  int32_t offset_ = -1;
  int64_t size_ = 0;
  EntryContentType content_type_ = EntryContentType::kUNDEFINED;
  scoped_refptr<base::RefCountedString> data_;
  
  DISALLOW_COPY_AND_ASSIGN(EntryContent);
};

}

#endif