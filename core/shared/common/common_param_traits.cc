// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/common/common_param_traits.h"

#include <string>

#include "base/strings/utf_string_conversions.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"

namespace IPC {

// DropData::FileSystemFileInfo
void ParamTraits<common::DropData::FileSystemFileInfo>::Write(base::Pickle* m,
                                                              const param_type& p) {
  m->WriteString(p.url.spec());
  m->WriteInt64(p.size);
  m->WriteString(p.filesystem_id);
}

bool ParamTraits<common::DropData::FileSystemFileInfo>::Read(const base::Pickle* m,
                                                             base::PickleIterator* iter,
                                                             param_type* r) {
    common::DropData::FileSystemFileInfo result;
    std::string url_string;
    int64_t size = 0;
    std::string filesystem_id;
    
    if (!iter->ReadString(&url_string) || !iter->ReadInt64(&size) ||
        !iter->ReadString(&filesystem_id)) {
      return false;
    }

    GURL url(url_string);
    if (!url.is_valid()) {
      return false;
    }

    result.url = url;
    result.size = size;
    result.filesystem_id = filesystem_id;

    *r = result;

    return true;
}

void ParamTraits<common::DropData::FileSystemFileInfo>::Log(const param_type& p,
                                                            std::string* l) {
  l->append("<DropData::FileSystemFileInfo>");
}


// DropData

void ParamTraits<common::DropData>::Write(base::Pickle* m,
                                          const param_type& p) {
  WriteParam(m, p.view_id);
  WriteParam(m, p.did_originate_from_renderer);
  WriteParam(m, p.url.spec());
  WriteParam(m, p.url_title);
  WriteParam(m, p.download_metadata);
 
  m->WriteUInt32(p.filenames.size());
  for (const auto& filename : p.filenames) {
#if defined(OS_WIN)    
    m->WriteString(base::UTF16ToASCII(filename.path.value()));
    m->WriteString(base::UTF16ToASCII(filename.display_name.value()));
#else
    m->WriteString(filename.path.value());
    m->WriteString(filename.display_name.value());
#endif    
  }
 
  WriteParam(m, p.file_mime_types);
  WriteParam(m, p.filesystem_id);
  common::DropData::FileSystemFileInfo::WriteFileSystemFilesToPickle(p.file_system_files, m);
  WriteParam(m, p.text);
  WriteParam(m, p.html);
  WriteParam(m, p.html_base_url.spec());
  WriteParam(m, p.file_contents);
  WriteParam(m, p.file_contents_source_url.spec());
  WriteParam(m, p.file_contents_filename_extension);
  WriteParam(m, p.file_contents_content_disposition);
  WriteParam(m, p.custom_data);
  WriteParam(m, p.key_modifiers);
}

bool ParamTraits<common::DropData>::Read(const base::Pickle* m,
                                         base::PickleIterator* iter,
                                         param_type* r) {
  int view_id;
  bool did_originate_from_renderer;
  std::string url_string;
  base::string16 url_title;
  base::string16 download_metadata;
  std::vector<ui::FileInfo> filenames;
  std::vector<base::string16> file_mime_types;
  base::string16 filesystem_id;
  std::vector<common::DropData::FileSystemFileInfo> file_system_files;
  base::NullableString16 text;
  base::NullableString16 html;
  //GURL html_base_url;
  std::string html_base_url_string;
  std::string file_contents;
  //GURL file_contents_source_url;
  std::string file_contents_source_url_string;
  base::FilePath::StringType file_contents_filename_extension;
  std::string file_contents_content_disposition;
  std::unordered_map<base::string16, base::string16> custom_data;
  int key_modifiers;

  if (!ReadParam(m, iter, &view_id) || !ReadParam(m, iter, &did_originate_from_renderer) || 
      !ReadParam(m, iter, &url_string) || !ReadParam(m, iter, &url_title) ||
      !ReadParam(m, iter, &download_metadata)) {
    return false;
  }  

  uint32_t num_files = 0;
  if (!iter->ReadUInt32(&num_files))
    return false;
  
  filenames.resize(num_files);

  for (uint32_t i = 0; i < num_files; ++i) {
    std::string path;
    std::string displayname;
    if (!iter->ReadString(&path)||
        !iter->ReadString(&displayname)) {
      return false;
    }
#if defined(OS_WIN)
    filenames[i].path = base::FilePath(base::ASCIIToUTF16(path));
    filenames[i].display_name = base::FilePath(base::ASCIIToUTF16(displayname));
#else   
    filenames[i].path = base::FilePath(path);
    filenames[i].display_name = base::FilePath(displayname);
#endif
  }

  if (!ReadParam(m, iter, &file_mime_types) || !ReadParam(m, iter, &filesystem_id)) {
    return false;
  }

  if (!common::DropData::FileSystemFileInfo::ReadFileSystemFilesFromPickle(*m, &file_system_files)) {
    return false;
  }

  if (!ReadParam(m, iter, &text) ||
      !ReadParam(m, iter, &html) || !ReadParam(m, iter, &html_base_url_string) ||
      !ReadParam(m, iter, &file_contents) || !ReadParam(m, iter, &file_contents_source_url_string) ||
      !ReadParam(m, iter, &file_contents_filename_extension) || !ReadParam(m, iter, &file_contents_content_disposition) ||
      !ReadParam(m, iter, &custom_data) || !ReadParam(m, iter, &key_modifiers)) {
    return false;
  }

  common::DropData result;
  result.view_id = view_id; 
  result.did_originate_from_renderer = did_originate_from_renderer;
  result.url = GURL(url_string);
  result.url_title = std::move(url_title);
  result.download_metadata = std::move(download_metadata);
  result.filenames = std::move(filenames);
  result.file_mime_types = std::move(file_mime_types);
  result.filesystem_id = std::move(filesystem_id);
  result.file_system_files = std::move(file_system_files);
  result.text = std::move(text);
  result.html = std::move(html);
  result.html_base_url = GURL(html_base_url_string);
  result.file_contents = std::move(file_contents);
  result.file_contents_source_url = GURL(file_contents_source_url_string);
  result.file_contents_filename_extension = std::move(file_contents_filename_extension);
  result.file_contents_content_disposition = std::move(file_contents_content_disposition);
  result.custom_data = std::move(custom_data);
  result.key_modifiers = key_modifiers;  

  *r = result;

  return true;
}

void ParamTraits<common::DropData>::Log(const param_type& p,
                                        std::string* l) {
  l->append("<DropData>");
}


// DropDataMetadata

void ParamTraits<common::DropDataMetadata>::Write(base::Pickle* m,
                                                  const param_type& p) {
  m->WriteUInt32(static_cast<uint32_t>(p.kind));
  WriteParam(m, p.mime_type);
  WriteParam(m, p.filename);
  WriteParam(m, p.file_system_url.spec());
}

bool ParamTraits<common::DropDataMetadata>::Read(const base::Pickle* m,
                                                 base::PickleIterator* iter,
                                                 param_type* r) {
  uint32_t kind;
  base::string16 mime_type;
  base::FilePath filename;
  std::string file_system_url_string;

  if (!iter->ReadUInt32(&kind) || !ReadParam(m, iter, &mime_type) || 
      !ReadParam(m, iter, &filename) || !ReadParam(m, iter, &file_system_url_string))
    return false;
  
  common::DropDataMetadata result;
  result.kind = static_cast<common::DropDataMetadataKind>(kind);
  result.mime_type = mime_type;
  result.filename = filename;
  result.file_system_url = GURL(file_system_url_string);  
  *r = result;
  return true;
}

void ParamTraits<common::DropDataMetadata>::Log(const param_type& p,
                                                std::string* l) {
  l->append("<DropDataMetadata>");
}

void ParamTraits<URL>::Write(base::Pickle* m, const URL& p) {
  if (p.possibly_invalid_spec().length() > 2 * 1024 * 1024) {//common::GetMaxURLChars()) {
   m->WriteString(std::string());
   return;
  }

  // Beware of print-parse inconsistency which would change an invalid
  // URL into a valid one. Ideally, the message would contain this flag
  // so that the read side could make the check, but performing it here
  // avoids changing the on-the-wire representation of such a fundamental
  // type as GURL. See https://crbug.com/166486 for additional work in
  // this area.
  if (!p.is_valid()) {
   m->WriteString(std::string());
   return;
  }

  m->WriteString(p.possibly_invalid_spec());

 }

 bool ParamTraits<URL>::Read(const base::Pickle* m,
  base::PickleIterator* iter,
  URL* p) {
  std::string s;
  if (!iter->ReadString(&s) || s.length() > 2 * 1024 * 1024) {//common::GetMaxURLChars()) {
   *p = URL();
   return false;
  }
  *p = URL(s);
  if (!s.empty() && !p->is_valid()) {
   *p = URL();
   return false;
  }
  return true;
 }

 void ParamTraits<URL>::Log(const URL& p, std::string* l) {
  l->append(p.spec());
 }

void ParamTraits<net::IPEndPoint>::Write(base::Pickle* m, const param_type& p) {
  WriteParam(m, p.address());
  WriteParam(m, p.port());
}

bool ParamTraits<net::IPEndPoint>::Read(const base::Pickle* m,
                                        base::PickleIterator* iter,
                                        param_type* p) {
  net::IPAddress address;
  uint16_t port;
  if (!ReadParam(m, iter, &address) || !ReadParam(m, iter, &port))
    return false;
  if (!address.empty() && !address.IsValid())
    return false;

  *p = net::IPEndPoint(address, port);
  return true;
}

void ParamTraits<net::IPEndPoint>::Log(const param_type& p, std::string* l) {
  LogParam("IPEndPoint:" + p.ToString(), l);
}

void ParamTraits<net::IPAddress>::Write(base::Pickle* m, const param_type& p) {
  base::StackVector<uint8_t, 16> bytes;
  for (uint8_t byte : p.bytes())
    bytes->push_back(byte);
  WriteParam(m, bytes);
}

bool ParamTraits<net::IPAddress>::Read(const base::Pickle* m,
                                       base::PickleIterator* iter,
                                       param_type* p) {
  base::StackVector<uint8_t, 16> bytes;
  if (!ReadParam(m, iter, &bytes))
    return false;
  if (bytes->size() && bytes->size() != net::IPAddress::kIPv4AddressSize &&
      bytes->size() != net::IPAddress::kIPv6AddressSize) {
    return false;
  }
  *p = net::IPAddress(bytes->data(), bytes->size());
  return true;
}

void ParamTraits<net::IPAddress>::Log(const param_type& p, std::string* l) {
    LogParam("IPAddress:" + (p.empty() ? "(empty)" : p.ToString()), l);
}

}  // namespace IPC

// Generate param traits write methods.
#include "ipc/param_traits_write_macros.h"
namespace IPC {
#undef CONTENT_PUBLIC_COMMON_COMMON_PARAM_TRAITS_MACROS_H_
#include "core/shared/common/common_param_traits_macros.h"
}  // namespace IPC

// Generate param traits read methods.
#include "ipc/param_traits_read_macros.h"
namespace IPC {
#undef CONTENT_PUBLIC_COMMON_COMMON_PARAM_TRAITS_MACROS_H_
#include "core/shared/common/common_param_traits_macros.h"
}  // namespace IPC

// Generate param traits log methods.
#include "ipc/param_traits_log_macros.h"
namespace IPC {
#undef CONTENT_PUBLIC_COMMON_COMMON_PARAM_TRAITS_MACROS_H_
#include "core/shared/common/common_param_traits_macros.h"
}  // namespace IPC
