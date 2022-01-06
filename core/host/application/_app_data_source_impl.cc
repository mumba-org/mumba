// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/app_data_source_impl.h"

#include <stddef.h>
#include <stdint.h>

#include <string>

#include "base/bind.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ref_counted_memory.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "mumba/app/resources/grit/content_resources.h"
#include "core/host/host_client.h"
#include "core/shared/common/client.h"
#include "ui/base/template_expressions.h"
//#include "ui/base/webui/jstemplate_builder.h"
//#include "ui/base/webui/web_ui_util.h"

namespace host {

// static
RpcDataSource* RpcDataSource::Create(const std::string& source_name) {
  return new AppDataSourceImpl(source_name);
}

// static
void RpcDataSource::Add(Workspace* workspace,
                        RpcDataSource* source) {
  URLDataManager::AddAppDataSource(workspace, source);
}

// static
void RpcDataSource::Update(Workspace* workspace,
                           const std::string& source_name,
                           std::unique_ptr<base::DictionaryValue> update) {
  URLDataManager::UpdateAppDataSource(workspace, source_name,
                                      std::move(update));
}

namespace {

std::string CleanUpPath(const std::string& path) {
  // Remove the query string for named resource lookups.
  return path.substr(0, path.find_first_of('?'));
}

}  // namespace

// Internal class to hide the fact that AppDataSourceImpl implements
// URLDataSource.
class AppDataSourceImpl::InternalDataSource : public URLDataSource {
 public:
  explicit InternalDataSource(AppDataSourceImpl* parent) : parent_(parent) {}

  ~InternalDataSource() override {}

  // URLDataSource implementation.
  std::string GetSource() const override { return parent_->GetSource(); }
  std::string GetMimeType(const std::string& path) const override {
    return parent_->GetMimeType(path);
  }
  void StartDataRequest(
      const GURL& url,
      const std::string& path,
      const ResourceRequestInfo::ApplicationContentsGetter& wc_getter,
      const URLDataSource::GotDataCallback& callback) override {
    return parent_->StartDataRequest(url, path, wc_getter, callback);
  }
  bool ShouldReplaceExistingSource() const override {
    return parent_->replace_existing_source_;
  }
  bool AllowCaching() const override { return false; }
  bool ShouldAddContentSecurityPolicy() const override {
    return parent_->add_csp_;
  }
  std::string GetContentSecurityPolicyScriptSrc() const override {
    if (parent_->script_src_set_)
      return parent_->script_src_;
    return URLDataSource::GetContentSecurityPolicyScriptSrc();
  }
  std::string GetContentSecurityPolicyObjectSrc() const override {
    if (parent_->object_src_set_)
      return parent_->object_src_;
    return URLDataSource::GetContentSecurityPolicyObjectSrc();
  }
  std::string GetContentSecurityPolicyChildSrc() const override {
    if (parent_->frame_src_set_)
      return parent_->frame_src_;
    return URLDataSource::GetContentSecurityPolicyChildSrc();
  }
  bool ShouldDenyXFrameOptions() const override {
    return parent_->deny_xframe_options_;
  }
  bool IsGzipped(const std::string& path) const override {
    return parent_->IsGzipped(path);
  }

 private:
  AppDataSourceImpl* parent_;
};

AppDataSourceImpl::AppDataSourceImpl(const std::string& source_name)
    : URLDataSourceImpl(source_name, new InternalDataSource(this)),
      source_name_(source_name),
      default_resource_(-1),
      add_csp_(true),
      script_src_set_(false),
      object_src_set_(false),
      frame_src_set_(false),
      deny_xframe_options_(true),
      add_load_time_data_defaults_(true),
      replace_existing_source_(true),
      use_gzip_(false) {}

AppDataSourceImpl::~AppDataSourceImpl() {
}

void AppDataSourceImpl::AddString(base::StringPiece name,
                                    const base::string16& value) {
  // TODO(dschuyler): Share only one copy of these strings.
  localized_strings_.SetKey(name, base::Value(value));
  replacements_[name.as_string()] = base::UTF16ToUTF8(value);
}

void AppDataSourceImpl::AddString(base::StringPiece name,
                                    const std::string& value) {
  localized_strings_.SetKey(name, base::Value(value));
  replacements_[name.as_string()] = value;
}

void AppDataSourceImpl::AddLocalizedString(base::StringPiece name, int ids) {
  std::string utf8_str =
      base::UTF16ToUTF8(common::GetClient()->GetLocalizedString(ids));
  localized_strings_.SetKey(name, base::Value(utf8_str));
  replacements_[name.as_string()] = utf8_str;
}

void AppDataSourceImpl::AddLocalizedStrings(
    const base::DictionaryValue& localized_strings) {
  localized_strings_.MergeDictionary(&localized_strings);
  ui::TemplateReplacementsFromDictionaryValue(localized_strings,
                                              &replacements_);
}

void AppDataSourceImpl::AddBoolean(base::StringPiece name, bool value) {
  localized_strings_.SetBoolean(name, value);
  // TODO(dschuyler): Change name of |localized_strings_| to |load_time_data_|
  // or similar. These values haven't been found as strings for
  // localization. The boolean values are not added to |replacements_|
  // for the same reason, that they are used as flags, rather than string
  // replacements.
}

void AppDataSourceImpl::AddInteger(base::StringPiece name, int32_t value) {
  localized_strings_.SetInteger(name, value);
}

void AppDataSourceImpl::SetJsonPath(base::StringPiece path) {
  DCHECK(json_path_.empty());
  DCHECK(!path.empty());

  json_path_ = path.as_string();
  excluded_paths_.insert(json_path_);
}

void AppDataSourceImpl::AddResourcePath(base::StringPiece path,
                                          int resource_id) {
  path_to_idr_map_[path.as_string()] = resource_id;
}

void AppDataSourceImpl::SetDefaultResource(int resource_id) {
  default_resource_ = resource_id;
}

void AppDataSourceImpl::SetRequestFilter(
    const RpcDataSource::HandleRequestCallback& callback) {
  filter_callback_ = callback;
}

void AppDataSourceImpl::DisableReplaceExistingSource() {
  replace_existing_source_ = false;
}

bool AppDataSourceImpl::IsAppDataSourceImpl() const {
  return true;
}

void AppDataSourceImpl::DisableContentSecurityPolicy() {
  add_csp_ = false;
}

void AppDataSourceImpl::OverrideContentSecurityPolicyScriptSrc(
    const std::string& data) {
  script_src_set_ = true;
  script_src_ = data;
}

void AppDataSourceImpl::OverrideContentSecurityPolicyObjectSrc(
    const std::string& data) {
  object_src_set_ = true;
  object_src_ = data;
}

void AppDataSourceImpl::OverrideContentSecurityPolicyChildSrc(
    const std::string& data) {
  frame_src_set_ = true;
  frame_src_ = data;
}

void AppDataSourceImpl::DisableDenyXFrameOptions() {
  deny_xframe_options_ = false;
}

void AppDataSourceImpl::UseGzip(
    const std::vector<std::string>& excluded_paths) {
  use_gzip_ = true;
  for (const auto& path : excluded_paths)
    excluded_paths_.insert(path);
}

const ui::TemplateReplacements* AppDataSourceImpl::GetReplacements() const {
  return &replacements_;
}

void AppDataSourceImpl::EnsureLoadTimeDataDefaultsAdded() {
  if (!add_load_time_data_defaults_)
    return;

  //add_load_time_data_defaults_ = false;
  //std::string locale = common::GetClient()->host()->GetApplicationLocale();
  //base::DictionaryValue defaults;
  //webui::SetLoadTimeDataDefaults(locale, &defaults);
  //AddLocalizedStrings(defaults);
}

std::string AppDataSourceImpl::GetSource() const {
  return source_name_;
}

std::string AppDataSourceImpl::GetMimeType(const std::string& path) const {
  // Remove the query string for to determine the mime type.
  std::string file_path = path.substr(0, path.find_first_of('?'));

  if (base::EndsWith(file_path, ".css", base::CompareCase::INSENSITIVE_ASCII))
    return "text/css";

  if (base::EndsWith(file_path, ".js", base::CompareCase::INSENSITIVE_ASCII))
    return "application/javascript";

  if (base::EndsWith(file_path, ".json", base::CompareCase::INSENSITIVE_ASCII))
    return "application/json";

  if (base::EndsWith(file_path, ".pdf", base::CompareCase::INSENSITIVE_ASCII))
    return "application/pdf";

  if (base::EndsWith(file_path, ".svg", base::CompareCase::INSENSITIVE_ASCII))
    return "image/svg+xml";

  return "text/html";
}

void AppDataSourceImpl::StartDataRequest(
    const GURL& url,
    const std::string& path,
    const ResourceRequestInfo::ApplicationContentsGetter& wc_getter,
    const URLDataSource::GotDataCallback& callback) {
  if (!filter_callback_.is_null() &&
      filter_callback_.Run(path, callback)) {
    return;
  }

  EnsureLoadTimeDataDefaultsAdded();

  if (!json_path_.empty() && path == json_path_) {
    SendLocalizedStringsAsJSON(callback);
    return;
  }

  int resource_id = default_resource_;
  std::map<std::string, int>::iterator result;
  // Remove the query string for named resource lookups.
  result = path_to_idr_map_.find(CleanUpPath(path));
  if (result != path_to_idr_map_.end())
    resource_id = result->second;
  DCHECK_NE(resource_id, -1);
  scoped_refptr<base::RefCountedMemory> response(
      common::GetClient()->GetDataResourceBytes(resource_id));
  callback.Run(response.get());
}

void AppDataSourceImpl::SendLocalizedStringsAsJSON(
    const URLDataSource::GotDataCallback& callback) {
  std::string template_data;
  //webui::AppendJsonJS(&localized_strings_, &template_data);
  callback.Run(base::RefCountedString::TakeString(&template_data));
}

bool AppDataSourceImpl::IsGzipped(const std::string& path) const {
  return use_gzip_ && excluded_paths_.count(CleanUpPath(path)) == 0;
}

}  // namespace host
