// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/url_data_source.h"

#include "core/host/application/url_data_manager.h"
#include "core/host/route/route_entry.h"
#include "core/host/host_thread.h"
//#include "core/shared/common/url_constants.h"
#include "net/url_request/url_request.h"

namespace host {

void URLDataSource::Add(Domain* domain,
                        URLDataSource* source) {
  URLDataManager::AddDataSource(domain, source);
}

scoped_refptr<base::SingleThreadTaskRunner>
URLDataSource::TaskRunnerForRequestPath(const std::string& scheme, const std::string& path) {
  return HostThread::GetTaskRunnerForThread(HostThread::UI);
}

bool URLDataSource::ShouldReplaceExistingSource() const {
  return true;
}

bool URLDataSource::AllowCaching() const {
  return true;
}

bool URLDataSource::ShouldAddContentSecurityPolicy() const {
  return true;
}

std::string URLDataSource::GetContentSecurityPolicyScriptSrc() const {
  // Specific resources require unsafe-eval in the Content Security Policy.
  // TODO(tsepez,mfoltz): Remove 'unsafe-eval' when tests have been fixed to
  // not use eval()/new Function().  http://crbug.com/525224
  return "script-src chrome://resources 'self' 'unsafe-eval';";
}

std::string URLDataSource::GetContentSecurityPolicyObjectSrc() const {
  return "object-src 'none';";
}

std::string URLDataSource::GetContentSecurityPolicyChildSrc() const {
  return "child-src 'none';";
}

std::string URLDataSource::GetContentSecurityPolicyStyleSrc() const {
  return std::string();
}

std::string URLDataSource::GetContentSecurityPolicyImgSrc() const {
  return std::string();
}

bool URLDataSource::ShouldDenyXFrameOptions() const {
  return true;
}

bool URLDataSource::ShouldServiceRequest(const GURL& url,
                                         ResourceContext* resource_context,
                                         int render_process_id) const {
  return false;//url.SchemeIs(kChromeUIScheme);
}

bool URLDataSource::ShouldServeMimeTypeAsContentTypeHeader() const {
  return false;
}

const ui::TemplateReplacements* URLDataSource::GetReplacements() const {
  return nullptr;
}

std::string URLDataSource::GetAccessControlAllowOriginForOrigin(
    const std::string& origin) const {
  return std::string();
}

bool URLDataSource::IsGzipped(const std::string& scheme, const std::string& path) const {
  return false;
}

}  // namespace host
