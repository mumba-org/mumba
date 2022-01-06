// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/net/host_network_delegate.h"

namespace host {

HostNetworkDelegate::HostNetworkDelegate() {

}

HostNetworkDelegate::~HostNetworkDelegate() {

}

int HostNetworkDelegate::OnBeforeURLRequest(net::URLRequest* request,
                        const net::CompletionCallback& callback,
                        GURL* new_url) {
 return 0;
}

int HostNetworkDelegate::OnBeforeStartTransaction(net::URLRequest* request,
                              const net::CompletionCallback& callback,
                              net::HttpRequestHeaders* headers) {
 return 0;
}

void HostNetworkDelegate::OnStartTransaction(net::URLRequest* request,
                        const net::HttpRequestHeaders& headers) {

}

int HostNetworkDelegate::OnHeadersReceived(
    net::URLRequest* request,
    const net::CompletionCallback& callback,
    const net::HttpResponseHeaders* original_response_headers,
    scoped_refptr<net::HttpResponseHeaders>* override_response_headers,
    GURL* allowed_unsafe_redirect_url) {

 return 0;
}

void HostNetworkDelegate::OnBeforeRedirect(net::URLRequest* request,
                      const GURL& new_location) {}

void HostNetworkDelegate::OnResponseStarted(net::URLRequest* request, int net_error) {}

void HostNetworkDelegate::OnNetworkBytesReceived(net::URLRequest* request,
                            int64_t bytes_received) {}

void HostNetworkDelegate::OnNetworkBytesSent(net::URLRequest* request,
                        int64_t bytes_sent) {}

void HostNetworkDelegate::OnCompleted(net::URLRequest* request,
                  bool started,
                  int net_error) {}

void HostNetworkDelegate::OnURLRequestDestroyed(net::URLRequest* request) {}

void HostNetworkDelegate::OnPACScriptError(int line_number, const base::string16& error) {}

net::NetworkDelegate::AuthRequiredResponse HostNetworkDelegate::OnAuthRequired(
    net::URLRequest* request,
    const net::AuthChallengeInfo& auth_info,
    const AuthCallback& callback,
    net::AuthCredentials* credentials) {

    return net::NetworkDelegate::AuthRequiredResponse::AUTH_REQUIRED_RESPONSE_NO_ACTION;
}

bool HostNetworkDelegate::OnCanGetCookies(const net::URLRequest& request,
                      const net::CookieList& cookie_list) {

 return true;
}

bool HostNetworkDelegate::OnCanSetCookie(const net::URLRequest& request,
                    const net::CanonicalCookie& cookie,
                    net::CookieOptions* options) {

 return true;
}

bool HostNetworkDelegate::OnCanAccessFile(const net::URLRequest& request,
                      const base::FilePath& original_path,
                      const base::FilePath& absolute_path) const {
  return true;
}

bool HostNetworkDelegate::OnCanEnablePrivacyMode(const GURL& url,
                            const GURL& site_for_cookies) const {

 return true;
}

bool HostNetworkDelegate::OnAreExperimentalCookieFeaturesEnabled() const {
  return true;
}

bool HostNetworkDelegate::OnCancelURLRequestWithPolicyViolatingReferrerHeader(
    const net::URLRequest& request,
    const GURL& target_url,
    const GURL& referrer_url) const {
  return true;
}

bool HostNetworkDelegate::OnCanQueueReportingReport(const url::Origin& origin) const {
  return true;
}

void HostNetworkDelegate::OnCanSendReportingReports(std::set<url::Origin> origins,
                                base::OnceCallback<void(std::set<url::Origin>)>
                                    result_callback) const {}

bool HostNetworkDelegate::OnCanSetReportingClient(const url::Origin& origin,
                              const GURL& endpoint) const {
  return true;
}

bool HostNetworkDelegate::OnCanUseReportingClient(const url::Origin& origin,
                              const GURL& endpoint) const {

  return true;
}
  

}