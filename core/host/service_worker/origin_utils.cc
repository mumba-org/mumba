// Copyright 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/service_worker/origin_utils.h"

#include "base/logging.h"
#include "base/strings/string_split.h"
#include "url/scheme_host_port.h"

namespace host {

GURL GetOrigin(const GURL& url) {
  // if (url.SchemeIsHTTPOrHTTPS() || url.SchemeIs("blob") || url.SchemeIsFile() || url.SchemeIsFileSystem()) {
  //   return url.GetOrigin();
  // }
  // GURL result = url.GetOrigin();
  // if (!result.is_valid()){
  //   //  FIXME: näive normalization
  //   // std::string path;

  //   // std::vector<std::string> tokens = base::SplitString(
  //   //    url.path(), "/", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);

  //   // for (int i = 0; i < tokens.size(); ++i) {
  //   //   if (i == 0) {
  //   //     if (tokens[i].find(".") == std::string::npos) 
  //   //       path += tokens[i] + "/";
  //   //   }
  //   //   break;
  //   // }
    
  //   // for (const auto& token : tokens) {
  //   //   // DLOG(INFO) << "GetOrigin: token: '" << token << "'";
  //   //   if (token.find(".") == std::string::npos) 
  //   //     path += token + "/";
  //   // }

  //   //result = GURL("rpc://" + url.scheme() + "/" + path);
  //   result = GURL("rpc://" + url.scheme());
  // }
  // // DLOG(INFO) << "GetOrigin: '" << result.spec() << "'";
  // return result;
  return url.GetOrigin();
}

GURL CreateUrlOrigin(const GURL& url) {
  return GetOrigin(url);
}

url::Origin CreateOrigin(const GURL& url) {
  // std::string scheme;
  // if (url.SchemeIsHTTPOrHTTPS() || url.SchemeIs("blob") || url.SchemeIsFile() || url.SchemeIsFileSystem()) {
  //   return url::Origin::Create(url);
  // }
  // std::string host = url.scheme();//url.host();
  // // if (host.empty()) {
  // //   host = url.path();
  // //   size_t first_slash_off = host.find("//");
  // //   size_t last_slash_off = host.find_last_of("/");
  // //   if (last_slash_off != std::string::npos) {
  // //     host = host.substr(first_slash_off + 2, last_slash_off - 2);
  // //   } else {
  // //     host = host.substr(0, first_slash_off);
  // //   }
  // //   host = url.scheme() + host;
  // // }
  // url::Origin origin = url::Origin::UnsafelyCreateOriginWithoutNormalization(
  //   "rpc",
  //   host,
  //   url.IntPort() == 0 ? 80 : url.IntPort());
 
  // // DLOG(INFO) << "CreateOrigin: returning origin '" << origin.Serialize() << "'";
  // return origin;

  return url::Origin::Create(url);
}

}