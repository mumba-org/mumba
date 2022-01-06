// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/common/url.h"

#include "base/strings/string_split.h"

URL::URL(): GURL() {}

URL::URL(const GURL& other): GURL(other) {

}

URL::URL(const URL& other): GURL(other) {

}

URL::URL(const std::string& url_string): GURL(url_string) {

}

URL::URL(const base::string16& url_string): GURL(url_string) {

}

URL::URL(const char* canonical_spec,
       		 size_t canonical_spec_len,
       		 const url::Parsed& parsed,
       		 bool is_valid): GURL(
       		 	canonical_spec,
       		 	canonical_spec_len,
       		 	parsed,
       		 	is_valid) {

}

URL::URL(std::string canonical_spec, 
	const url::Parsed& parsed, 
	bool is_valid): GURL(canonical_spec, parsed, is_valid) {

}

URL::~URL() {

}

URL& URL::operator=(URL other) {
	Swap(&other);
  return *this;
}

URL& URL::operator=(GURL other) {
  Swap(&other);
  return *this;
}


std::string URL::path() const {
  std::string content = GetContent();
  if (scheme() == "shell") {
    size_t shell_end = content.find('/');
    if (shell_end == std::string::npos) {
      return std::string();
    }
    return content.substr(shell_end+1); 
  }
  return content;
}

std::string URL::shell() const {
 if (scheme() == "shell") {
   std::string content = GetContent();
   size_t shell_end = content.find('/');
   if (shell_end == std::string::npos) {
    return content;
   }
   return content.substr(0, shell_end);
 }
 return scheme();
}

std::string URL::root() const {
 std::string content = GetContent();
     
 if (scheme() == "shell") {
  size_t shell_end = content.find('/');
  size_t root_end = content.substr(shell_end+1).find('/');
 
   // 'shell:x' case => no root
   if (shell_end == std::string::npos) {
    return std::string();
   }
   // whatever goes after shell:x/{...} is our root
   // if theres none.. so its empty
   return content.substr(shell_end+1, root_end);
 }

 size_t root_end = content.find('/');
 
 if (root_end == std::string::npos) {
    return content;
 }

 return content.substr(0, root_end);
}

std::string URL::last() const {
  std::string content = GetContent();

  //DLOG(INFO) << "spec: " << spec() << " content: " << content;
  
  size_t last_bar = content.rfind("/");
  
  //DLOG(INFO) << "lastbar: " << last_bar;

  if (last_bar == std::string::npos) {
    //DLOG(INFO) << "lastbar = npos. returning '" << content << "'";
    return content;
  }

  if (last_bar == (content.size() - 1)) {
    std::string content_rest = content.substr(0, last_bar);
    size_t almost_last_bar = content_rest.rfind('/'); 
    if (almost_last_bar != std::string::npos)
      return content.substr(almost_last_bar + 1);

    return content_rest;
  }

  //DLOG(INFO) << "returning '" << content.substr(last_bar + 1) << "' substring from '" << content << "'";
  return content.substr(last_bar + 1); 
}

std::vector<std::string> URL::SplitContent() const {
 std::string origin = GetContent();
 return base::SplitString(origin, "/", base::KEEP_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
}