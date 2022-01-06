// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMMON_URL_H_
#define COMMON_URL_H_

#include <vector>

#include "base/uuid.h"
#include "url/gurl.h"
#include "core/shared/common/content_export.h"

class CONTENT_EXPORT URL : public GURL {
public:
	URL();
	URL(const GURL& other);
	URL(const URL& other);

  explicit URL(const std::string& url_string);
  explicit URL(const base::string16& url_string);

  URL(const char* canonical_spec,
       size_t canonical_spec_len,
       const url::Parsed& parsed,
       bool is_valid);

  URL(std::string canonical_spec, const url::Parsed& parsed, bool is_valid);

  ~URL();

  URL& operator=(URL other);
  URL& operator=(GURL other);

  //bool SchemeIsObject() const {
  //  return SchemeIs("object");
  //}

  // formal url:
  // shell:path
  // shell:{path/path}
  // shell:{path/path/}

  std::string shell() const;
  std::string path() const;
  // the root node
  std::string root() const;
  // last node in the chain
  std::string last() const;
  
  // split the content part by '/'
  std::vector<std::string> SplitContent() const;
  
  //void GetShellAndPath(std::string& shell, std::string& path) const;

private:

};

#endif
