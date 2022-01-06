// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_FAVICON_CHROME_FAVICON_CLIENT_H_
#define CHROME_BROWSER_FAVICON_CHROME_FAVICON_CLIENT_H_

#include "base/macros.h"
#include "components/favicon/core/favicon_client.h"

class GURL;

namespace host {
class Workspace;

// FaviconClient implements the the FaviconClient interface.
class FaviconClient : public favicon::FaviconClient {
 public:
  explicit FaviconClient(scoped_refptr<Workspace> workspace);
  ~FaviconClient() override;

 private:
  // favicon::FaviconClient implementation:
  bool IsNativeApplicationURL(const GURL& url) override;
  base::CancelableTaskTracker::TaskId GetFaviconForNativeApplicationURL(
      const GURL& url,
      const std::vector<int>& desired_sizes_in_pixel,
      const favicon_base::FaviconResultsCallback& callback,
      base::CancelableTaskTracker* tracker) override;

  //Workspace* workspace_;

  DISALLOW_COPY_AND_ASSIGN(FaviconClient);
};

}

#endif  // CHROME_BROWSER_FAVICON_CHROME_FAVICON_CLIENT_H_
