// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_APPLICATION_LOAD_NOTIFICATION_DETAILS_H_
#define MUMBA_HOST_APPLICATION_LOAD_NOTIFICATION_DETAILS_H_

namespace host {

// The LoadNotificationDetails object contains additional details about a
// page load that has been completed.  It was created to let the MetricsService
// log page load metrics.
struct LoadNotificationDetails {
  LoadNotificationDetails(const GURL& url,
                          base::TimeDelta load_time)
      : url(url),
        load_time(load_time) {}

  // The URL loaded.
  GURL url;

  // The length of time the page load took.
  base::TimeDelta load_time;
};

}

#endif