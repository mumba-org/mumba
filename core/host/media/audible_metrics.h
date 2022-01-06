// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MEDIA_AUDIBLE_METRICS_H_
#define MUMBA_HOST_MEDIA_AUDIBLE_METRICS_H_

#include <memory>
#include <set>

#include "base/time/tick_clock.h"
#include "core/shared/common/content_export.h"

namespace host {

class ApplicationContents;

// This class handles metrics regarding audible ApplicationContents.
// It does register three different information:
// - how many ApplicationContents are audible when a ApplicationContents become audible.
// - how long multiple ApplicationContents are audible at the same time.
// - for a browsing session, how often and how many ApplicationContents get audible at
//   the same time.
class CONTENT_EXPORT AudibleMetrics {
 public:
  AudibleMetrics();
  ~AudibleMetrics();

  void UpdateAudibleApplicationContentsState(const ApplicationContents* web_contents,
                                     bool audible);

  void SetClockForTest(const base::TickClock* test_clock);

 private:
  void AddAudibleApplicationContents(const ApplicationContents* web_contents);
  void RemoveAudibleApplicationContents(const ApplicationContents* web_contents);

  base::TimeTicks concurrent_application_contents_start_time_;
  size_t max_concurrent_audible_application_contents_in_session_;
  const base::TickClock* clock_;

  std::set<const ApplicationContents*> audible_application_contents_;

  DISALLOW_COPY_AND_ASSIGN(AudibleMetrics);
};

}  // namespace host

#endif // MUMBA_HOST_MEDIA_AUDIBLE_METRICS_H_
