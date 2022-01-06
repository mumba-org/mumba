// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/media/audible_metrics.h"

#include <utility>

#include "base/metrics/histogram_macros.h"
#include "base/time/default_tick_clock.h"

namespace host {

AudibleMetrics::AudibleMetrics()
    : max_concurrent_audible_application_contents_in_session_(0),
      clock_(base::DefaultTickClock::GetInstance()) {}

AudibleMetrics::~AudibleMetrics() {
}

void AudibleMetrics::UpdateAudibleApplicationContentsState(
    const ApplicationContents* web_contents, bool audible) {
  bool found =
      audible_application_contents_.find(web_contents) != audible_application_contents_.end();
  if (found == audible)
    return;

  if (audible)
    AddAudibleApplicationContents(web_contents);
  else
    RemoveAudibleApplicationContents(web_contents);
}

void AudibleMetrics::SetClockForTest(const base::TickClock* test_clock) {
  clock_ = test_clock;
}

void AudibleMetrics::AddAudibleApplicationContents(const ApplicationContents* web_contents) {
  UMA_HISTOGRAM_CUSTOM_COUNTS(
      "Media.Audible.ConcurrentTabsWhenStarting", audible_application_contents_.size(),
      1, 10, 11);

  audible_application_contents_.insert(web_contents);
  if (audible_application_contents_.size() > 1 &&
      concurrent_application_contents_start_time_.is_null()) {
    concurrent_application_contents_start_time_ = clock_->NowTicks();
  }

  if (audible_application_contents_.size() >
      max_concurrent_audible_application_contents_in_session_) {
    max_concurrent_audible_application_contents_in_session_ =
        audible_application_contents_.size();

    UMA_HISTOGRAM_CUSTOM_COUNTS(
        "Media.Audible.MaxConcurrentTabsInSession",
        max_concurrent_audible_application_contents_in_session_,
        1, 10, 11);
  }
}

void AudibleMetrics::RemoveAudibleApplicationContents(const ApplicationContents* web_contents) {
  audible_application_contents_.erase(web_contents);

  if (audible_application_contents_.size() <= 1 &&
      !concurrent_application_contents_start_time_.is_null()) {
    base::TimeDelta concurrent_total_time =
        clock_->NowTicks() - concurrent_application_contents_start_time_;
    concurrent_application_contents_start_time_ = base::TimeTicks();

    UMA_HISTOGRAM_LONG_TIMES("Media.Audible.ConcurrentTabsTime",
                             concurrent_total_time);
  }
}

}  // namespace host
