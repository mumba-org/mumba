// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_PUBLIC_BROWSER_HISTOGRAM_FETCHER_H_
#define CONTENT_PUBLIC_BROWSER_HISTOGRAM_FETCHER_H_

#include "base/callback.h"
#include "base/task_runner.h"
#include "base/time/time.h"
#include "core/shared/common/content_export.h"

namespace host {

// Fetch histogram data asynchronously from the various child processes, into
// the host process. This method is used by the metrics services in
// preparation for a log upload. It contacts all processes, and get them to
// upload to the host any/all changes to histograms.  When all changes have
// been acquired, or when the wait time expires (whichever is sooner), post the
// callback to the specified TaskRunner. Note the callback is posted exactly
// once.
CONTENT_EXPORT void FetchHistogramsAsynchronously(
    scoped_refptr<base::TaskRunner> task_runner,
    const base::Closure& callback,
    base::TimeDelta wait_time);

}  // namespace host

#endif  // CONTENT_PUBLIC_BROWSER_HISTOGRAM_FETCHER_H_
