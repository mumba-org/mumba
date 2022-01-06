// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_MAIN_RUNNER_H__
#define MUMBA_HOST_MAIN_RUNNER_H__

#include <memory>

#include "base/macros.h"
#include "base/at_exit.h"
#include "core/common/main_params.h"

namespace host {
class HostMainLoop;
class NotificationServiceImpl;

class HostMainRunner {
public:
 static bool ExitedMainMessageLoop();

 HostMainRunner();
 ~HostMainRunner();

 int Initialize(const common::MainParams& params);
 int Run();
 void Shutdown();

private:
 //class ShadowingAtExitManager;
 // True if we have started to initialize the runner.
 bool initialization_started_;
 // True if the runner has been shut down.
 bool is_shutdown_;

 std::unique_ptr<HostMainLoop> main_loop_;

 std::unique_ptr<base::AtExitManager> exit_manager_;

 std::unique_ptr<NotificationServiceImpl> notification_service_;

 DISALLOW_COPY_AND_ASSIGN(HostMainRunner);
};

}

#endif
