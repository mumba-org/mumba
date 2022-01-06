// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_KIT_CPP_LAUNCHER_DAEMON_H_
#define MUMBA_KIT_CPP_LAUNCHER_DAEMON_H_

#include "base/run_loop.h"
#include "base/message_loop/message_loop.h"
/*
 * This is a "artificial daemon" implementation
 *
 * a) it will launch a detached mumba host process if it isnt one running
 * b) it will control the application ui window start/stop lifetime cycle with the binary
 *    working as a scoped process. if it get killed the stop on its target application
 *    gets called, and when its launched, it run the start cycle
 *
 * Its considered "artificial" because the real process it represents its the application process
 * controlled by the host process
 *
 */
class LauncherDaemon {
public:
 class Delegate {
 public:
  virtual ~Delegate() {}
  virtual void OnBeforeRun() = 0;
  virtual void OnAfterRun() = 0;
 };
 
 LauncherDaemon(Delegate* delegate, std::unique_ptr<base::MessageLoop> message_loop);
 ~LauncherDaemon();

 void Run();
 void Quit();

private:
 
 void QuitOnMainLoop();

 Delegate* delegate_;
 base::Closure quit_closure_;
 base::RunLoop main_loop_; 
 std::unique_ptr<base::MessageLoop> message_loop_;

};

#endif