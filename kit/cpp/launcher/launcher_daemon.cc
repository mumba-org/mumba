// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "launcher/launcher_daemon.h"

#include "base/callback.h"
#include "base/bind.h"
#include "base/task_runner.h"

LauncherDaemon::LauncherDaemon(Delegate* delegate, std::unique_ptr<base::MessageLoop> message_loop):
 delegate_(delegate),
 message_loop_(std::move(message_loop)) {

}

LauncherDaemon::~LauncherDaemon() {

}

void LauncherDaemon::Run() {
  delegate_->OnBeforeRun();
  quit_closure_ = main_loop_.QuitClosure();
  main_loop_.Run();
  delegate_->OnAfterRun();
}

void LauncherDaemon::Quit() {
  message_loop_->task_runner()->PostTask(
    FROM_HERE,
    base::BindOnce(&LauncherDaemon::QuitOnMainLoop, base::Unretained(this)));
}

void LauncherDaemon::QuitOnMainLoop() {
  std::move(quit_closure_).Run();
}