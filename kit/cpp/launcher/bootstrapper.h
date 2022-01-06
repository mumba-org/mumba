// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_KIT_CPP_LAUNCHER_BOOTSTRAPPER_H_
#define MUMBA_KIT_CPP_LAUNCHER_BOOTSTRAPPER_H_

#include "base/command_line.h"
/*
 * The bootstrapper class have the special task of checking
 * if everything is set before running the commands and if not
 * make sure everything is in place.
 * Its the application "terraform" step
 */ 

class Bootstrapper {
public:
 Bootstrapper();
 ~Bootstrapper();

 bool DoBootstrap(const base::CommandLine::StringVector& args);
};

#endif