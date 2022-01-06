// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_RUNTIME_MUMBA_SHIMS_SANDBOX_IMPL_H_
#define MUMBA_RUNTIME_MUMBA_SHIMS_SANDBOX_IMPL_H_

#include "base/macros.h"

class Sandbox {
public:
  static Sandbox* CreateInstance();
  static Sandbox* GetInstance();

  Sandbox();
  ~Sandbox();
  
  bool Init();
  bool Enter();
  void Leave();
  
private:
 
 bool initialized_;
 
 DISALLOW_COPY_AND_ASSIGN(Sandbox);
};


#endif