// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_WIN_JUMPLIST_FACTORY_H_
#define CHROME_BROWSER_WIN_JUMPLIST_FACTORY_H_

#include "base/memory/singleton.h"

namespace host {
class JumpList;
class JumpListFactory {
 public:
  JumpListFactory();
  ~JumpListFactory();

  static JumpList* Get();

  static JumpListFactory* GetInstance();

 private:
  
  JumpList* jumplist() {
    return jumplist_.get();
  }
  
  std::unique_ptr<JumpList> jumplist_;
};

}

#endif  // CHROME_BROWSER_WIN_JUMPLIST_FACTORY_H_
