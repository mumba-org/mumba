// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_INDEX_INDEX_BACKEND_H_
#define MUMBA_HOST_INDEX_INDEX_BACKEND_H_

#include "base/macros.h"

namespace host {

/*
 * The index backend, only handled by a backend thread
 */
class IndexBackend {
public:
  IndexBackend();
  ~IndexBackend();
    
private:
 DISALLOW_COPY_AND_ASSIGN(IndexBackend);
};

}

#endif