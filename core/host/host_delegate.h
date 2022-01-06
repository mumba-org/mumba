// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_HOST_DELEGATE_H__
#define MUMBA_HOST_HOST_DELEGATE_H__

namespace host {

class HostDelegate {
public:
 virtual ~HostDelegate() {}
 virtual void PerformShutdown() = 0;
};

} // host 




#endif