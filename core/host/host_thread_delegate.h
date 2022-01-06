// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_THREAD_DELEGATE_H__
#define MUMBA_HOST_THREAD_DELEGATE_H__

namespace host {

// A class with this type may be registered via
// HostThread::SetDelegate.
//
// If registered as such, it will schedule to run Init() before the
// message loop begins and the schedule InitAsync() as the first
// task on its message loop (after the HostThread has done its own
// initialization), and receive a CleanUp call right after the message
// loop ends (and before the HostThread has done its own clean-up).
class HostThreadDelegate {
public:
 virtual ~HostThreadDelegate() {}
 // Called prior to starting the message loop
 virtual void Init() = 0;
 // Called just after the message loop ends.
 virtual void CleanUp() = 0;
};

}

#endif