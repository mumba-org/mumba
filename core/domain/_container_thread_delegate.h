// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_DOMAIN_THREAD_DELEGATE_H__
#define MUMBA_DOMAIN_DOMAIN_THREAD_DELEGATE_H__

namespace domain {

// A class with this type may be registered via
// DomainThread::SetDelegate.
//
// If registered as such, it will schedule to run Init() before the
// message loop begins and the schedule InitAsync() as the first
// task on its message loop (after the DomainThread has done its own
// initialization), and receive a CleanUp call right after the message
// loop ends (and before the DomainThread has done its own clean-up).
class DomainThreadDelegate {
public:
 virtual ~DomainThreadDelegate() {}
 // Called prior to starting the message loop
 virtual void Init() = 0;
 // Called just after the message loop ends.
 virtual void CleanUp() = 0;
};

}

#endif