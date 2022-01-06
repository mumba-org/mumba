// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_NOTIFICATION_TYPES_H_
#define MUMBA_DOMAIN_NOTIFICATION_TYPES_H_

// This file describes various types used to describe and filter notifications
// that pass through the NotificationService.
//
// Only notifications that are fired from the content module should be here. We
// should never have a notification that is fired by the embedder and listened
// to by content.
namespace domain {

enum NotificationType {
  NOTIFICATION_START = 0,

  // General -----------------------------------------------------------------

  // Special signal value to represent an interest in all notifications.
  // Not valid when posting a notification.
  NOTIFICATION_ALL = NOTIFICATION_START,

  // Indicates that a ChildProcessHost was created and its handle is now
  // available. The source will be the RenderProcessHost that corresponds to
  // the process.
  NOTIFICATION_CHILD_PROCESS_CREATED,

  // Indicates that a ChildProcessHost is destructing. The source will be the
  // ChildProcessHost that corresponds to the process.
  NOTIFICATION_CHILD_PROCESS_TERMINATED,

  // Indicates that a child process is starting to exit, such that it should
  // not be used for future navigations.  The source will be the
  // ChildProcessHost that corresponds to the process.
  NOTIFICATION_CHILD_PROCESS_CLOSING,

  // Indicates that a child process was closed (meaning it exited, but the
  // RenderProcessHost might be reused).  The source will be the corresponding
  // RenderProcessHost.  The details will be a DomainClosedDetails struct.
  // This may get sent along with CHILD_PROCESS_TERMINATED.
  NOTIFICATION_CHILD_PROCESS_CLOSED,
  
  // Custom notifications used by the embedder should start from here.
  NOTIFICATION_END,
};

}  // namespace switch
#endif  // MUMBA_DOMAIN_NOTIFICATION_TYPES_H_
