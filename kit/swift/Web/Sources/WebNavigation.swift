// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public enum WebNavigationType : Int {
  case LinkClicked = 0
  case FormSubmitted = 1
  case BackForward = 2
  case Reload = 3
  case FormResubmitted = 4
  case Other = 5
}

public enum WebNavigationPolicy : Int {
  case Ignore = 0
  case Download = 1
  case CurrentTab = 2
  case NewBackgroundTab = 3
  case NewForegroundTab = 4
  case NewWindow = 5
  case NewPopup = 6
  case HandledByClient = 7
}

public enum WebCustomHandlersState : Int {
    case New = 0
    case Registered = 1
    case Declined = 2
}