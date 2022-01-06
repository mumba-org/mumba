// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public enum UrlRequestStatusListenerStatus : Int {
  case Invalid = -1
  case Idle = 0
  case WaitingForStalledSocketPool = 1
  case WaitingForAvailableSocket = 2
  case WaitingForDelegate = 3
  case WaitingForCache = 4
  case DowloadingPacFile = 5
  case ResolvingProxyForUrl = 6
  case ResolvingHostInPacFile = 7
  case EstablishingProxyTunnel = 8
  case ResolvingHost = 9
  case Connection = 10
  case SslHandshake = 11
  case SendingRequest = 12
  case WaitingForResponse = 13
  case ReadingResponse = 14
}

public protocol UrlRequestStatusListener : class {
  func onStatus(_: UrlRequestStatusListenerStatus)
}
