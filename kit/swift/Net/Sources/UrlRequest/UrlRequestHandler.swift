// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public protocol UrlRequestHandler {
  mutating func onRedirectReceived(request: UrlRequest, info: UrlResponseInfo, locationUrl: String)
  mutating func onResponseStarted(request: UrlRequest, info: UrlResponseInfo)
  mutating func onReadCompleted(request: UrlRequest, info: UrlResponseInfo, buffer: UrlBuffer, bytesRead: UInt64)
  mutating func onSucceeded(request: UrlRequest, info: UrlResponseInfo)
  mutating func onFailed(request: UrlRequest, info: UrlResponseInfo, error: UrlRequestError)
  mutating func onCanceled(request: UrlRequest, info: UrlResponseInfo)
} 