// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public protocol Handler {
  func onResponseStarted(request: Request, info: ResponseInfo)
  func onReadCompleted(request: Request, info: ResponseInfo, buffer: Buffer, bytesRead: UInt64)
  func onSucceeded(request: Request, info: ResponseInfo)
  func onFailed(request: Request, info: ResponseInfo, error: RequestError)
  func onCanceled(request: Request, info: ResponseInfo)
}