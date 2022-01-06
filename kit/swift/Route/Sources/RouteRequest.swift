// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation

public class RouteRequest {
  
  public var callId: Int = 0
  public var readSize: Int = 0
  public var readOffset: Int = 0
  public var url: String = String()
  public var contentType: String = String()
  public var startedTime: Int64 = 0
  public var inputData: Data?

  public init() {}

  public init(callId: Int, url: String, contentType: String, startedTime: Int64) {
    self.callId = callId
    self.url = url
    self.contentType = contentType
    self.startedTime = startedTime
  }

  public init(callId: Int, url: String, contentType: String, startedTime: Int64, inputData: Data) {
    self.callId = callId
    self.url = url
    self.contentType = contentType
    self.startedTime = startedTime
    self.inputData = inputData
  }
}