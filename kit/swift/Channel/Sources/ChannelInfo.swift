// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation
import MumbaShims

public struct ChannelInfo {
  public var uuid: String
  public var scheme: String
  public var name: String

  public init(uuid: String, scheme: String, name: String) {
    self.uuid = uuid
    self.name = name
    self.scheme = scheme
  }

  public init(scheme: String, name: String) {
    uuid = String()
    self.name = name
    self.scheme = scheme
  }
}