// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public struct RTCIceCandidate {
  public var candidate: String = String()
  public var sdpMid: String = String()
  public var sdpMLineIndex: UInt16
  //public var serializer = {attribute}
}
