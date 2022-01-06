// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Compositor

public protocol ExternalBeginFrameClient {
  func onDisplayDidFinishFrame(ack: BeginFrameAck)
  func onNeedsExternalBeginFrames(needsBeginFrames: Bool)
}