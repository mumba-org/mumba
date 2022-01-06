// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class FrameSinkManagerImpl {

  internal var reference: FrameSinkManagerRef
  
  public init() {
    reference = _FrameSinkManagerImplCreate()!
  }

  internal init(reference: FrameSinkManagerRef) {
    self.reference = reference
  }

  deinit {
    _FrameSinkManagerImplDestroy(reference)
  }

  public func registerBeginFrameSource(beginFrameSource: BeginFrameSource,
                                       frameSinkId: FrameSinkId) {
    _FrameSinkManagerImplRegisterBeginFrameSource(reference, beginFrameSource.reference, frameSinkId.clientId, frameSinkId.sinkId)
  }

  public func setLocalClient(_ hostFrameSinkManager: HostFrameSinkManager) {
    _FrameSinkManagerImplSetLocalClient(reference, hostFrameSinkManager.reference)
  }

}