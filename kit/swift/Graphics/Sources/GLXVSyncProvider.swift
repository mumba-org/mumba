// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class GLXVSyncProvider {
  var reference: GLXVSyncProviderRef

  init(reference: GLXVSyncProviderRef) {
    self.reference = reference
  }

  deinit {
    _GLXVSyncProviderDestroy(reference)
  }

}

extension GLXVSyncProvider : VSyncProvider {

  public func getVSyncParameters(callback: UpdateVSyncCallback) {
    // TODO: actually implement it
    _GLXVSyncProviderGetVSyncParameters(reference)
  }
}
