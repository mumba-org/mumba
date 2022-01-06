// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base

public struct ParentLocalSurfaceIdAllocator {
  
  private var currentLocalSurfaceId: LocalSurfaceId

  public init() {
    currentLocalSurfaceId = LocalSurfaceId(
      parent: 0, 
      child: 1, 
      token: UnguessableToken.create())
  }

  public mutating func generateId() -> LocalSurfaceId {
    currentLocalSurfaceId.parentSequenceNumber += 1
    return currentLocalSurfaceId
  }


}
