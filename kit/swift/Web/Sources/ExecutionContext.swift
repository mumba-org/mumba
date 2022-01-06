// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public struct ExecutionContext {
    
    public var reference: ExecutionContextRef

    init(reference: ExecutionContextRef) {
        self.reference = reference
    }


}