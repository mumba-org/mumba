// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class WebSecurityOrigin {
  
  var reference: WebSecurityOriginRef

  init(reference: WebSecurityOriginRef) {
    self.reference = reference
  }

  deinit {
    _WebSecurityOriginDestroy(reference)
  }

}