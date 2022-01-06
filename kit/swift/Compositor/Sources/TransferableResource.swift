// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class TransferableResource {
  var reference: TransferableResourceRef

  init(reference: TransferableResourceRef) {
    self.reference = reference
  }

  // deinit: we are not suppose to own this reference
  //         its owned by the C++ code runtime 
}