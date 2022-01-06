// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class UrlRequestFinishedInfo {

  var reference: Cronet_RequestFinishedInfoPtr

  public init() {
    reference = Cronet_RequestFinishedInfo_Create()
  }

  deinit {
    Cronet_RequestFinishedInfo_Destroy(reference)
  }
}