// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public enum WebAppBannerPromptReply : Int {
  case None = 0
  case Cancel
}

public class WebAppBannerClient {

    var reference: WebAppBannerClientRef

    init(reference: WebAppBannerClientRef) {
        self.reference = reference
    }

}