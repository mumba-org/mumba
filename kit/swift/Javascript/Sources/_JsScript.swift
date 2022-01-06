// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class JsScript {
  var reference: JsScriptRef

  init(reference: JsScriptRef) {
    self.reference = reference
  }

  deinit {
    //_JavascriptScriptDestroy(reference)
  }
}

public class JsSourceScript {
  var reference: JsSourceScriptRef

  init(reference: JsSourceScriptRef) {
    self.reference = reference
  }

  deinit {
    //_JavascriptSourceScriptDestroy(reference)
  }
}

public class JsScriptOrigin {
  var reference: JsScriptOriginRef

  init(reference: JsScriptOriginRef) {
    self.reference = reference
  }

  deinit {
    //_JavascriptScriptOriginDestroy(reference)
  }
}