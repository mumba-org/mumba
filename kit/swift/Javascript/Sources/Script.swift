// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class JavascriptScript {
  var reference: JavascriptScriptRef

  init(reference: JavascriptScriptRef) {
    self.reference = reference
  }

  deinit {
    //_JavascriptScriptDestroy(reference)
  }
}

public class JavascriptSourceScript {
  var reference: JavascriptSourceScriptRef

  init(reference: JavascriptSourceScriptRef) {
    self.reference = reference
  }

  deinit {
    //_JavascriptSourceScriptDestroy(reference)
  }
}

public class JavascriptScriptOrigin {
  var reference: JavascriptScriptOriginRef

  init(reference: JavascriptScriptOriginRef) {
    self.reference = reference
  }

  deinit {
    //_JavascriptScriptOriginDestroy(reference)
  }
}