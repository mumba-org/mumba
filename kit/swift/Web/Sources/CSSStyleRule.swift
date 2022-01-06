// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class CSSRule {
 
  var reference: CSSRuleRef

  init(reference: CSSRuleRef) {
    self.reference = reference
  }

  deinit {
    _CSSRuleDestroy(reference)
  }
 
}


public class CSSRuleList {
 
  var reference: CSSRuleListRef


  init(reference: CSSRuleListRef) {
    self.reference = reference
  }

  deinit {
    _CSSRuleListDestroy(reference)
  }
 
}