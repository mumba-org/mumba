// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public enum WebHistoryCommitType : Int {
  case StandardCommit = 0
  case BackForwardCommit = 1
  case InitialCommitInChildFrame = 2
  case HistoryInertCommit = 3
}

public enum WebHistoryLoadType : Int {
  case SameDocumentLoad = 0
  case DifferentDocumentLoad = 1
}

public class WebHistoryItem {
  
  var reference: WebHistoryItemRef

  init(reference: WebHistoryItemRef) {
    self.reference = reference
  }

  deinit {

  }

}