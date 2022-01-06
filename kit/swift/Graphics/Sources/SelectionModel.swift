// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public enum VisualCursorDirection {
  case Left
  case Right
}

public enum LogicalCursorDirection {
  case Backward
  case Forward
}

public class SelectionModel {
  
  public var selection: TextRange
  public var caretAffinity: LogicalCursorDirection
  public var caretPos: Int {
    return selection.end
  }
  
  public init() {
    selection = TextRange()
    caretAffinity = .Backward
  }
  
  public init(pos: Int, affinity: LogicalCursorDirection) {
    selection = TextRange(pos: pos)
    caretAffinity = affinity
  }
  
  public init(selection: TextRange, affinity: LogicalCursorDirection) {
    self.selection = selection
    caretAffinity = affinity
  }

}

extension SelectionModel : Equatable {}

public func == (left: SelectionModel, right: SelectionModel) -> Bool {
  return (left.selection == right.selection) && (left.caretAffinity == right.caretAffinity) && (left.caretPos == right.caretPos)
}