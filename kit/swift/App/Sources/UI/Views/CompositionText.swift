// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public struct CompositionUnderline {
  public var startOffset: UInt32
  public var endOffset: UInt32
  public var color: Color
  public var thick: Bool
  public var backgroundColor: Color
}

public typealias CompositionUnderlines = [CompositionUnderline]

public struct CompositionText {
  public var text: String
  public var underlines: CompositionUnderlines
  public var selection: TextRange
}
