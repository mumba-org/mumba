// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public struct ClipboardFormatType {

}

public enum ClipboardType {
  case CopyPaste
  case Selection
  case Drag
}

public class Clipboard {

  public static var forCurrentThread: Clipboard {
    return Clipboard()
  }

  public func readText(from type: ClipboardType) -> String? {
    return nil
  }
}

// Should be a struct, as we dont need or want to pass this around.
// but unfortunatelly, structs dont have destructors as classes do

public class ScopedClipboardWriter {
  
  private var type: ClipboardType
  
  public init(_ type: ClipboardType) {
    self.type = type
  }

  //deinit {

  //}

  public func writeText(_ text: String) {
  //  var parameters = Clipboard::ObjectMapParams()
  //  parameters.append(
  //    Clipboard.ObjectMapParam(text.begin, text.end))
  //  objects[Clipboard.CBF_TEXT] = parameters
  }

}
