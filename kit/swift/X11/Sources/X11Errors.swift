// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Platform

public enum X11Error: Int32 {
  case BadRequest          = 1  /* bad request code */
  case BadValue            = 2  /* int parameter out of range */
  case BadWindow           = 3  /* parameter not a Window */
  case BadPixmap           = 4  /* parameter not a Pixmap */
  case BadAtom             = 5  /* parameter not an Atom */
  case BadCursor           = 6  /* parameter not a Cursor */
  case BadFont             = 7  /* parameter not a Font */
  case BadMatch            = 8  /* parameter mismatch */
  case BadDrawable         = 9  /* parameter not a Pixmap or Window */
  case BadAccess           = 10  /* depending on context:*/
  case BadAlloc            = 11
  case BadColor            = 12  /* no such colormap */
  case BadGC               = 13  /* parameter not a GC */
  case BadIDChoice         = 14  /* choice not in range or already used */
  case BadName             = 15  /* font or color name doesn't exist */
  case BadLength           = 16  /* Request length incorrect */
  case BadImplementation   = 17  /* server is defective */
  case FirstExtensionError = 128
  case LastExtensionError  = 255
}

public struct X11Exception : PlatformException {
  public let code: Int
  public let message: String

  // Status
  public static let InitException  = X11Exception(code: 100, message: "X11: error initializing a threaded X11 environment")
  public static let OpenDisplayException  = X11Exception(code: 101, message: "X11: error opening the default display")
  public static let WindowCreateException = X11Exception(code: 102, message: "X11: error creating the window handle")

  public init(code: Int, message: String) {
    self.code = code
    self.message = message
  }
}
