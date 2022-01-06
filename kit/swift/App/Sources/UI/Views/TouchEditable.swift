// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public protocol TouchEditable : SimpleMenuModelDelegate {
  // Gets the bounds of the client view in its local coordinates.
  var bounds: IntRect { get }

  // Gets the NativeView hosting the client.
  //var nativeView: NativeView

  // Select everything between start and end (points are in view's local
  // coordinate system). |start| is the logical start and |end| is the logical
  // end of selection. Visually, |start| may lie after |end|.
  func selectRect(start: IntPoint, end: IntPoint)

  // Move the caret to |point|. |point| is in local coordinates.
  func moveCaret(to: IntPoint)

  // Gets the end points of the current selection. The end points |anchor| and
  // |focus| must be the cursor rect for the logical start and logical end of
  // selection (in local coordinates):
  // ____________________________________
  // | textfield with |selected text|   |
  // ------------------------------------
  //                  ^anchor       ^focus
  //
  // Visually, anchor could be to the right of focus in the figure above - it
  // depends on the selection direction.
  func getSelectionEndPoints(anchor: inout SelectionBound,
                             focus: inout SelectionBound)

  // Converts a point to/from screen coordinates from/to client view.
  func convertPointToScreen(point: inout IntPoint)
  func convertPointFromScreen(point: inout IntPoint)

  // Returns true if the editable draws its own handles (hence, the
  // TouchEditingControllerDeprecated need not draw handles).
  func drawsHandles() -> Bool

  // Tells the editable to open context menu.
  func openContextMenu(anchor: IntPoint)

  // Tells the editable to end touch editing and destroy touch selection
  // controller it owns.
  func destroyTouchSelection()
}