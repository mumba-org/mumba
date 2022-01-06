// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public class WindowButtonOrderProvider {

  public static let instance: WindowButtonOrderProvider = WindowButtonOrderProvider()

  public private(set) var leadingButtons: [FrameButton] = []
  public private(set) var trailingButtons: [FrameButton] = []

  public init() {
    trailingButtons.append(FrameButton.minimize)
    trailingButtons.append(FrameButton.maximize)
    trailingButtons.append(FrameButton.close)
  }

  public func setWindowButtonOrder(leading: [FrameButton], trailing: [FrameButton]) {
    self.leadingButtons = leading
    self.trailingButtons = trailing
  }

}