// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public func getDefaultWindowMask(size: IntSize, scale: Float, windowMask: Path) {
  let width = size.width / Int(scale)
  let height = size.height / Int(scale)

  windowMask.moveTo(x: 0, y: 3)
  windowMask.lineTo(x: 1, y: 3)
  windowMask.lineTo(x: 1, y: 1)
  windowMask.lineTo(x: 3, y: 1)
  windowMask.lineTo(x: 3, y: 0)

  windowMask.lineTo(x: width - 3, y: 0)
  windowMask.lineTo(x: width - 3, y: 1)
  windowMask.lineTo(x: width - 1, y: 1)
  windowMask.lineTo(x: width - 1, y: 3)
  windowMask.lineTo(x: width, y: 3)

  windowMask.lineTo(x: width, y: height - 3)
  windowMask.lineTo(x: width - 1, y: height - 3)
  windowMask.lineTo(x: width - 1, y: height - 1)
  windowMask.lineTo(x: width - 3, y: height - 1)
  windowMask.lineTo(x: width - 3, y: height)

  windowMask.lineTo(x: 3, y: height)
  windowMask.lineTo(x: 3, y: height - 1)
  windowMask.lineTo(x: 1, y: height - 1)
  windowMask.lineTo(x: 1, y: height - 3)
  windowMask.lineTo(x: 0, y: height - 3)

  windowMask.close()

  let m = Mat()
  m.scale(x: Double(scale), y: Double(scale))
  windowMask.transform(matrix: m)
}