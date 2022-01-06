// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public protocol LayoutManager {
  func installed(host: View)
  func uninstalled(host: View)
  func layout(host: View)
  func getPreferredSize(host: View) -> IntSize
  func getPreferredHeightForWidth(host: View, width: Int) -> Int
  func viewAdded(host: View, view: View)
  func viewRemoved(host: View, view: View)
}
