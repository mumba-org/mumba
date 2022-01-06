// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public protocol PrefixDelegate : class {
  var rowCount: Int { get }
  var selectedRow: Int { get }
  func setSelectedRow(row: Int)
  func getTextForRow(row: Int) -> String?
};