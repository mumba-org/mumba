// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public struct WebBlobInfo {
  public var isFile: Bool = false
  public var uuid: String = String()
  public var type: String = String()
  public var size: Int64 = 0
  public var filePath: String = String()
  public var fileName: String = String()
  public var lastModified: Double = 0.0
}