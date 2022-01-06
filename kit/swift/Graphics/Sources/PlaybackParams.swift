// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public struct PlaybackParams {

  public typealias customDataRasterCallback = (_: SkiaCanvas, _: UInt32) -> Void
  public typealias didDrawOpCallback = () -> Void

  public var imageProvider: ImageProvider?
  public var originalCtm: Mat
  public var customCallback: customDataRasterCallback?
  public var didDrawOpCallback: didDrawOpCallback?

  public init(imageProvider: ImageProvider?, originalCtm: Mat) {
    self.imageProvider = imageProvider
    self.originalCtm = originalCtm
  }

  public init(imageProvider: ImageProvider?, originalCtm: Mat, customCallback: customDataRasterCallback?, didDrawOpCallback: didDrawOpCallback?) {
    self.imageProvider = imageProvider
    self.originalCtm = originalCtm
    self.customCallback = customCallback
    self.didDrawOpCallback = didDrawOpCallback
  }
}