// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public enum TileMode : Int {
  /** replicate the edge color if the shader draws outside of its
   *  original bounds
   */
  case Clamp = 0

  /** repeat the shader's image horizontally and vertically */
  case Repeat = 1

  /** repeat the shader's image horizontally and vertically, alternating
   *  mirror images so that adjacent images always seam
   */
  case Mirror = 2
}

public enum ShaderType {
  case skia
  case paint
}

public protocol Shader : class {
  var type: ShaderType { get }
}