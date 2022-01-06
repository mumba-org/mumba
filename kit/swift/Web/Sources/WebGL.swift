// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Graphics

public struct WebGLUniformLocation {
 var reference: WebGLUniformLocationRef
 init(reference: WebGLUniformLocationRef) {
   self.reference = reference
 }
}

public struct WebGLProgram {
  var reference: WebGLProgramRef
  init(reference: WebGLProgramRef) {
    self.reference = reference
  }
}

public struct WebGLTexture {
  var reference: WebGLTextureRef
  init(reference: WebGLTextureRef) {
    self.reference = reference
  }
}

public struct WebGLSampler {
  var reference: WebGLSamplerRef
  init(reference: WebGLSamplerRef) {
    self.reference = reference
  }
}

public struct WebGLBuffer {
  var reference: WebGLBufferRef
  init(reference: WebGLBufferRef) {
    self.reference = reference
  }
}

public struct WebGLVertexArrayObject {
  var reference: WebGLVertexArrayObjectRef
  init(reference: WebGLVertexArrayObjectRef) {
    self.reference = reference
  }
}

public struct WebGLShader {
  var reference: WebGLShaderRef
  init(reference: WebGLShaderRef) {
    self.reference = reference
  }
}

public struct WebGLFramebuffer {
  var reference: WebGLFramebufferRef
  init(reference: WebGLFramebufferRef) {
    self.reference = reference
  }
}

public struct WebGLRenderbuffer {
  var reference: WebGLRenderbufferRef
  init(reference: WebGLRenderbufferRef) {
    self.reference = reference
  }
}

public struct WebGLQuery {
  var reference: WebGLQueryRef
  init(reference: WebGLQueryRef) {
    self.reference = reference
  }
}

public struct WebGLSync {
  var reference: WebGLSyncRef
  init(reference: WebGLSyncRef) {
    self.reference = reference
  }
}

public struct WebGLTransformFeedback {
  var reference: WebGLTransformFeedbackRef
  init(reference: WebGLTransformFeedbackRef) {
    self.reference = reference
  }
}

public struct WebGLActiveInfo {
  var reference: WebGLActiveInfoRef
  init(reference: WebGLActiveInfoRef) {
    self.reference = reference
  }
}

public struct WebGLContextAttributes {}

public struct WebGLShaderPrecisionFormat {
  var reference: WebGLShaderPrecisionFormatRef
  init(reference: WebGLShaderPrecisionFormatRef) {
    self.reference = reference
  }
}