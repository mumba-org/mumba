// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Graphics

public typealias GLenum = UInt32
public typealias GLboolean = UInt8
public typealias GLbitfield = UInt32
public typealias GLbyte = Int8
public typealias GLshort = Int16
public typealias GLint = Int32
public typealias GLsizei = Int32
public typealias GLintptr = Int
public typealias GLsizeiptr = Int
public typealias GLubyte = UInt8
public typealias GLushort = UInt16
public typealias GLuint = UInt32
public typealias Glfloat = Float
public typealias GLclampf = Float
public typealias GLint64 = Int64
public typealias GLuint64 = UInt64
 
public class WebGLRenderingContext {

  public let DEPTH_BUFFER_BIT: GLenum              = 0x00000100
  public let STENCIL_BUFFER_BIT: GLenum            = 0x00000400
  public let COLOR_BUFFER_BIT: GLenum              = 0x00004000

  /* BeginMode */
  public let POINTS: GLenum                        = 0x0000
  public let LINES: GLenum                         = 0x0001
  public let LINE_LOOP: GLenum                     = 0x0002
  public let LINE_STRIP: GLenum                    = 0x0003
  public let TRIANGLES: GLenum                     = 0x0004
  public let TRIANGLE_STRIP: GLenum                = 0x0005
  public let TRIANGLE_FAN: GLenum                  = 0x0006

  /* AlphaFunction (not supported in ES20) */
  /*      NEVER */
  /*      LESS */
  /*      EQUAL */
  /*      LEQUAL */
  /*      GREATER */
  /*      NOTEQUAL */
  /*      GEQUAL */
  /*      ALWAYS */

  /* BlendingFactorDest */
  public let ZERO: GLenum                           = 0
  public let ONE: GLenum                            = 1
  public let SRC_COLOR: GLenum                      = 0x0300
  public let ONE_MINUS_SRC_COLOR: GLenum            = 0x0301
  public let SRC_ALPHA: GLenum                      = 0x0302
  public let ONE_MINUS_SRC_ALPHA: GLenum            = 0x0303
  public let DST_ALPHA: GLenum                      = 0x0304
  public let ONE_MINUS_DST_ALPHA: GLenum            = 0x0305

  /* BlendingFactorSrc */
  /*      ZERO */
  /*      ONE */
  public let DST_COLOR: GLenum                      = 0x0306
  public let ONE_MINUS_DST_COLOR: GLenum            = 0x0307
  public let SRC_ALPHA_SATURATE: GLenum             = 0x0308
  /*      SRC_ALPHA */
  /*      ONE_MINUS_SRC_ALPHA */
  /*      DST_ALPHA */
  /*      ONE_MINUS_DST_ALPHA */

  /* BlendEquationSeparate */
  public let FUNC_ADD: GLenum                       = 0x8006
  public let BLEND_EQUATION: GLenum                 = 0x8009
  public let BLEND_EQUATION_RGB: GLenum             = 0x8009   /* same as BLEND_EQUATION */
  public let BLEND_EQUATION_ALPHA: GLenum           = 0x883D

  /* BlendSubtract */
  public let FUNC_SUBTRACT: GLenum                  = 0x800A
  public let FUNC_REVERSE_SUBTRACT: GLenum          = 0x800B

  /* Separate Blend Functions */
  public let BLEND_DST_RGB: GLenum                  = 0x80C8
  public let BLEND_SRC_RGB: GLenum                  = 0x80C9
  public let BLEND_DST_ALPHA: GLenum                = 0x80CA
  public let BLEND_SRC_ALPHA: GLenum                = 0x80CB
  public let CONSTANT_COLOR: GLenum                 = 0x8001
  public let ONE_MINUS_CONSTANT_COLOR: GLenum       = 0x8002
  public let CONSTANT_ALPHA: GLenum                 = 0x8003
  public let ONE_MINUS_CONSTANT_ALPHA: GLenum       = 0x8004
  public let BLEND_COLOR: GLenum                    = 0x8005

  /* Buffer Objects */
  public let ARRAY_BUFFER: GLenum                   = 0x8892
  public let ELEMENT_ARRAY_BUFFER: GLenum           = 0x8893
  public let ARRAY_BUFFER_BINDING: GLenum           = 0x8894
  public let ELEMENT_ARRAY_BUFFER_BINDING: GLenum   = 0x8895

  public let STREAM_DRAW: GLenum                    = 0x88E0
  public let STATIC_DRAW: GLenum                    = 0x88E4
  public let DYNAMIC_DRAW: GLenum                   = 0x88E8

  public let BUFFER_SIZE: GLenum                    = 0x8764
  public let BUFFER_USAGE: GLenum                   = 0x8765

  public let CURRENT_VERTEX_ATTRIB: GLenum          = 0x8626

  /* CullFaceMode */
  public let FRONT: GLenum                          = 0x0404
  public let BACK: GLenum                           = 0x0405
  public let FRONT_AND_BACK: GLenum                 = 0x0408

  /* DepthFunction */
  /*      NEVER */
  /*      LESS */
  /*      EQUAL */
  /*      LEQUAL */
  /*      GREATER */
  /*      NOTEQUAL */
  /*      GEQUAL */
  /*      ALWAYS */

  /* EnableCap */
  public let TEXTURE_2D: GLenum                     = 0x0DE1
  public let CULL_FACE: GLenum                      = 0x0B44
  public let BLEND: GLenum                          = 0x0BE2
  public let DITHER: GLenum                         = 0x0BD0
  public let STENCIL_TEST: GLenum                   = 0x0B90
  public let DEPTH_TEST: GLenum                     = 0x0B71
  public let SCISSOR_TEST: GLenum                   = 0x0C11
  public let POLYGON_OFFSET_FILL: GLenum            = 0x8037
  public let SAMPLE_ALPHA_TO_COVERAGE: GLenum       = 0x809E
  public let SAMPLE_COVERAGE: GLenum                = 0x80A0

  /* ErrorCode */
  public let NO_ERROR: GLenum                       = 0
  public let INVALID_ENUM: GLenum                   = 0x0500
  public let INVALID_VALUE: GLenum                  = 0x0501
  public let INVALID_OPERATION: GLenum              = 0x0502
  public let OUT_OF_MEMORY: GLenum                  = 0x0505

  /* FrontFaceDirection */
  public let CW: GLenum                             = 0x0900
  public let CCW: GLenum                            = 0x0901

  /* GetPName */
  public let LINE_WIDTH: GLenum                     = 0x0B21
  public let ALIASED_POINT_SIZE_RANGE: GLenum       = 0x846D
  public let ALIASED_LINE_WIDTH_RANGE: GLenum       = 0x846E
  public let CULL_FACE_MODE: GLenum                 = 0x0B45
  public let FRONT_FACE: GLenum                     = 0x0B46
  public let DEPTH_RANGE: GLenum                    = 0x0B70
  public let DEPTH_WRITEMASK: GLenum                = 0x0B72
  public let DEPTH_CLEAR_VALUE: GLenum              = 0x0B73
  public let DEPTH_FUNC: GLenum                     = 0x0B74
  public let STENCIL_CLEAR_VALUE: GLenum            = 0x0B91
  public let STENCIL_FUNC: GLenum                   = 0x0B92
  public let STENCIL_FAIL: GLenum                   = 0x0B94
  public let STENCIL_PASS_DEPTH_FAIL: GLenum        = 0x0B95
  public let STENCIL_PASS_DEPTH_PASS: GLenum        = 0x0B96
  public let STENCIL_REF: GLenum                    = 0x0B97
  public let STENCIL_VALUE_MASK: GLenum             = 0x0B93
  public let STENCIL_WRITEMASK: GLenum              = 0x0B98
  public let STENCIL_BACK_FUNC: GLenum              = 0x8800
  public let STENCIL_BACK_FAIL: GLenum              = 0x8801
  public let STENCIL_BACK_PASS_DEPTH_FAIL: GLenum   = 0x8802
  public let STENCIL_BACK_PASS_DEPTH_PASS: GLenum   = 0x8803
  public let STENCIL_BACK_REF: GLenum               = 0x8CA3
  public let STENCIL_BACK_VALUE_MASK: GLenum        = 0x8CA4
  public let STENCIL_BACK_WRITEMASK: GLenum         = 0x8CA5
  public let VIEWPORT: GLenum                       = 0x0BA2
  public let SCISSOR_BOX: GLenum                    = 0x0C10
  /*      SCISSOR_TEST */
  public let COLOR_CLEAR_VALUE: GLenum              = 0x0C22
  public let COLOR_WRITEMASK: GLenum                = 0x0C23
  public let UNPACK_ALIGNMENT: GLenum               = 0x0CF5
  public let PACK_ALIGNMENT: GLenum                 = 0x0D05
  public let MAX_TEXTURE_SIZE: GLenum               = 0x0D33
  public let MAX_VIEWPORT_DIMS: GLenum              = 0x0D3A
  public let SUBPIXEL_BITS: GLenum                  = 0x0D50
  public let RED_BITS: GLenum                       = 0x0D52
  public let GREEN_BITS: GLenum                     = 0x0D53
  public let BLUE_BITS: GLenum                      = 0x0D54
  public let ALPHA_BITS: GLenum                     = 0x0D55
  public let DEPTH_BITS: GLenum                     = 0x0D56
  public let STENCIL_BITS: GLenum                   = 0x0D57
  public let POLYGON_OFFSET_UNITS: GLenum           = 0x2A00
  /*      POLYGON_OFFSET_FILL */
  public let POLYGON_OFFSET_FACTOR: GLenum          = 0x8038
  public let TEXTURE_BINDING_2D: GLenum             = 0x8069
  public let SAMPLE_BUFFERS: GLenum                 = 0x80A8
  public let SAMPLES: GLenum                        = 0x80A9
  public let SAMPLE_COVERAGE_VALUE: GLenum          = 0x80AA
  public let SAMPLE_COVERAGE_INVERT: GLenum         = 0x80AB

  /* GetTextureParameter */
  /*      TEXTURE_MAG_FILTER */
  /*      TEXTURE_MIN_FILTER */
  /*      TEXTURE_WRAP_S */
  /*      TEXTURE_WRAP_T */

  public let COMPRESSED_TEXTURE_FORMATS: GLenum     = 0x86A3

  /* HintMode */
  public let DONT_CARE: GLenum                      = 0x1100
  public let FASTEST: GLenum                        = 0x1101
  public let NICEST: GLenum                         = 0x1102

  /* HintTarget */
  public let GENERATE_MIPMAP_HINT: GLenum            = 0x8192

  /* DataType */
  public let BYTE: GLenum                           = 0x1400
  public let UNSIGNED_BYTE: GLenum                  = 0x1401
  public let SHORT: GLenum                          = 0x1402
  public let UNSIGNED_SHORT: GLenum                 = 0x1403
  public let INT: GLenum                            = 0x1404
  public let UNSIGNED_INT: GLenum                   = 0x1405
  public let FLOAT: GLenum                          = 0x1406

  /* PixelFormat */
  public let DEPTH_COMPONENT: GLenum                = 0x1902
  public let ALPHA: GLenum                          = 0x1906
  public let RGB: GLenum                            = 0x1907
  public let RGBA: GLenum                           = 0x1908
  public let LUMINANCE: GLenum                      = 0x1909
  public let LUMINANCE_ALPHA: GLenum                = 0x190A

  /* PixelType */
  /*      UNSIGNED_BYTE */
  public let UNSIGNED_SHORT_4_4_4_4: GLenum         = 0x8033
  public let UNSIGNED_SHORT_5_5_5_1: GLenum         = 0x8034
  public let UNSIGNED_SHORT_5_6_5: GLenum           = 0x8363

  /* Shaders */
  public let FRAGMENT_SHADER: GLenum                  = 0x8B30
  public let VERTEX_SHADER: GLenum                    = 0x8B31
  public let MAX_VERTEX_ATTRIBS: GLenum               = 0x8869
  public let MAX_VERTEX_UNIFORM_VECTORS: GLenum       = 0x8DFB
  public let MAX_VARYING_VECTORS: GLenum              = 0x8DFC
  public let MAX_COMBINED_TEXTURE_IMAGE_UNITS: GLenum = 0x8B4D
  public let MAX_VERTEX_TEXTURE_IMAGE_UNITS: GLenum   = 0x8B4C
  public let MAX_TEXTURE_IMAGE_UNITS: GLenum          = 0x8872
  public let MAX_FRAGMENT_UNIFORM_VECTORS: GLenum     = 0x8DFD
  public let SHADER_TYPE: GLenum                      = 0x8B4F
  public let DELETE_STATUS: GLenum                    = 0x8B80
  public let LINK_STATUS: GLenum                      = 0x8B82
  public let VALIDATE_STATUS: GLenum                  = 0x8B83
  public let ATTACHED_SHADERS: GLenum                 = 0x8B85
  public let ACTIVE_UNIFORMS: GLenum                  = 0x8B86
  public let ACTIVE_ATTRIBUTES: GLenum                = 0x8B89
  public let SHADING_LANGUAGE_VERSION: GLenum         = 0x8B8C
  public let CURRENT_PROGRAM: GLenum                  = 0x8B8D

  /* StencilFunction */
  public let NEVER: GLenum                          = 0x0200
  public let LESS: GLenum                           = 0x0201
  public let EQUAL: GLenum                          = 0x0202
  public let LEQUAL: GLenum                         = 0x0203
  public let GREATER: GLenum                        = 0x0204
  public let NOTEQUAL: GLenum                       = 0x0205
  public let GEQUAL: GLenum                         = 0x0206
  public let ALWAYS: GLenum                         = 0x0207

  /* StencilOp */
  /*      ZERO */
  public let KEEP: GLenum                           = 0x1E00
  public let REPLACE: GLenum                        = 0x1E01
  public let INCR: GLenum                           = 0x1E02
  public let DECR: GLenum                           = 0x1E03
  public let INVERT: GLenum                         = 0x150A
  public let INCR_WRAP: GLenum                      = 0x8507
  public let DECR_WRAP: GLenum                      = 0x8508

  /* StringName */
  public let VENDOR: GLenum                         = 0x1F00
  public let RENDERER: GLenum                       = 0x1F01
  public let VERSION: GLenum                        = 0x1F02

  /* TextureMagFilter */
  public let NEAREST: GLenum                        = 0x2600
  public let LINEAR: GLenum                         = 0x2601

  /* TextureMinFilter */
  /*      NEAREST */
  /*      LINEAR */
  public let NEAREST_MIPMAP_NEAREST: GLenum         = 0x2700
  public let LINEAR_MIPMAP_NEAREST: GLenum          = 0x2701
  public let NEAREST_MIPMAP_LINEAR: GLenum          = 0x2702
  public let LINEAR_MIPMAP_LINEAR: GLenum           = 0x2703

  /* TextureParameterName */
  public let TEXTURE_MAG_FILTER: GLenum             = 0x2800
  public let TEXTURE_MIN_FILTER: GLenum             = 0x2801
  public let TEXTURE_WRAP_S: GLenum                 = 0x2802
  public let TEXTURE_WRAP_T: GLenum                 = 0x2803

  /* TextureTarget */
  /*      TEXTURE_2D */
  public let TEXTURE: GLenum                        = 0x1702

  public let TEXTURE_CUBE_MAP: GLenum               = 0x8513
  public let TEXTURE_BINDING_CUBE_MAP: GLenum       = 0x8514
  public let TEXTURE_CUBE_MAP_POSITIVE_X: GLenum    = 0x8515
  public let TEXTURE_CUBE_MAP_NEGATIVE_X: GLenum    = 0x8516
  public let TEXTURE_CUBE_MAP_POSITIVE_Y: GLenum    = 0x8517
  public let TEXTURE_CUBE_MAP_NEGATIVE_Y: GLenum    = 0x8518
  public let TEXTURE_CUBE_MAP_POSITIVE_Z: GLenum    = 0x8519
  public let TEXTURE_CUBE_MAP_NEGATIVE_Z: GLenum    = 0x851A
  public let MAX_CUBE_MAP_TEXTURE_SIZE: GLenum      = 0x851C

  /* TextureUnit */
  public let TEXTURE0: GLenum                       = 0x84C0
  public let TEXTURE1: GLenum                       = 0x84C1
  public let TEXTURE2: GLenum                       = 0x84C2
  public let TEXTURE3: GLenum                       = 0x84C3
  public let TEXTURE4: GLenum                       = 0x84C4
  public let TEXTURE5: GLenum                       = 0x84C5
  public let TEXTURE6: GLenum                       = 0x84C6
  public let TEXTURE7: GLenum                       = 0x84C7
  public let TEXTURE8: GLenum                       = 0x84C8
  public let TEXTURE9: GLenum                       = 0x84C9
  public let TEXTURE10: GLenum                      = 0x84CA
  public let TEXTURE11: GLenum                      = 0x84CB
  public let TEXTURE12: GLenum                      = 0x84CC
  public let TEXTURE13: GLenum                      = 0x84CD
  public let TEXTURE14: GLenum                      = 0x84CE
  public let TEXTURE15: GLenum                      = 0x84CF
  public let TEXTURE16: GLenum                      = 0x84D0
  public let TEXTURE17: GLenum                      = 0x84D1
  public let TEXTURE18: GLenum                      = 0x84D2
  public let TEXTURE19: GLenum                      = 0x84D3
  public let TEXTURE20: GLenum                      = 0x84D4
  public let TEXTURE21: GLenum                      = 0x84D5
  public let TEXTURE22: GLenum                      = 0x84D6
  public let TEXTURE23: GLenum                      = 0x84D7
  public let TEXTURE24: GLenum                      = 0x84D8
  public let TEXTURE25: GLenum                      = 0x84D9
  public let TEXTURE26: GLenum                      = 0x84DA
  public let TEXTURE27: GLenum                      = 0x84DB
  public let TEXTURE28: GLenum                      = 0x84DC
  public let TEXTURE29: GLenum                      = 0x84DD
  public let TEXTURE30: GLenum                      = 0x84DE
  public let TEXTURE31: GLenum                      = 0x84DF
  public let ACTIVE_TEXTURE: GLenum                 = 0x84E0

  /* TextureWrapMode */
  public let REPEAT: GLenum                         = 0x2901
  public let CLAMP_TO_EDGE: GLenum                  = 0x812F
  public let MIRRORED_REPEAT: GLenum                = 0x8370

  /* Uniform Types */
  public let FLOAT_VEC2: GLenum                     = 0x8B50
  public let FLOAT_VEC3: GLenum                     = 0x8B51
  public let FLOAT_VEC4: GLenum                     = 0x8B52
  public let INT_VEC2: GLenum                       = 0x8B53
  public let INT_VEC3: GLenum                       = 0x8B54
  public let INT_VEC4: GLenum                       = 0x8B55
  public let BOOL: GLenum                           = 0x8B56
  public let BOOL_VEC2: GLenum                      = 0x8B57
  public let BOOL_VEC3: GLenum                      = 0x8B58
  public let BOOL_VEC4: GLenum                      = 0x8B59
  public let FLOAT_MAT2: GLenum                     = 0x8B5A
  public let FLOAT_MAT3: GLenum                     = 0x8B5B
  public let FLOAT_MAT4: GLenum                     = 0x8B5C
  public let SAMPLER_2D: GLenum                     = 0x8B5E
  public let SAMPLER_CUBE: GLenum                   = 0x8B60

  /* Vertex Arrays */
  public let VERTEX_ATTRIB_ARRAY_ENABLED: GLenum        = 0x8622
  public let VERTEX_ATTRIB_ARRAY_SIZE: GLenum           = 0x8623
  public let VERTEX_ATTRIB_ARRAY_STRIDE: GLenum         = 0x8624
  public let VERTEX_ATTRIB_ARRAY_TYPE: GLenum           = 0x8625
  public let VERTEX_ATTRIB_ARRAY_NORMALIZED: GLenum     = 0x886A
  public let VERTEX_ATTRIB_ARRAY_POINTER: GLenum        = 0x8645
  public let VERTEX_ATTRIB_ARRAY_BUFFER_BINDING: GLenum = 0x889F

  /* Read Format */
  public let IMPLEMENTATION_COLOR_READ_TYPE: GLenum   = 0x8B9A
  public let IMPLEMENTATION_COLOR_READ_FORMAT: GLenum = 0x8B9B

  /* Shader Source */
  public let COMPILE_STATUS: GLenum                 = 0x8B81

  /* Shader Precision-Specified Types */
  public let LOW_FLOAT: GLenum                      = 0x8DF0
  public let MEDIUM_FLOAT: GLenum                   = 0x8DF1
  public let HIGH_FLOAT: GLenum                     = 0x8DF2
  public let LOW_INT: GLenum                        = 0x8DF3
  public let MEDIUM_INT: GLenum                     = 0x8DF4
  public let HIGH_INT: GLenum                       = 0x8DF5

  /* Framebuffer Object. */
  public let FRAMEBUFFER: GLenum                    = 0x8D40
  public let RENDERBUFFER: GLenum                   = 0x8D41

  public let RGBA4: GLenum                          = 0x8056
  public let RGB5_A1: GLenum                        = 0x8057
  public let RGB565: GLenum                         = 0x8D62
  public let DEPTH_COMPONENT16: GLenum              = 0x81A5
  public let STENCIL_INDEX8: GLenum                 = 0x8D48
  public let DEPTH_STENCIL: GLenum                  = 0x84F9

  public let RENDERBUFFER_WIDTH: GLenum             = 0x8D42
  public let RENDERBUFFER_HEIGHT: GLenum            = 0x8D43
  public let RENDERBUFFER_INTERNAL_FORMAT: GLenum   = 0x8D44
  public let RENDERBUFFER_RED_SIZE: GLenum          = 0x8D50
  public let RENDERBUFFER_GREEN_SIZE: GLenum        = 0x8D51
  public let RENDERBUFFER_BLUE_SIZE: GLenum         = 0x8D52
  public let RENDERBUFFER_ALPHA_SIZE: GLenum        = 0x8D53
  public let RENDERBUFFER_DEPTH_SIZE: GLenum        = 0x8D54
  public let RENDERBUFFER_STENCIL_SIZE: GLenum      = 0x8D55

  public let FRAMEBUFFER_ATTACHMENT_OBJECT_TYPE: GLenum           = 0x8CD0
  public let FRAMEBUFFER_ATTACHMENT_OBJECT_NAME: GLenum           = 0x8CD1
  public let FRAMEBUFFER_ATTACHMENT_TEXTURE_LEVEL: GLenum         = 0x8CD2
  public let FRAMEBUFFER_ATTACHMENT_TEXTURE_CUBE_MAP_FACE: GLenum = 0x8CD3

  public let COLOR_ATTACHMENT0: GLenum              = 0x8CE0
  public let DEPTH_ATTACHMENT: GLenum               = 0x8D00
  public let STENCIL_ATTACHMENT: GLenum             = 0x8D20
  public let DEPTH_STENCIL_ATTACHMENT: GLenum       = 0x821A

  public let NONE: GLenum                           = 0

  public let FRAMEBUFFER_COMPLETE: GLenum                      = 0x8CD5
  public let FRAMEBUFFER_INCOMPLETE_ATTACHMENT: GLenum         = 0x8CD6
  public let FRAMEBUFFER_INCOMPLETE_MISSING_ATTACHMENT: GLenum = 0x8CD7
  public let FRAMEBUFFER_INCOMPLETE_DIMENSIONS: GLenum         = 0x8CD9
  public let FRAMEBUFFER_UNSUPPORTED: GLenum                   = 0x8CDD

  public let FRAMEBUFFER_BINDING: GLenum            = 0x8CA6
  public let RENDERBUFFER_BINDING: GLenum           = 0x8CA7
  public let MAX_RENDERBUFFER_SIZE: GLenum          = 0x84E8

  public let INVALID_FRAMEBUFFER_OPERATION: GLenum  = 0x0506

  /* WebGL-specific enums */
  public let UNPACK_FLIP_Y_WEBGL: GLenum                = 0x9240
  public let UNPACK_PREMULTIPLY_ALPHA_WEBGL: GLenum     = 0x9241
  public let CONTEXT_LOST_WEBGL: GLenum                 = 0x9242
  public let UNPACK_COLORSPACE_CONVERSION_WEBGL: GLenum = 0x9243
  public let BROWSER_DEFAULT_WEBGL: GLenum              = 0x9244

  /* WebGL-specific enums */
  public let MAX_CLIENT_WAIT_TIMEOUT_WEBGL: GLenum                 = 0x9247

  //public let TIMEOUT_IGNORED: GLenum = -1

  public private(set) var drawingBufferWidth: GLsizei = 0
  public private(set) var drawingBufferHeight: GLsizei = 0

  public var contextAttributes: WebGLContextAttributes? {
    //WebGLRenderingContextGetContextAttributes(reference, int* a, int* b)
    return nil
  }

  public var error: GLenum {
    return WebGLRenderingContextGetError(reference)
  }

  public var isContextLost: Bool {
    return WebGLRenderingContextIsContextLost(reference) != 0
  }

  internal var window: WebWindow?
  internal var worker: WebWorker?
  internal var scope: ServiceWorkerGlobalScope?
  private var callbacks: [WebGLRenderingContextCommitState] = []
  internal var reference: WebGLRenderingContextRef

  init(reference: WebGLRenderingContextRef, window: WebWindow) {
    self.reference = reference
    self.window = window
  }

  init(reference: WebGLRenderingContextRef, worker: WebWorker) {
    self.reference = reference
    self.worker = worker
  }

  init(reference: WebGLRenderingContextRef, scope: ServiceWorkerGlobalScope) {
    self.reference = reference
    self.scope = scope
  }

  public func activeTexture(texture: GLenum) {
    WebGLRenderingContextActiveTexture(reference, texture)
  }
  
  public func attachShader(_ program: WebGLProgram, shader: WebGLShader) {
    WebGLRenderingContextAttachShader(reference, program.reference, shader.reference)
  }

  public func bindAttribLocation(_ program: WebGLProgram, index: GLuint, name: String) {
    name.withCString {
      WebGLRenderingContextBindAttribLocation(reference, program.reference, index, $0)
    }
  }

  public func bindBuffer(_ target: GLenum, buffer: WebGLBuffer?) {
    WebGLRenderingContextBindBuffer(reference, target, buffer == nil ? nil : buffer!.reference)
  }

  public func bindFramebuffer(_ target: GLenum, framebuffer: WebGLFramebuffer) {
    WebGLRenderingContextBindFramebuffer(reference, target, framebuffer.reference)
  }

  public func bindRenderbuffer(_ target: GLenum, renderbuffer: WebGLRenderbuffer) {
    WebGLRenderingContextBindRenderbuffer(reference, target, renderbuffer.reference)
  }

  public func bindTexture(_ target: GLenum, texture: WebGLTexture) {
    WebGLRenderingContextBindTexture(reference, target, texture.reference)
  }

  public func blendColor(red: GLclampf, green: GLclampf, blue: GLclampf, alpha: GLclampf) {
    WebGLRenderingContextBlendColor(reference, red, green, blue, alpha)
  }

  public func blendEquation(mode: GLenum) {
    WebGLRenderingContextBlendEquation(reference, mode)
  }

  public func blendEquationSeparate(modeRGB: GLenum, modeAlpha: GLenum) {
    WebGLRenderingContextBlendEquationSeparate(reference, modeRGB, modeAlpha)
  }

  public func blendFunc(sfactor: GLenum, dfactor: GLenum) {
    WebGLRenderingContextBlendFunc(reference, sfactor, dfactor)
  }

  public func blendFuncSeparate(srcRGB: GLenum, dstRGB: GLenum, srcAlpha: GLenum, dstAlpha: GLenum) {
    WebGLRenderingContextBlendFuncSeparate(reference, srcRGB, dstRGB, srcAlpha, dstAlpha)
  }

  
  // webgl1

  public func bufferData(_ target: GLenum, size: GLsizeiptr, usage: GLenum) {
    WebGLRenderingContextBufferData0(reference, target, size, usage)
  }

  public func bufferData(_ target: GLenum, data: ArrayBufferView, usage: GLenum) {
    WebGLRenderingContextBufferData1(reference, target, data.reference, usage)
  }

  public func bufferData(_ target: GLenum, data: ArrayBuffer, usage: GLenum) {
    WebGLRenderingContextBufferData2(reference, target, data.reference, usage)
  }

  public func bufferSubData(_ target: GLenum, offset: GLintptr, data: ArrayBufferView) {
    WebGLRenderingContextBufferSubData0(reference, target, offset, data.reference)
  }

  public func bufferSubData(_ target: GLenum, offset: GLintptr, data: ArrayBuffer) {
    WebGLRenderingContextBufferSubData1(reference, target, offset, data.reference)
  }

  public func checkFramebufferStatus(_ target: GLenum) -> GLenum {
    return WebGLRenderingContextCheckFramebufferStatus(reference, target)
  }

  public func clear(_ mask: GLbitfield) {
    WebGLRenderingContextClear(reference, mask)
  }

  public func clearColor(r: GLclampf, g: GLclampf, b: GLclampf, a: GLclampf) {
    WebGLRenderingContextClearColor(reference, r, g, b, a)
  }

  public func clearDepth(_ depth: GLclampf) {
    WebGLRenderingContextClearDepth(reference, depth)
  }

  public func clearStencil(_ s: GLint) {
    WebGLRenderingContextClearStencil(reference, s)
  }

  public func colorMask(r: GLboolean, g: GLboolean, b: GLboolean, alpha: GLboolean) {
    WebGLRenderingContextColorMask(reference, r, g, b, alpha)
  }

  public func compileShader(_ shader: WebGLShader) {
    WebGLRenderingContextCompileShader(reference, shader.reference)
  }

  public func compressedTexImage2D(_ target: GLenum, level: GLint, internalformat: GLenum,
                                   width: GLsizei, height: GLsizei, border: GLint, data: ArrayBufferView) {
    WebGLRenderingContextCompressedTexImage2D0(reference, target, level, internalformat, width, height, border, data.reference)
  }

  public func compressedTexSubImage2D(_ target: GLenum, level: GLint, xoffset: GLint, yoffset: GLint,
                                      width: GLsizei, height: GLsizei, format: GLenum, data: ArrayBufferView) {
    WebGLRenderingContextCompressedTexSubImage2D0(reference, target, level, xoffset, yoffset, width, height, format, data.reference)
  }

  public func copyTexImage2D(_ target: GLenum, level: GLint, internalformat: GLenum, 
                             x: GLint, y: GLint, width: GLsizei, height: GLsizei, border: GLint) {
    WebGLRenderingContextCopyTexImage2D(reference, target, level, internalformat, x, y, width, height, border)
  }

  public func copyTexSubImage2D(_ target: GLenum, level: GLint, xoffset: GLint, yoffset: GLint, 
                                x: GLint, y: GLint, width: GLsizei, height: GLsizei) {
    WebGLRenderingContextCopyTexSubImage2D(reference, target, level, xoffset, yoffset, x, y, width, height)
  }

  public func createBuffer() -> WebGLBuffer {
    return WebGLBuffer(reference: WebGLRenderingContextCreateBuffer(reference)!)
  }

  public func createFramebuffer() -> WebGLFramebuffer {
    return WebGLFramebuffer(reference: WebGLRenderingContextCreateFramebuffer(reference)!)
  }

  public func createProgram() -> WebGLProgram {
    return WebGLProgram(reference: WebGLRenderingContextCreateProgram(reference)!)
  }

  public func createRenderbuffer() -> WebGLRenderbuffer {
    return WebGLRenderbuffer(reference: WebGLRenderingContextCreateRenderbuffer(reference))
  }

  public func createShader(type: GLenum) -> WebGLShader {
    return WebGLShader(reference: WebGLRenderingContextCreateShader(reference, type))
  }

  public func createTexture() -> WebGLTexture {
    return WebGLTexture(reference: WebGLRenderingContextCreateTexture(reference)!)
  }

  public func cullFace(mode: GLenum) {
    WebGLRenderingContextCullFace(reference, mode)
  }

  public func deleteBuffer(buffer: WebGLBuffer) {
    WebGLRenderingContextDeleteBuffer(reference, buffer.reference)
  }

  public func deleteFramebuffer(framebuffer: WebGLFramebuffer) {
    WebGLRenderingContextDeleteFramebuffer(reference, framebuffer.reference)
  }

  public func deleteProgram(program: WebGLProgram) {
    WebGLRenderingContextDeleteProgram(reference, program.reference)
  }

  public func deleteRenderbuffer(renderbuffer: WebGLRenderbuffer) {
    WebGLRenderingContextDeleteRenderbuffer(reference, renderbuffer.reference)
  }

  public func deleteShader(shader: WebGLShader) {
    WebGLRenderingContextDeleteShader(reference, shader.reference)
  }

  public func deleteTexture(texture: WebGLTexture) {
    WebGLRenderingContextDeleteTexture(reference, texture.reference)
  }

  public func depthFunc(_ fn: GLenum) {
    WebGLRenderingContextDepthFunc(reference, fn)
  }

  public func depthMask(_ flag: GLboolean) {
    WebGLRenderingContextDepthMask(reference, flag)
  }

  public func depthRange(zNear: GLclampf, zFar: GLclampf) {
    WebGLRenderingContextDepthRange(reference, zNear, zFar)
  }

  public func detachShader(program: WebGLProgram, shader: WebGLShader) {
    WebGLRenderingContextDetachShader(reference, program.reference, shader.reference)
  }
  
  public func disable(cap: GLenum) {
    WebGLRenderingContextDisable(reference, cap)
  }

  public func disableVertexAttribArray(index: GLuint) {
    WebGLRenderingContextDisableVertexAttribArray(reference, index)
  }

  public func drawArrays(mode: GLenum, first: GLint, count: GLsizei) {
    WebGLRenderingContextDrawArrays(reference, mode, first, count)
  }

  public func drawElements(mode: GLenum, count: GLsizei, type: GLenum, offset: GLintptr) {
    WebGLRenderingContextDrawElements(reference, mode, count, type, offset)
  }

  public func enable(_ cap: GLenum) {
    WebGLRenderingContextEnable(reference, cap)
  }

  public func enableVertexAttribArray(index: GLuint) {
    WebGLRenderingContextEnableVertexAttribArray(reference, index)
  }
  
  public func finish() {
    WebGLRenderingContextFinish(reference)
  }
  
  public func flush() {
    WebGLRenderingContextFlush(reference)
  }
  
  public func framebufferRenderbuffer(_ target: GLenum, attachment: GLenum, renderbuffertarget: GLenum, renderbuffer: WebGLRenderbuffer) {
    WebGLRenderingContextFramebufferRenderbuffer(reference, target, attachment, renderbuffertarget, renderbuffer.reference)  
  }
  
  public func framebufferTexture2D(_ target: GLenum, attachment: GLenum, textTarget: GLenum, texture: WebGLTexture, level: GLint) {
    WebGLRenderingContextFramebufferTexture2D(reference, target, attachment, textTarget, texture.reference, level)    
  }
  
  public func frontFace(mode: GLenum) {
    WebGLRenderingContextFrontFace(reference, mode)    
  }
  
  public func generateMipmap(_ target: GLenum) {
    WebGLRenderingContextGenerateMipmap(reference, target)
  }
  
  public func getActiveAttrib(program: WebGLProgram, index: GLuint) -> WebGLActiveInfo {
    return WebGLActiveInfo(reference: WebGLRenderingContextGetActiveAttrib(reference, program.reference, index)!)
  }
  
  public func getActiveUniform(program: WebGLProgram, index: GLuint) -> WebGLActiveInfo {
    return WebGLActiveInfo(reference: WebGLRenderingContextGetActiveUniform(reference, program.reference, index)!)
  }

  public func getAttachedShaders(program: WebGLProgram) -> [WebGLShader] {
    var result: [WebGLShader] = []
    var references: WebGLShaderRef?
    var count: CInt = 0
    WebGLRenderingContextGetAttachedShaders(reference, program.reference, &references, &count)
    for _guts in 0..<count {
      result.append(WebGLShader(reference: references!))
      references = references!.advanced(by: MemoryLayout<intptr_t>.stride)
    }
    return result
  }

  public func getAttribLocation(program: WebGLProgram, name: String) -> GLint {
    return name.withCString {
      return WebGLRenderingContextGetAttribLocation(reference, program.reference, $0)
    }
  }

  public func getBufferParameter(_ target: GLenum, name: GLenum) -> Any? {
    //void* WebGLRenderingContextGetBufferParameter(reference, target, name)
    return nil
  }

  public func getExtension(name: String) -> Any? {
    // void* WebGLRenderingContextGetExtension(reference, const char* name)
    return nil
  }

  public func getFramebufferAttachmentParameter(_ target: GLenum, attachment: GLenum, name: GLenum) -> Any? {
    // void* WebGLRenderingContextGetFramebufferAttachmentParameter(reference, target, attachment, name)
    return nil
  }
  
  public func getParameter(name: GLenum) -> Any? {
    // void* WebGLRenderingContextGetParameter(reference, name)
    return nil
  }

  public func getProgramParameter(program: WebGLProgram, name: GLenum) -> Any? {
    // void* WebGLRenderingContextGetProgramParameter(reference, WebGLProgramRef program, name)
    return nil
  }

  public func getProgramInfoLog(program: WebGLProgram) -> String? {
    var len: CInt = 0
    guard let ref = WebGLRenderingContextGetProgramInfoLog(reference, program.reference, &len) else {
      return nil
    }
    return String(bytesNoCopy: ref, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
  }

  public func getRenderbufferParameter(_ target: GLenum, name: GLenum) -> Any? {
    return nil
    //void* WebGLRenderingContextGetRenderbufferParameter(reference, target, name)
  }

  public func getShaderParameter(shader: WebGLShader, name: GLenum) -> Any? {
    // void* WebGLRenderingContextGetShaderParameter(reference, WebGLShaderRef shader, name)
    return nil
  }

  public func getShaderInfoLog(shader: WebGLShader) -> String? {
    var len: CInt = 0
    guard let ref = WebGLRenderingContextGetShaderInfoLog(reference, shader.reference, &len) else {
      return nil
    }
    return String(bytesNoCopy: ref, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
  }

  public func getShaderPrecisionFormat(shadertype: GLenum, precisiontype: GLenum) -> WebGLShaderPrecisionFormat {
    return WebGLShaderPrecisionFormat(reference: WebGLRenderingContextGetShaderPrecisionFormat(reference, shadertype, precisiontype)!)
  }

  public func getShaderSource(shader: WebGLShader) -> String? {
    var len: CInt = 0
    guard let ref = WebGLRenderingContextGetShaderSource(reference, shader.reference, &len) else {
      return nil
    }
    return String(bytesNoCopy: ref, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
  }

  public func getSupportedExtensions() -> [String] {
    //var result: [String] = []
    let result: [String] = []
    // var count: CInt = 0
    // var exts: UnsafePointer<CChar>?
    // WebGLRenderingContextGetSupportedExtensions(reference, &exts, &count)
    // for i in 0..<count {
    //   result.append(String(cString: exts[Int(i)]!))
    // }
    return result
  }

  public func getTexParameter(_ target: GLenum, name: GLenum) -> Any? {
    //void* WebGLRenderingContextGetTexParameter(reference, target, name)
    return nil
  }

  public func getUniform(program: WebGLProgram, location: WebGLUniformLocation) -> Any? {
    // void* WebGLRenderingContextGetUniform(reference, WebGLProgramRef program, location.reference)
    return nil
  }

  public func getUniformLocation(program: WebGLProgram, name: String) -> WebGLUniformLocation {
    return name.withCString {
      return WebGLUniformLocation(reference: WebGLRenderingContextGetUniformLocation(reference, program.reference, $0))
    }
  }

  public func getVertexAttrib(index: GLuint, name: GLenum) -> Any? {
    // void* WebGLRenderingContextGetVertexAttrib(reference, index, name)
    return nil
  }

  public func getVertexAttribOffset(index: GLuint, name: GLenum) -> GLintptr {
    return WebGLRenderingContextGetVertexAttribOffset(reference, index, name)
  }

  public func hint(_ target: GLenum, mode: GLenum) {
    WebGLRenderingContextHint(reference, target, mode)
  }

  public func isBuffer(_ buffer: WebGLBuffer) -> Bool {
    return WebGLRenderingContextIsBuffer(reference, buffer.reference) != 0
  }
  
  public func isEnabled(_ cap: GLenum) -> Bool {
    return WebGLRenderingContextIsEnabled(reference, cap) != 0
  }

  public func isFramebuffer(framebuffer: WebGLFramebuffer) -> Bool {
    return WebGLRenderingContextIsFramebuffer(reference, framebuffer.reference) != 0
  }
  
  public func isProgram(program: WebGLProgram) -> Bool {
    return WebGLRenderingContextIsProgram(reference, program.reference) != 0
  }
  
  public func isRenderbuffer(renderbuffer: WebGLRenderbuffer) -> Bool {
    return WebGLRenderingContextIsRenderbuffer(reference, renderbuffer.reference) != 0
  }

  public func isShader(shader: WebGLShader) -> Bool {
    return WebGLRenderingContextIsShader(reference, shader.reference) != 0
  }

  public func isTexture(texture: WebGLTexture) -> Bool {
    return WebGLRenderingContextIsTexture(reference, texture.reference) != 0
  }
  
  public func lineWidth(width: GLfloat) {
    WebGLRenderingContextLineWidth(reference, width)
  }
  
  public func linkProgram(_ program: WebGLProgram) {
    WebGLRenderingContextLinkProgram(reference, program.reference)
  }
  
  public func pixelStorei(name: GLenum, param: GLint) {
    WebGLRenderingContextPixelStorei(reference, name, param)
  }

  public func polygonOffset(factor: GLfloat, units: GLfloat) {
    WebGLRenderingContextPolygonOffset(reference, factor, units)
  }

  public func readPixels(x: GLint, y: GLint, width: GLsizei, height: GLsizei, format: GLenum, type: GLenum, pixels: ArrayBufferView) {
    WebGLRenderingContextReadPixels(reference, x, y, width, height, format, type, pixels.reference)
  }

  public func renderbufferStorage(_ target: GLenum, internalformat: GLenum, width: GLsizei, height: GLsizei) {
    WebGLRenderingContexRenderbufferStorage(reference, target, internalformat, width, height)
  }
  
  public func sampleCoverage(value: GLclampf, invert: Bool) {
    WebGLRenderingContextSampleCoverage(reference, value, invert ? 1 : 0)
  }
  
  public func scissor(x: GLint, y: GLint, width: GLsizei, height: GLsizei) {
    WebGLRenderingContextScissor(reference, x, y, width, height)
  }
  
  public func shaderSource(_ shader: WebGLShader, source: String) {
    source.withCString {
      WebGLRenderingContextShaderSource(reference, shader.reference, $0)
    }
  }
  
  public func stencilFunc(_ fn: GLenum, ref: GLint, mask: GLuint) {
    WebGLRenderingContextStencilFunc(reference, fn, ref, mask)
  }
  
  public func stencilFuncSeparate(face: GLenum, fn: GLenum, ref: GLint, mask: GLuint) {
    WebGLRenderingContextStencilFuncSeparate(reference, face, fn, ref, mask)
  }
  
  public func stencilMask(mask: GLuint) {
    WebGLRenderingContextStencilMask(reference, mask)
  }
  
  public func stencilMaskSeparate(face: GLenum, mask: GLuint) {
    WebGLRenderingContextStencilMaskSeparate(reference, face, mask)
  }

  public func stencilOp(fail: GLenum, zfail: GLenum, zpass: GLenum) {
    WebGLRenderingContextStencilOp(reference, fail, zfail, zpass)
  }
  
  public func stencilOpSeparate(face: GLenum, fail: GLenum, zfail: GLenum, zpass: GLenum) {
    WebGLRenderingContextStencilOpSeparate(reference, face, fail, zfail, zpass)
  }

  public func texParameterf(_ target: GLenum, name: GLenum, param: GLfloat) {
    WebGLRenderingContextTexParameterf(reference, target, name, param)
  }

  public func texParameteri(_ target: GLenum, name: GLenum, param: GLint) {
    WebGLRenderingContextTexParameteri(reference, target, name, param)
  }

  public func texImage2D(_ target: GLenum, level: GLint, internalformat: GLint, width: GLsizei, height: GLsizei, border: GLint, format: GLenum, type: GLenum, pixels: ArrayBufferView) {
    WebGLRenderingContextTexImage2D0(reference, target, level, internalformat, width, height, border, format, type, pixels.reference)
  }

  public func texImage2D(_ target: GLenum, level: GLint, internalformat: GLint, format: GLenum, type: GLenum, pixels: ImageData) {
    WebGLRenderingContextTexImage2D1(reference, target, level, internalformat, format, type, pixels.reference)
  }

  public func texImage2D(_ target: GLenum, level: GLint, internalformat: GLint, format: GLenum, type: GLenum, image: HtmlImageElement) {
    WebGLRenderingContextTexImage2D2(reference, target, level, internalformat, format, type, image.reference)
  }

  public func texImage2D(_ target: GLenum, level: GLint, internalformat: GLint, format: GLenum, type: GLenum, canvas: HtmlCanvasElement) {
    WebGLRenderingContextTexImage2D3(reference, target, level, internalformat, format, type, canvas.reference)
  }
  
  public func texImage2D(_ target: GLenum, level: GLint, internalformat: GLint, format: GLenum, type: GLenum, video: HtmlVideoElement) {
    WebGLRenderingContextTexImage2D4(reference, target, level, internalformat, format, type, video.reference)
  }

  public func texImage2D(_ target: GLenum, level: GLint, internalformat: GLint, format: GLenum, type: GLenum, bitmap: ImageBitmap) {
    WebGLRenderingContextTexImage2D5(reference, target, level, internalformat, format, type, bitmap.reference)
  }

  public func texSubImage2D(_ target: GLenum, level: GLint, xoffset: GLint, yoffset: GLint, width: GLsizei, height: GLsizei, format: GLenum, type: GLenum, pixels: ArrayBufferView) {
    WebGLRenderingContextTexSubImage2D0(reference, target, level, xoffset, yoffset, width, height, format, type, pixels.reference)
  }

  public func texSubImage2D(_ target: GLenum, level: GLint, xoffset: GLint, yoffset: GLint, format: GLenum, type: GLenum, pixels: ImageData) {
    WebGLRenderingContextTexSubImage2D1(reference, target, level, xoffset, yoffset, format, type, pixels.reference)
  }
  
  public func texSubImage2D(_ target: GLenum, level: GLint, xoffset: GLint, yoffset: GLint, format: GLenum, type: GLenum, image: HtmlImageElement) {
    WebGLRenderingContextTexSubImage2D2(reference, target, level, xoffset, yoffset, format, type, image.reference)
  }
  
  public func texSubImage2D(_ target: GLenum, level: GLint, xoffset: GLint, yoffset: GLint, format: GLenum, type: GLenum, canvas: HtmlCanvasElement) {
    WebGLRenderingContextTexSubImage2D3(reference, target, level, xoffset, yoffset, format, type, canvas.reference)
  }
  
  public func texSubImage2D(_ target: GLenum, level: GLint, xoffset: GLint, yoffset: GLint, format: GLenum, type: GLenum, video: HtmlVideoElement) {
    WebGLRenderingContextTexSubImage2D4(reference, target, level, xoffset, yoffset, format, type, video.reference)
  }
  
  public func texSubImage2D(_ target: GLenum, level: GLint, xoffset: GLint, yoffset: GLint, format: GLenum, type: GLenum, bitmap: ImageBitmap) {
    WebGLRenderingContextTexSubImage2D5(reference, target, level, xoffset, yoffset, format, type, bitmap.reference)
  }
  
  public func uniform1f(location: WebGLUniformLocation, x: GLfloat) {
    WebGLRenderingContextUniform1f(reference, location.reference, x)
  }

  public func uniform1fv(location: WebGLUniformLocation, v: Float32Array) {
    WebGLRenderingContextUniform1fv0(reference, location.reference, v.reference)
  }

  public func uniform1fv(location: WebGLUniformLocation, v: [GLfloat]) {
    v.withUnsafeBufferPointer {
      WebGLRenderingContextUniform1fv1(reference, location.reference, CInt(v.count), $0.baseAddress!)
    }
  }

  public func uniform1i(location: WebGLUniformLocation, x: GLint) {
    WebGLRenderingContextUniform1i(reference, location.reference, x)
  }

  public func uniform1iv(location: WebGLUniformLocation, v: Int32Array) {
    WebGLRenderingContextUniform1iv0(reference, location.reference, v.reference)
  }

  public func uniform1iv(location: WebGLUniformLocation, v: [GLint]) {
    v.withUnsafeBufferPointer {
      WebGLRenderingContextUniform1iv1(reference, location.reference, CInt(v.count), $0.baseAddress!)
    }
  }

  public func uniform2f(location: WebGLUniformLocation, x: GLfloat, y: GLfloat) {
    WebGLRenderingContextUniform2f(reference, location.reference, x, y)
  }

  public func uniform2fv(location: WebGLUniformLocation, v: Float32Array) {
    WebGLRenderingContextUniform2fv0(reference, location.reference, v.reference)
  }

  public func uniform2fv(location: WebGLUniformLocation, v: [GLfloat]) {
    v.withUnsafeBufferPointer {
      WebGLRenderingContextUniform2fv1(reference, location.reference, CInt(v.count), $0.baseAddress!)
    }
  }

  public func uniform2i(location: WebGLUniformLocation, x: GLint, y: GLint) {
    WebGLRenderingContextUniform2i(reference, location.reference, x, y)
  }
  
  public func uniform2iv(location: WebGLUniformLocation, v: Int32Array) {
    WebGLRenderingContextUniform2iv0(reference, location.reference, v.reference)
  }

  public func uniform2iv(location: WebGLUniformLocation, v: [GLint]) {
    v.withUnsafeBufferPointer {
      WebGLRenderingContextUniform2iv1(reference, location.reference, CInt(v.count), $0.baseAddress!)
    }
  }

  public func uniform3f(location: WebGLUniformLocation, x: GLfloat, y: GLfloat, z: GLfloat) {
    WebGLRenderingContextUniform3f(reference, location.reference, x, y, z)
  }

  public func uniform3fv(location: WebGLUniformLocation, v: Float32Array) {
    WebGLRenderingContextUniform3fv0(reference, location.reference, v.reference)
  }

  public func uniform3fv(location: WebGLUniformLocation, v: [GLfloat]) {
    v.withUnsafeBufferPointer {
      WebGLRenderingContextUniform3fv1(reference, location.reference, CInt(v.count), $0.baseAddress!)
    }
  }

  public func uniform3i(location: WebGLUniformLocation, x: GLint, y: GLint, z: GLint) {
    WebGLRenderingContextUniform3i(reference, location.reference, x, y, z)
  }

  public func uniform3iv(location: WebGLUniformLocation, v: Int32Array) {
    WebGLRenderingContextUniform3iv0(reference, location.reference, v.reference)
  }

  public func uniform3iv(location: WebGLUniformLocation, v: [GLint]) {
    v.withUnsafeBufferPointer {
      WebGLRenderingContextUniform3iv1(reference, location.reference, CInt(v.count), $0.baseAddress!)
    }
  }

  public func uniform4f(location: WebGLUniformLocation, x: GLfloat, y: GLfloat, z: GLfloat, w: GLfloat) {
    WebGLRenderingContextUniform4f(reference, location.reference, x, y, z, w)
  }

  public func uniform4fv(location: WebGLUniformLocation, v: Float32Array) {
    WebGLRenderingContextUniform4fv0(reference, location.reference, v.reference)
  }

  public func uniform4fv(location: WebGLUniformLocation, v: [GLfloat]) {
    v.withUnsafeBufferPointer {
      WebGLRenderingContextUniform4fv1(reference, location.reference, CInt(v.count), $0.baseAddress!)
    }
  }

  public func uniform4i(location: WebGLUniformLocation, x: GLint, y: GLint, z: GLint, w: GLint) {
    WebGLRenderingContextUniform4i(reference, location.reference, x, y, z, w)
  }

  public func uniform4iv(location: WebGLUniformLocation, v: Int32Array) {
    WebGLRenderingContextUniform4iv0(reference, location.reference, v.reference)
  }

  public func uniform4iv(location: WebGLUniformLocation, v: [GLint]) {
    v.withUnsafeBufferPointer {
      WebGLRenderingContextUniform4iv1(reference, location.reference, CInt(v.count), $0.baseAddress!)
    }
  }
  
  public func uniformMatrix2fv(location: WebGLUniformLocation, transpose: Bool, array: Float32Array) {
    WebGLRenderingContextUniformMatrix2fv0(reference, location.reference, transpose ? 1 : 0, array.reference)
  }

  public func uniformMatrix2fv(location: WebGLUniformLocation, transpose: Bool, array: [GLfloat]) {
    array.withUnsafeBufferPointer {
      WebGLRenderingContextUniformMatrix2fv1(reference, location.reference, transpose ? 1 : 0, CInt(array.count), $0.baseAddress!)
    }
  }

  public func uniformMatrix3fv(location: WebGLUniformLocation, transpose: Bool, array: Float32Array) {
    WebGLRenderingContextUniformMatrix3fv0(reference, location.reference, transpose ? 1 : 0, array.reference)
  }

  public func uniformMatrix3fv(location: WebGLUniformLocation, transpose: Bool, array: [GLfloat]) {
    array.withUnsafeBufferPointer {
      WebGLRenderingContextUniformMatrix3fv1(reference, location.reference, transpose ? 1 : 0, CInt(array.count), $0.baseAddress!)
    }
  }

  public func uniformMatrix4fv(location: WebGLUniformLocation, transpose: Bool, array: Float32Array) {
    WebGLRenderingContextUniformMatrix4fv0(reference, location.reference, transpose ? 1 : 0, array.reference)
  }

  public func uniformMatrix4fv(location: WebGLUniformLocation, transpose: Bool, array: [GLfloat]) {
    array.withUnsafeBufferPointer {
      WebGLRenderingContextUniformMatrix4fv1(reference, location.reference, transpose ? 1 : 0, CInt(array.count), $0.baseAddress!)
    }
  }

  public func useProgram(_ program: WebGLProgram) {
    WebGLRenderingContextUseProgram(reference, program.reference)  
  }

  public func validateProgram(_ program: WebGLProgram) {
    WebGLRenderingContextValidateProgram(reference, program.reference)
  }

  public func vertexAttrib1f(index: GLuint, x: GLfloat) {
    WebGLRenderingContextVertexAttrib1f(reference, index, x)
  }
  
  public func vertexAttrib1fv(index: GLuint, values: Float32Array) {
    WebGLRenderingContextVertexAttrib1fv0(reference, index, values.reference)
  }
  
  public func vertexAttrib1fv(index: GLuint, values: [GLfloat]) {
    values.withUnsafeBufferPointer {
      WebGLRenderingContextVertexAttrib1fv1(reference, index, CInt(values.count), $0.baseAddress!)
    }
  }
  
  public func vertexAttrib2f(index: GLuint, x: GLfloat, y: GLfloat) {
    WebGLRenderingContextVertexAttrib2f(reference, index, x, y)
  }
  
  public func vertexAttrib2fv(index: GLuint, values: Float32Array) {
    WebGLRenderingContextVertexAttrib2fv0(reference, index, values.reference)
  }
  
  public func vertexAttrib2fv(index: GLuint, values: [GLfloat]) {
    values.withUnsafeBufferPointer {
      WebGLRenderingContextVertexAttrib2fv1(reference, index, CInt(values.count), $0.baseAddress!)
    }
  }
  
  public func vertexAttrib3f(index: GLuint, x: GLfloat, y: GLfloat, z: GLfloat) {
    WebGLRenderingContextVertexAttrib3f(reference, index, x, y, z)
  }
  
  public func vertexAttrib3fv(index: GLuint, values: Float32Array) {
    WebGLRenderingContextVertexAttrib3fv0(reference, index, values.reference)
  }
  
  public func vertexAttrib3fv(index: GLuint, values: [GLfloat]) {
    values.withUnsafeBufferPointer {
      WebGLRenderingContextVertexAttrib3fv1(reference, index, CInt(values.count), $0.baseAddress!)
    }
  }
  
  public func vertexAttrib4f(index: GLuint, x: GLfloat, y: GLfloat, z: GLfloat, w: GLfloat) {
    WebGLRenderingContextVertexAttrib4f(reference, index, x, y, z, w)
  }
  
  public func vertexAttrib4fv(index: GLuint, values: Float32Array) {
    WebGLRenderingContextVertexAttrib4fv0(reference, index, values.reference)
  }
  
  public func vertexAttrib4fv(index: GLuint, values: [GLfloat]) {
    values.withUnsafeBufferPointer {
      WebGLRenderingContextVertexAttrib4fv1(reference, index, CInt(values.count), $0.baseAddress!)
    }
  }

  public func vertexAttribPointer(index: GLuint, size: GLint, type: GLenum, normalized: Bool, stride: GLsizei, offset: GLintptr) {
    WebGLRenderingContextVertexAttribPointer(reference, index, size, type, normalized ? 1 : 0, stride, offset)
  }

  public func viewport(x: GLint, y: GLint, width: GLsizei, height: GLsizei) {
    WebGLRenderingContextViewport(reference, x, y, width, height)
  }

  public func commit(_ cb: @escaping () -> Void) {
    let state = WebGLRenderingContextCommitState(self, cb)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    if let w = window {
      WebGLRenderingContextCommit(reference, w.reference, statePtr, { (cbState: UnsafeMutableRawPointer?, ignore: UnsafeMutableRawPointer?) in
        let cb = unsafeBitCast(cbState, to: WebGLRenderingContextCommitState.self)
        cb.callback()
        cb.dispose()
      })
    }
    if let w = worker {
      WebGLRenderingContextCommitFromWorker(reference, w.reference, statePtr, { (cbState: UnsafeMutableRawPointer?, ignore: UnsafeMutableRawPointer?) in
        let cb = unsafeBitCast(cbState, to: WebGLRenderingContextCommitState.self)
        cb.callback()
        cb.dispose()
      })
    }
    if let w = scope {
      WebGLRenderingContextCommitFromServiceWorker(reference, w.reference, statePtr, { (cbState: UnsafeMutableRawPointer?, ignore: UnsafeMutableRawPointer?) in
        let cb = unsafeBitCast(cbState, to: WebGLRenderingContextCommitState.self)
        cb.callback()
        cb.dispose()
      })
    }
  }

  // WebXR Device API support
  //public func setCompatibleXRDevice(device: XRDevice) -> Promise {
  //}


  internal func addCallback(_ cb: WebGLRenderingContextCommitState) {
    callbacks.append(cb)
  }

  internal func removeCallback(_ state: WebGLRenderingContextCommitState) {
    for (i, item) in callbacks.enumerated() {
      if item === state {
        callbacks.remove(at: i)
        return
      }
    }
  }

}

public class WebGLRenderingContextCommitState {
  
  weak var context: WebGLRenderingContext?
  let callback: () -> Void
  
  init(_ context: WebGLRenderingContext, _ cb: @escaping () -> Void) {
    self.context = context
    self.callback = cb
    context.addCallback(self)
  }

  func dispose() {
    context!.removeCallback(self)
  }

}