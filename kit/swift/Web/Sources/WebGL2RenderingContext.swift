// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Graphics

public class WebGL2RenderingContext : WebGLRenderingContext {
  public let READ_BUFFER: GLenum                                   = 0x0C02
  public let UNPACK_ROW_LENGTH: GLenum                             = 0x0CF2
  public let UNPACK_SKIP_ROWS: GLenum                              = 0x0CF3
  public let UNPACK_SKIP_PIXELS: GLenum                            = 0x0CF4
  public let PACK_ROW_LENGTH: GLenum                               = 0x0D02
  public let PACK_SKIP_ROWS: GLenum                                = 0x0D03
  public let PACK_SKIP_PIXELS: GLenum                              = 0x0D04
  public let COLOR: GLenum                                         = 0x1800
  public let DEPTH: GLenum                                         = 0x1801
  public let STENCIL: GLenum                                       = 0x1802
  public let RED: GLenum                                           = 0x1903
  public let RGB8: GLenum                                          = 0x8051
  public let RGBA8: GLenum                                         = 0x8058
  public let RGB10_A2: GLenum                                      = 0x8059
  public let TEXTURE_BINDING_3D: GLenum                            = 0x806A
  public let UNPACK_SKIP_IMAGES: GLenum                            = 0x806D
  public let UNPACK_IMAGE_HEIGHT: GLenum                           = 0x806E
  public let TEXTURE_3D: GLenum                                    = 0x806F
  public let TEXTURE_WRAP_R: GLenum                                = 0x8072
  public let MAX_3D_TEXTURE_SIZE: GLenum                           = 0x8073
  public let UNSIGNED_INT_2_10_10_10_REV: GLenum                   = 0x8368
  public let MAX_ELEMENTS_VERTICES: GLenum                         = 0x80E8
  public let MAX_ELEMENTS_INDICES: GLenum                          = 0x80E9
  public let TEXTURE_MIN_LOD: GLenum                               = 0x813A
  public let TEXTURE_MAX_LOD: GLenum                               = 0x813B
  public let TEXTURE_BASE_LEVEL: GLenum                            = 0x813C
  public let TEXTURE_MAX_LEVEL: GLenum                             = 0x813D
  public let MIN: GLenum                                           = 0x8007
  public let MAX: GLenum                                           = 0x8008
  public let DEPTH_COMPONENT24: GLenum                             = 0x81A6
  public let MAX_TEXTURE_LOD_BIAS: GLenum                          = 0x84FD
  public let TEXTURE_COMPARE_MODE: GLenum                          = 0x884C
  public let TEXTURE_COMPARE_FUNC: GLenum                          = 0x884D
  public let CURRENT_QUERY: GLenum                                 = 0x8865
  public let QUERY_RESULT: GLenum                                  = 0x8866
  public let QUERY_RESULT_AVAILABLE: GLenum                        = 0x8867
  public let STREAM_READ: GLenum                                   = 0x88E1
  public let STREAM_COPY: GLenum                                   = 0x88E2
  public let STATIC_READ: GLenum                                   = 0x88E5
  public let STATIC_COPY: GLenum                                   = 0x88E6
  public let DYNAMIC_READ: GLenum                                  = 0x88E9
  public let DYNAMIC_COPY: GLenum                                  = 0x88EA
  public let MAX_DRAW_BUFFERS: GLenum                              = 0x8824
  public let DRAW_BUFFER0: GLenum                                  = 0x8825
  public let DRAW_BUFFER1: GLenum                                  = 0x8826
  public let DRAW_BUFFER2: GLenum                                  = 0x8827
  public let DRAW_BUFFER3: GLenum                                  = 0x8828
  public let DRAW_BUFFER4: GLenum                                  = 0x8829
  public let DRAW_BUFFER5: GLenum                                  = 0x882A
  public let DRAW_BUFFER6: GLenum                                  = 0x882B
  public let DRAW_BUFFER7: GLenum                                  = 0x882C
  public let DRAW_BUFFER8: GLenum                                  = 0x882D
  public let DRAW_BUFFER9: GLenum                                  = 0x882E
  public let DRAW_BUFFER10: GLenum                                 = 0x882F
  public let DRAW_BUFFER11: GLenum                                 = 0x8830
  public let DRAW_BUFFER12: GLenum                                 = 0x8831
  public let DRAW_BUFFER13: GLenum                                 = 0x8832
  public let DRAW_BUFFER14: GLenum                                 = 0x8833
  public let DRAW_BUFFER15: GLenum                                 = 0x8834
  public let MAX_FRAGMENT_UNIFORM_COMPONENTS: GLenum               = 0x8B49
  public let MAX_VERTEX_UNIFORM_COMPONENTS: GLenum                 = 0x8B4A
  public let SAMPLER_3D: GLenum                                    = 0x8B5F
  public let SAMPLER_2D_SHADOW: GLenum                             = 0x8B62
  public let FRAGMENT_SHADER_DERIVATIVE_HINT: GLenum               = 0x8B8B
  public let PIXEL_PACK_BUFFER: GLenum                             = 0x88EB
  public let PIXEL_UNPACK_BUFFER: GLenum                           = 0x88EC
  public let PIXEL_PACK_BUFFER_BINDING: GLenum                     = 0x88ED
  public let PIXEL_UNPACK_BUFFER_BINDING: GLenum                   = 0x88EF
  public let FLOAT_MAT2x3: GLenum                                  = 0x8B65
  public let FLOAT_MAT2x4: GLenum                                  = 0x8B66
  public let FLOAT_MAT3x2: GLenum                                  = 0x8B67
  public let FLOAT_MAT3x4: GLenum                                  = 0x8B68
  public let FLOAT_MAT4x2: GLenum                                  = 0x8B69
  public let FLOAT_MAT4x3: GLenum                                  = 0x8B6A
  public let SRGB: GLenum                                          = 0x8C40
  public let SRGB8: GLenum                                         = 0x8C41
  public let SRGB8_ALPHA8: GLenum                                  = 0x8C43
  public let COMPARE_REF_TO_TEXTURE: GLenum                        = 0x884E
  public let RGBA32F: GLenum                                       = 0x8814
  public let RGB32F: GLenum                                        = 0x8815
  public let RGBA16F: GLenum                                       = 0x881A
  public let RGB16F: GLenum                                        = 0x881B
  public let VERTEX_ATTRIB_ARRAY_INTEGER: GLenum                   = 0x88FD
  public let MAX_ARRAY_TEXTURE_LAYERS: GLenum                      = 0x88FF
  public let MIN_PROGRAM_TEXEL_OFFSET: GLenum                      = 0x8904
  public let MAX_PROGRAM_TEXEL_OFFSET: GLenum                      = 0x8905
  public let MAX_VARYING_COMPONENTS: GLenum                        = 0x8B4B
  public let TEXTURE_2D_ARRAY: GLenum                              = 0x8C1A
  public let TEXTURE_BINDING_2D_ARRAY: GLenum                      = 0x8C1D
  public let R11F_G11F_B10F: GLenum                                = 0x8C3A
  public let UNSIGNED_INT_10F_11F_11F_REV: GLenum                  = 0x8C3B
  public let RGB9_E5: GLenum                                       = 0x8C3D
  public let UNSIGNED_INT_5_9_9_9_REV: GLenum                      = 0x8C3E
  public let TRANSFORM_FEEDBACK_BUFFER_MODE: GLenum                = 0x8C7F
  public let MAX_TRANSFORM_FEEDBACK_SEPARATE_COMPONENTS: GLenum    = 0x8C80
  public let TRANSFORM_FEEDBACK_VARYINGS: GLenum                   = 0x8C83
  public let TRANSFORM_FEEDBACK_BUFFER_START: GLenum               = 0x8C84
  public let TRANSFORM_FEEDBACK_BUFFER_SIZE: GLenum                = 0x8C85
  public let TRANSFORM_FEEDBACK_PRIMITIVES_WRITTEN: GLenum         = 0x8C88
  public let RASTERIZER_DISCARD: GLenum                            = 0x8C89
  public let MAX_TRANSFORM_FEEDBACK_INTERLEAVED_COMPONENTS: GLenum = 0x8C8A
  public let MAX_TRANSFORM_FEEDBACK_SEPARATE_ATTRIBS: GLenum       = 0x8C8B
  public let INTERLEAVED_ATTRIBS: GLenum                           = 0x8C8C
  public let SEPARATE_ATTRIBS: GLenum                              = 0x8C8D
  public let TRANSFORM_FEEDBACK_BUFFER: GLenum                     = 0x8C8E
  public let TRANSFORM_FEEDBACK_BUFFER_BINDING: GLenum             = 0x8C8F
  public let RGBA32UI: GLenum                                      = 0x8D70
  public let RGB32UI: GLenum                                       = 0x8D71
  public let RGBA16UI: GLenum                                      = 0x8D76
  public let RGB16UI: GLenum                                       = 0x8D77
  public let RGBA8UI: GLenum                                       = 0x8D7C
  public let RGB8UI: GLenum                                        = 0x8D7D
  public let RGBA32I: GLenum                                       = 0x8D82
  public let RGB32I: GLenum                                        = 0x8D83
  public let RGBA16I: GLenum                                       = 0x8D88
  public let RGB16I: GLenum                                        = 0x8D89
  public let RGBA8I: GLenum                                        = 0x8D8E
  public let RGB8I: GLenum                                         = 0x8D8F
  public let RED_INTEGER: GLenum                                   = 0x8D94
  public let RGB_INTEGER: GLenum                                   = 0x8D98
  public let RGBA_INTEGER: GLenum                                  = 0x8D99
  public let SAMPLER_2D_ARRAY: GLenum                              = 0x8DC1
  public let SAMPLER_2D_ARRAY_SHADOW: GLenum                       = 0x8DC4
  public let SAMPLER_CUBE_SHADOW: GLenum                           = 0x8DC5
  public let UNSIGNED_INT_VEC2: GLenum                             = 0x8DC6
  public let UNSIGNED_INT_VEC3: GLenum                             = 0x8DC7
  public let UNSIGNED_INT_VEC4: GLenum                             = 0x8DC8
  public let INT_SAMPLER_2D: GLenum                                = 0x8DCA
  public let INT_SAMPLER_3D: GLenum                                = 0x8DCB
  public let INT_SAMPLER_CUBE: GLenum                              = 0x8DCC
  public let INT_SAMPLER_2D_ARRAY: GLenum                          = 0x8DCF
  public let UNSIGNED_INT_SAMPLER_2D: GLenum                       = 0x8DD2
  public let UNSIGNED_INT_SAMPLER_3D: GLenum                       = 0x8DD3
  public let UNSIGNED_INT_SAMPLER_CUBE: GLenum                     = 0x8DD4
  public let UNSIGNED_INT_SAMPLER_2D_ARRAY: GLenum                 = 0x8DD7
  public let DEPTH_COMPONENT32F: GLenum                            = 0x8CAC
  public let DEPTH32F_STENCIL8: GLenum                             = 0x8CAD
  public let FLOAT_32_UNSIGNED_INT_24_8_REV: GLenum                = 0x8DAD
  public let FRAMEBUFFER_ATTACHMENT_COLOR_ENCODING: GLenum         = 0x8210
  public let FRAMEBUFFER_ATTACHMENT_COMPONENT_TYPE: GLenum         = 0x8211
  public let FRAMEBUFFER_ATTACHMENT_RED_SIZE: GLenum               = 0x8212
  public let FRAMEBUFFER_ATTACHMENT_GREEN_SIZE: GLenum             = 0x8213
  public let FRAMEBUFFER_ATTACHMENT_BLUE_SIZE: GLenum              = 0x8214
  public let FRAMEBUFFER_ATTACHMENT_ALPHA_SIZE: GLenum             = 0x8215
  public let FRAMEBUFFER_ATTACHMENT_DEPTH_SIZE: GLenum             = 0x8216
  public let FRAMEBUFFER_ATTACHMENT_STENCIL_SIZE: GLenum           = 0x8217
  public let FRAMEBUFFER_DEFAULT: GLenum                           = 0x8218
  public let UNSIGNED_INT_24_8: GLenum                             = 0x84FA
  public let DEPTH24_STENCIL8: GLenum                              = 0x88F0
  public let UNSIGNED_NORMALIZED: GLenum                           = 0x8C17
  public let DRAW_FRAMEBUFFER_BINDING: GLenum                      = 0x8CA6 /* Same as FRAMEBUFFER_BINDING */
  public let READ_FRAMEBUFFER: GLenum                              = 0x8CA8
  public let DRAW_FRAMEBUFFER: GLenum                              = 0x8CA9
  public let READ_FRAMEBUFFER_BINDING: GLenum                      = 0x8CAA
  public let RENDERBUFFER_SAMPLES: GLenum                          = 0x8CAB
  public let FRAMEBUFFER_ATTACHMENT_TEXTURE_LAYER: GLenum          = 0x8CD4
  public let MAX_COLOR_ATTACHMENTS: GLenum                         = 0x8CDF
  public let COLOR_ATTACHMENT1: GLenum                             = 0x8CE1
  public let COLOR_ATTACHMENT2: GLenum                             = 0x8CE2
  public let COLOR_ATTACHMENT3: GLenum                             = 0x8CE3
  public let COLOR_ATTACHMENT4: GLenum                             = 0x8CE4
  public let COLOR_ATTACHMENT5: GLenum                             = 0x8CE5
  public let COLOR_ATTACHMENT6: GLenum                             = 0x8CE6
  public let COLOR_ATTACHMENT7: GLenum                             = 0x8CE7
  public let COLOR_ATTACHMENT8: GLenum                             = 0x8CE8
  public let COLOR_ATTACHMENT9: GLenum                             = 0x8CE9
  public let COLOR_ATTACHMENT10: GLenum                            = 0x8CEA
  public let COLOR_ATTACHMENT11: GLenum                            = 0x8CEB
  public let COLOR_ATTACHMENT12: GLenum                            = 0x8CEC
  public let COLOR_ATTACHMENT13: GLenum                            = 0x8CED
  public let COLOR_ATTACHMENT14: GLenum                            = 0x8CEE
  public let COLOR_ATTACHMENT15: GLenum                            = 0x8CEF
  public let FRAMEBUFFER_INCOMPLETE_MULTISAMPLE: GLenum            = 0x8D56
  public let MAX_SAMPLES: GLenum                                   = 0x8D57
  public let HALF_FLOAT: GLenum                                    = 0x140B
  public let RG: GLenum                                            = 0x8227
  public let RG_INTEGER: GLenum                                    = 0x8228
  public let R8: GLenum                                            = 0x8229
  public let RG8: GLenum                                           = 0x822B
  public let R16F: GLenum                                          = 0x822D
  public let R32F: GLenum                                          = 0x822E
  public let RG16F: GLenum                                         = 0x822F
  public let RG32F: GLenum                                         = 0x8230
  public let R8I: GLenum                                           = 0x8231
  public let R8UI: GLenum                                          = 0x8232
  public let R16I: GLenum                                          = 0x8233
  public let R16UI: GLenum                                         = 0x8234
  public let R32I: GLenum                                          = 0x8235
  public let R32UI: GLenum                                         = 0x8236
  public let RG8I: GLenum                                          = 0x8237
  public let RG8UI: GLenum                                         = 0x8238
  public let RG16I: GLenum                                         = 0x8239
  public let RG16UI: GLenum                                        = 0x823A
  public let RG32I: GLenum                                         = 0x823B
  public let RG32UI: GLenum                                        = 0x823C
  public let VERTEX_ARRAY_BINDING: GLenum                          = 0x85B5
  public let R8_SNORM: GLenum                                      = 0x8F94
  public let RG8_SNORM: GLenum                                     = 0x8F95
  public let RGB8_SNORM: GLenum                                    = 0x8F96
  public let RGBA8_SNORM: GLenum                                   = 0x8F97
  public let SIGNED_NORMALIZED: GLenum                             = 0x8F9C
  public let COPY_READ_BUFFER: GLenum                              = 0x8F36
  public let COPY_WRITE_BUFFER: GLenum                             = 0x8F37
  public let COPY_READ_BUFFER_BINDING: GLenum                      = 0x8F36 /* Same as COPY_READ_BUFFER */
  public let COPY_WRITE_BUFFER_BINDING: GLenum                     = 0x8F37 /* Same as COPY_WRITE_BUFFER */
  public let UNIFORM_BUFFER: GLenum                                = 0x8A11
  public let UNIFORM_BUFFER_BINDING: GLenum                        = 0x8A28
  public let UNIFORM_BUFFER_START: GLenum                          = 0x8A29
  public let UNIFORM_BUFFER_SIZE: GLenum                           = 0x8A2A
  public let MAX_VERTEX_UNIFORM_BLOCKS: GLenum                     = 0x8A2B
  public let MAX_FRAGMENT_UNIFORM_BLOCKS: GLenum                   = 0x8A2D
  public let MAX_COMBINED_UNIFORM_BLOCKS: GLenum                   = 0x8A2E
  public let MAX_UNIFORM_BUFFER_BINDINGS: GLenum                   = 0x8A2F
  public let MAX_UNIFORM_BLOCK_SIZE: GLenum                        = 0x8A30
  public let MAX_COMBINED_VERTEX_UNIFORM_COMPONENTS: GLenum        = 0x8A31
  public let MAX_COMBINED_FRAGMENT_UNIFORM_COMPONENTS: GLenum      = 0x8A33
  public let UNIFORM_BUFFER_OFFSET_ALIGNMENT: GLenum               = 0x8A34
  public let ACTIVE_UNIFORM_BLOCKS: GLenum                         = 0x8A36
  public let UNIFORM_TYPE: GLenum                                  = 0x8A37
  public let UNIFORM_SIZE: GLenum                                  = 0x8A38
  public let UNIFORM_BLOCK_INDEX: GLenum                           = 0x8A3A
  public let UNIFORM_OFFSET: GLenum                                = 0x8A3B
  public let UNIFORM_ARRAY_STRIDE: GLenum                          = 0x8A3C
  public let UNIFORM_MATRIX_STRIDE: GLenum                         = 0x8A3D
  public let UNIFORM_IS_ROW_MAJOR: GLenum                          = 0x8A3E
  public let UNIFORM_BLOCK_BINDING: GLenum                         = 0x8A3F
  public let UNIFORM_BLOCK_DATA_SIZE: GLenum                       = 0x8A40
  public let UNIFORM_BLOCK_ACTIVE_UNIFORMS: GLenum                 = 0x8A42
  public let UNIFORM_BLOCK_ACTIVE_UNIFORM_INDICES: GLenum          = 0x8A43
  public let UNIFORM_BLOCK_REFERENCED_BY_VERTEX_SHADER: GLenum     = 0x8A44
  public let UNIFORM_BLOCK_REFERENCED_BY_FRAGMENT_SHADER: GLenum   = 0x8A46
  public let INVALID_INDEX: GLenum                                 = 0xFFFFFFFF
  public let MAX_VERTEX_OUTPUT_COMPONENTS: GLenum                  = 0x9122
  public let MAX_FRAGMENT_INPUT_COMPONENTS: GLenum                 = 0x9125
  public let MAX_SERVER_WAIT_TIMEOUT: GLenum                       = 0x9111
  public let OBJECT_TYPE: GLenum                                   = 0x9112
  public let SYNC_CONDITION: GLenum                                = 0x9113
  public let SYNC_STATUS: GLenum                                   = 0x9114
  public let SYNC_FLAGS: GLenum                                    = 0x9115
  public let SYNC_FENCE: GLenum                                    = 0x9116
  public let SYNC_GPU_COMMANDS_COMPLETE: GLenum                    = 0x9117
  public let UNSIGNALED: GLenum                                    = 0x9118
  public let SIGNALED: GLenum                                      = 0x9119
  public let ALREADY_SIGNALED: GLenum                              = 0x911A
  public let TIMEOUT_EXPIRED: GLenum                               = 0x911B
  public let CONDITION_SATISFIED: GLenum                           = 0x911C
  public let WAIT_FAILED: GLenum                                   = 0x911D
  public let SYNC_FLUSH_COMMANDS_BIT: GLenum                       = 0x00000001
  public let VERTEX_ATTRIB_ARRAY_DIVISOR: GLenum                   = 0x88FE
  public let ANY_SAMPLES_PASSED: GLenum                            = 0x8C2F
  public let ANY_SAMPLES_PASSED_CONSERVATIVE: GLenum               = 0x8D6A
  public let SAMPLER_BINDING: GLenum                               = 0x8919
  public let RGB10_A2UI: GLenum                                    = 0x906F
  public let INT_2_10_10_10_REV: GLenum                            = 0x8D9F
  public let TRANSFORM_FEEDBACK: GLenum                            = 0x8E22
  public let TRANSFORM_FEEDBACK_PAUSED: GLenum                     = 0x8E23
  public let TRANSFORM_FEEDBACK_ACTIVE: GLenum                     = 0x8E24
  public let TRANSFORM_FEEDBACK_BINDING: GLenum                    = 0x8E25
  public let TEXTURE_IMMUTABLE_FORMAT: GLenum                      = 0x912F
  public let MAX_ELEMENT_INDEX: GLenum                             = 0x8D6B
  public let TEXTURE_IMMUTABLE_LEVELS: GLenum                      = 0x82DF

   /* Buffer objects */
  public func bufferData(target: GLenum, srcData: ArrayBufferView, usage: GLenum, srcOffset: GLuint, length: GLuint = 0) {
    WebGL2RenderingContextBufferData3(reference, target, srcData.reference, usage, srcOffset, length)
  }

  public func bufferSubData(target: GLenum, dstByteOffset: GLintptr, srcData: ArrayBufferView, srcOffset: GLuint, length: GLuint = 0) {
    WebGL2RenderingContextBufferSubData(reference, target, dstByteOffset, srcData.reference, srcOffset, length)
  }

  public func copyBufferSubData(readTarget: GLenum, writeTarget: GLenum, readOffset: GLintptr, writeOffset: GLintptr, size: GLsizeiptr) {
    WebGL2RenderingContextCopyBufferSubData(reference, readTarget, writeTarget, readOffset, writeOffset, size)
  }

  public func getBufferSubData(target: GLenum, srcByteOffset: GLintptr, dstData: ArrayBufferView, dstOffset: GLuint = 0, length: GLuint = 0) {
    WebGL2RenderingContextGetBufferSubData(reference, target, srcByteOffset, dstData.reference, dstOffset, length)
  }

  public func blitFramebuffer(_ srcX0: GLint, _ srcY0: GLint, _ srcX1: GLint, _ srcY1: GLint, _ dstX0: GLint, _ dstY0: GLint, _ dstX1: GLint, _ dstY1: GLint, mask: GLbitfield, filter: GLenum) {
    WebGL2RenderingContextBlitFramebuffer(reference, srcX0, srcY0, srcX1, srcY1, dstX0, dstY0, dstX1, dstY1, mask, filter)
  }
  
  public func framebufferTextureLayer(target: GLenum, attachment: GLenum, texture: WebGLTexture, level: GLint, layer: GLint) {
    WebGL2RenderingContextFramebufferTextureLayer(reference, target, attachment, texture.reference, level, layer)
  }

  public func getInternalformatParameter(target: GLenum, internalformat: GLenum, name: GLenum) -> Any? {
    //void* WebGL2RenderingContextGetInternalformatParameter(reference, target, internalformat, name)
    return nil
  }
  
  public func invalidateFramebuffer(target: GLenum, attachments: [GLenum]) {
    attachments.withUnsafeBufferPointer {
      WebGL2RenderingContextInvalidateFramebuffer(reference, target, CInt(attachments.count), $0.baseAddress)
    }
  }

  public func invalidateSubFramebuffer(target: GLenum, attachments: [GLenum], x: GLint, y: GLint, width: GLsizei, height: GLsizei) {
    attachments.withUnsafeBufferPointer {
      WebGL2RenderingContextInvalidateSubFramebuffer(reference, target, CInt(attachments.count), $0.baseAddress, x, y, width, height)
    }
  }
  
  public func readBuffer(mode: GLenum) {
    WebGL2RenderingContextReadBuffer(reference, mode)
  }

    /* Renderbuffer objects */
  public func renderbufferStorageMultisample(target: GLenum, samples: GLsizei, internalformat: GLenum, width: GLsizei, height: GLsizei) {
    WebGL2RenderingContextRenderbufferStorageMultisample(reference, target, samples, internalformat, width, height)
  }
   
  public func texImage2D(target: GLenum, level: GLint, internalformat: GLint, width: GLsizei, height: GLsizei, border: GLint, format: GLenum, type: GLenum, offset: GLintptr) {
    WebGL2RenderingContextTexImage2D6(reference, target, level, internalformat, width, height, border, format, type, offset)
  }
  
  public func texImage2D(target: GLenum, level: GLint, internalformat: GLint, width: GLsizei, height: GLsizei, border: GLint, format: GLenum, type: GLenum, data: ImageData) {
    WebGL2RenderingContextTexImage2D7(reference, target, level, internalformat, width, height, border, format, type, data.reference)    
  }

  public func texImage2D(target: GLenum, level: GLint, internalformat: GLint, width: GLsizei, height: GLsizei, border: GLint, format: GLenum, type: GLenum, image: HtmlImageElement) {
    WebGL2RenderingContextTexImage2D8(reference, target, level, internalformat, width, height, border, format, type, image.reference)
  }
  
  public func texImage2D(target: GLenum, level: GLint, internalformat: GLint, width: GLsizei, height: GLsizei, border: GLint, format: GLenum, type: GLenum, canvas: HtmlCanvasElement) {
    WebGL2RenderingContextTexImage2D9(reference, target, level, internalformat, width, height, border, format, type, canvas.reference)
  }

  public func texImage2D(target: GLenum, level: GLint, internalformat: GLint, width: GLsizei, height: GLsizei, border: GLint, format: GLenum, type: GLenum, video: HtmlVideoElement) {
    WebGL2RenderingContextTexImage2D10(reference, target, level, internalformat, width, height, border, format, type, video.reference)
  }

  public func texImage2D(target: GLenum, level: GLint, internalformat: GLint, width: GLsizei, height: GLsizei, border: GLint, format: GLenum, type: GLenum, bitmap: ImageBitmap) {
    WebGL2RenderingContextTexImage2D11(reference, target, level, internalformat, width, height, border, format, type, bitmap.reference)
  }

  public func texImage2D(target: GLenum, level: GLint, internalformat: GLint, width: GLsizei, height: GLsizei, border: GLint, format: GLenum, type: GLenum, srcData: ArrayBufferView, srcOffset: GLuint) {
    WebGL2RenderingContextTexImage2D12(reference, target, level, internalformat, width, height, border, format, type, srcData.reference, srcOffset)
  }

  public func texSubImage2D(target: GLenum, level: GLint, xoffset: GLint, yoffset: GLint, width: GLsizei, height: GLsizei, format: GLenum, type: GLenum, offset: GLintptr) {
    WebGL2RenderingContextTexSubImage2D6(reference, target, level, xoffset, yoffset, width, height, format, type, offset)
  }

  public func texSubImage2D(target: GLenum, level: GLint, xoffset: GLint, yoffset: GLint, width: GLsizei, height: GLsizei, format: GLenum, type: GLenum, data: ImageData) {
    WebGL2RenderingContextTexSubImage2D7(reference, target, level, xoffset, yoffset, width, height, format, type, data.reference)
  }
  
  public func texSubImage2D(target: GLenum, level: GLint, xoffset: GLint, yoffset: GLint, width: GLsizei, height: GLsizei, format: GLenum, type: GLenum, image: HtmlImageElement) {
    WebGL2RenderingContextTexSubImage2D8(reference, target, level, xoffset, yoffset, width, height, format, type, image.reference)
  }
  
  public func texSubImage2D(target: GLenum, level: GLint, xoffset: GLint, yoffset: GLint, width: GLsizei, height: GLsizei, format: GLenum, type: GLenum, canvas: HtmlCanvasElement) {
    WebGL2RenderingContextTexSubImage2D9(reference, target, level, xoffset, yoffset, width, height, format, type, canvas.reference)
  }
  
  public func texSubImage2D(target: GLenum, level: GLint, xoffset: GLint, yoffset: GLint, width: GLsizei, height: GLsizei, format: GLenum, type: GLenum, video: HtmlVideoElement) {
    WebGL2RenderingContextTexSubImage2D10(reference, target, level, xoffset, yoffset, width, height, format, type, video.reference)
  }
  
  public func texSubImage2D(target: GLenum, level: GLint, xoffset: GLint, yoffset: GLint, width: GLsizei, height: GLsizei, format: GLenum, type: GLenum, bitmap: ImageBitmap) {
    WebGL2RenderingContextTexSubImage2D11(reference, target, level, xoffset, yoffset, width, height, format, type, bitmap.reference)
  }
  
  public func texSubImage2D(target: GLenum, level: GLint, xoffset: GLint, yoffset: GLint, width: GLsizei, height: GLsizei, format: GLenum, type: GLenum, srcData: ArrayBufferView, srcOffset: GLuint) {
    WebGL2RenderingContextTexSubImage2D12(reference, target, level, xoffset, yoffset, width, height, format, type, srcData.reference, srcOffset)
  }

  public func texStorage2D(target: GLenum, levels: GLsizei, internalformat: GLenum, width: GLsizei, height: GLsizei) {
    WebGL2RenderingContextTexStorage2D0(reference, target, levels, internalformat, width, height)
  }
  
  public func texStorage3D(target: GLenum, levels: GLsizei, internalformat: GLenum, width: GLsizei, height: GLsizei, depth: GLsizei) {
    WebGL2RenderingContextTexStorage3D1(reference, target, levels, internalformat, width, height, depth)
  }

  public func texImage3D(target: GLenum, level: GLint, internalformat: GLint, width: GLsizei, height: GLsizei, depth: GLsizei, border: GLint, format: GLenum, type: GLenum, offset: GLintptr) {
    WebGL2RenderingContextTexImage3D0(reference, target, level, internalformat, width, height, depth, border, format, type, offset)
  }
  
  public func texImage3D(target: GLenum, level: GLint, internalformat: GLint, width: GLsizei, height: GLsizei, depth: GLsizei, border: GLint, format: GLenum, type: GLenum, data: ImageData) {
    WebGL2RenderingContextTexImage3D1(reference, target, level, internalformat, width, height, depth, border, format, type, data.reference)
  }
  
  public func texImage3D(target: GLenum, level: GLint, internalformat: GLint, width: GLsizei, height: GLsizei, depth: GLsizei, border: GLint, format: GLenum, type: GLenum, image: HtmlImageElement) {
    WebGL2RenderingContextTexImage3D2(reference, target, level, internalformat, width, height, depth, border, format, type, image.reference)
  }
  
  public func texImage3D(target: GLenum, level: GLint, internalformat: GLint, width: GLsizei, height: GLsizei, depth: GLsizei, border: GLint, format: GLenum, type: GLenum, canvas: HtmlCanvasElement) {
    WebGL2RenderingContextTexImage3D3(reference, target, level, internalformat, width, height, depth, border, format, type, canvas.reference)
  }
  
  public func texImage3D(target: GLenum, level: GLint, internalformat: GLint, width: GLsizei, height: GLsizei, depth: GLsizei, border: GLint, format: GLenum, type: GLenum, video: HtmlVideoElement) {
    WebGL2RenderingContextTexImage3D4(reference, target, level, internalformat, width, height, depth, border, format, type, video.reference)
  }
  
  public func texImage3D(target: GLenum, level: GLint, internalformat: GLint, width: GLsizei, height: GLsizei, depth: GLsizei, border: GLint, format: GLenum, type: GLenum, bitmap: ImageBitmap) {
    WebGL2RenderingContextTexImage3D5(reference, target, level, internalformat, width, height, depth, border, format, type, bitmap.reference)
  }

  public func texImage3D(target: GLenum, level: GLint, internalformat: GLint, width: GLsizei, height: GLsizei, depth: GLsizei, border: GLint, format: GLenum, type: GLenum, pixels: ArrayBufferView) {
    WebGL2RenderingContextTexImage3D6(reference, target, level, internalformat, width, height, depth, border, format, type, pixels.reference)
  }
  
  public func texImage3D(target: GLenum, level: GLint, internalformat: GLint, width: GLsizei, height: GLsizei, depth: GLsizei, border: GLint, format: GLenum, type: GLenum, pixels: ArrayBufferView, srcOffset: GLuint) {
    WebGL2RenderingContextTexImage3D7(reference, target, level, internalformat, width, height, depth, border, format, type, pixels.reference, srcOffset)
  }

  public func texSubImage3D(target: GLenum, level: GLint, xoffset: GLint, yoffset: GLint, zoffset: GLint, width: GLsizei, height: GLsizei, depth: GLsizei, format: GLenum, type: GLenum, offset: GLintptr) {
    WebGL2RenderingContextTexSubImage3D0(reference, target, level, xoffset, yoffset, zoffset, width, height, depth, format, type, offset)
  }
  
  public func texSubImage3D(target: GLenum, level: GLint, xoffset: GLint, yoffset: GLint, zoffset: GLint, width: GLsizei, height: GLsizei, depth: GLsizei, format: GLenum, type: GLenum, data: ImageData) {
    WebGL2RenderingContextTexSubImage3D1(reference, target, level, xoffset, yoffset, zoffset, width, height, depth, format, type, data.reference)
  }
  
  public func texSubImage3D(target: GLenum, level: GLint, xoffset: GLint, yoffset: GLint, zoffset: GLint, width: GLsizei, height: GLsizei, depth: GLsizei, format: GLenum, type: GLenum, image: HtmlImageElement) {
    WebGL2RenderingContextTexSubImage3D2(reference, target, level, xoffset, yoffset, zoffset, width, height, depth, format, type, image.reference)
  }
  
  public func texSubImage3D(target: GLenum, level: GLint, xoffset: GLint, yoffset: GLint, zoffset: GLint, width: GLsizei, height: GLsizei, depth: GLsizei, format: GLenum, type: GLenum, canvas: HtmlCanvasElement) {
    WebGL2RenderingContextTexSubImage3D3(reference, target, level, xoffset, yoffset, zoffset, width, height, depth, format, type, canvas.reference)
  }
  
  public func texSubImage3D(target: GLenum, level: GLint, xoffset: GLint, yoffset: GLint, zoffset: GLint, width: GLsizei, height: GLsizei, depth: GLsizei, format: GLenum, type: GLenum, video: HtmlVideoElement) {
    WebGL2RenderingContextTexSubImage3D4(reference, target, level, xoffset, yoffset, zoffset, width, height, depth, format, type, video.reference)
  }

  public func texSubImage3D(target: GLenum, level: GLint, xoffset: GLint, yoffset: GLint, zoffset: GLint, width: GLsizei, height: GLsizei, depth: GLsizei, format: GLenum, type: GLenum, bitmap: ImageBitmap) {
    WebGL2RenderingContextTexSubImage3D5(reference, target, level, xoffset, yoffset, zoffset, width, height, depth, format, type, bitmap.reference)
  }
  
  public func texSubImage3D(target: GLenum, level: GLint, xoffset: GLint, yoffset: GLint, zoffset: GLint, width: GLsizei, height: GLsizei, depth: GLsizei, format: GLenum, type: GLenum, pixels: ArrayBufferView, srcOffset: GLuint = 0) {
    WebGL2RenderingContextTexSubImage3D6(reference, target, level, xoffset, yoffset, zoffset, width, height, depth, format, type, pixels.reference, srcOffset)
  }

  public func copyTexSubImage3D(target: GLenum, level: GLint, xoffset: GLint, yoffset: GLint, zoffset: GLint, x: GLint, y: GLint, width: GLsizei, height: GLsizei) {
    WebGL2RenderingContextCopyTexSubImage3D(reference, target, level, xoffset, yoffset, zoffset, x, y, width, height)
  }

  public func compressedTexImage2D(target: GLenum, level: GLint, internalformat: GLenum,
                                   width: GLsizei, height: GLsizei, border: GLint,
                                   data: ArrayBufferView, srcOffset: GLuint,
                                   srcLengthOverride: GLuint = 0) {
    WebGL2RenderingContextCompressedTexImage2D1(reference, target, level, internalformat, width, height, border, data.reference, srcOffset, srcLengthOverride)
  }
  
  public func compressedTexSubImage2D(target: GLenum, level: GLint, xoffset: GLint, yoffset: GLint, width: GLsizei, height: GLsizei, format: GLenum, data: ArrayBufferView, srcOffset: GLuint, srcLengthOverride: GLuint = 0) {
    WebGL2RenderingContextCompressedTexSubImage2D1(reference, target, level, xoffset, yoffset, width, height, format, data.reference, srcOffset, srcLengthOverride)
  }
  
  public func compressedTexImage3D(target: GLenum, level: GLint, internalformat: GLenum, width: GLsizei, height: GLsizei, depth: GLsizei, border: GLint, data: ArrayBufferView, srcOffset: GLuint = 0, srcLengthOverride: GLuint = 0) {
    WebGL2RenderingContextCompressedTexImage3D0(reference, target, level, internalformat, width, height, depth, border, data.reference, srcOffset, srcLengthOverride)
  }
  
  public func compressedTexSubImage3D(target: GLenum, level: GLint, xoffset: GLint, yoffset: GLint, zoffset: GLint, width: GLsizei, height: GLsizei, depth: GLsizei, format: GLenum, data: ArrayBufferView, srcOffset: GLuint = 0, srcLengthOverride: GLuint = 0) {
    WebGL2RenderingContextCompressedTexSubImage3D0(reference, target, level, xoffset, yoffset, zoffset, width, height, depth, format, data.reference, srcOffset, srcLengthOverride)
  }
  
  public func compressedTexImage2D(target: GLenum, level: GLint, internalformat: GLenum,
                                   width: GLsizei, height: GLsizei, border: GLint,
                                   imageSize: GLsizei, offset: GLintptr) {
    WebGL2RenderingContextCompressedTexImage2D2(reference, target, level, internalformat, width, height, border, imageSize, offset)
  }
  
  public func compressedTexSubImage2D(target: GLenum, level: GLint, xoffset: GLint, yoffset: GLint,
                                      width: GLsizei, height: GLsizei, format: GLenum,
                                      imageSize: GLsizei, offset: GLintptr) {
    WebGL2RenderingContextCompressedTexSubImage2D2(reference, target, level, xoffset, yoffset, width, height, format, imageSize, offset)
  }
  
  public func compressedTexImage3D(target: GLenum, level: GLint, internalformat: GLenum,
                                   width: GLsizei, height: GLsizei, depth: GLsizei, border: GLint,
                                   imageSize: GLsizei, offset: GLintptr) {
    WebGL2RenderingContextCompressedTexImage3D1(reference, target, level, internalformat, width, height, depth, border, imageSize, offset)
  }
  
  public func compressedTexSubImage3D(target: GLenum, level: GLint, xoffset: GLint, yoffset: GLint, zoffset: GLint,
                                      width: GLsizei, height: GLsizei, depth: GLsizei, format: GLenum,
                                      imageSize: GLsizei, offset: GLintptr) {
    WebGL2RenderingContextCompressedTexSubImage3D1(reference, target, level, xoffset, yoffset, zoffset, width, height, depth, format, imageSize, offset)
  }

  public func getFragDataLocation(program: WebGLProgram, name: String) -> GLint {
    return name.withCString {
      return WebGL2RenderingContextGetFragDataLocation(reference, program.reference, $0)
    }
  }

    /* Uniforms and attributes */
  public func uniform1ui(location: WebGLUniformLocation, v0: GLuint) {
    WebGL2RenderingContextUniform1ui(reference, location.reference, v0)
  }

  public func uniform2ui(location: WebGLUniformLocation, v0: GLuint, v1: GLuint) {
    WebGL2RenderingContextUniform2ui(reference, location.reference, v0, v1)
  }

  public func uniform3ui(location: WebGLUniformLocation, v0: GLuint, v1: GLuint, v2: GLuint) {
    WebGL2RenderingContextUniform3ui(reference, location.reference, v0, v1, v2)
  }

  public func uniform4ui(location: WebGLUniformLocation, v0: GLuint, v1: GLuint, v2: GLuint, v3: GLuint) {
    WebGL2RenderingContextUniform4ui(reference, location.reference, v0, v1, v2, v3)
  }

  public func uniform1fv(location: WebGLUniformLocation, v: Float32Array, srcOffset: GLuint, srcLength: GLuint = 0) {
    WebGL2RenderingContextUniform1fv2(reference, location.reference, v.reference, srcOffset, srcLength)
  }
  
  public func uniform1fv(location: WebGLUniformLocation, v: [GLfloat], srcOffset: GLuint, srcLength: GLuint = 0) {
    v.withUnsafeBufferPointer {
      WebGL2RenderingContextUniform1fv3(reference, location.reference, CInt(v.count), $0.baseAddress!, srcOffset, srcLength)
    }
  }
  
  public func uniform2fv(location: WebGLUniformLocation, v: Float32Array, srcOffset: GLuint, srcLength: GLuint = 0) {
    WebGL2RenderingContextUniform2fv2(reference, location.reference, v.reference, srcOffset, srcLength)
  }
  
  public func uniform2fv(location: WebGLUniformLocation, v: [GLfloat], srcOffset: GLuint, srcLength: GLuint = 0) {
    v.withUnsafeBufferPointer {
      WebGL2RenderingContextUniform2fv3(reference, location.reference, CInt(v.count), $0.baseAddress!, srcOffset, srcLength)
    }
  }
  
  public func uniform3fv(location: WebGLUniformLocation, v: Float32Array, srcOffset: GLuint, srcLength: GLuint = 0) {
    WebGL2RenderingContextUniform3fv2(reference, location.reference, v.reference, srcOffset, srcLength)
  }
  
  public func uniform3fv(location: WebGLUniformLocation, v: [GLfloat], srcOffset: GLuint, srcLength: GLuint = 0) {
    v.withUnsafeBufferPointer {
      WebGL2RenderingContextUniform3fv3(reference, location.reference, CInt(v.count), $0.baseAddress!, srcOffset, srcLength)
    }
  }
  
  public func uniform4fv(location: WebGLUniformLocation, v: Float32Array, srcOffset: GLuint, srcLength: GLuint = 0) {
    WebGL2RenderingContextUniform4fv2(reference, location.reference, v.reference, srcOffset, srcLength)
  }
  
  public func uniform4fv(location: WebGLUniformLocation, v: [GLfloat], srcOffset: GLuint, srcLength: GLuint = 0) {
    v.withUnsafeBufferPointer {
      WebGL2RenderingContextUniform4fv3(reference, location.reference, CInt(v.count), $0.baseAddress!, srcOffset, srcLength)
    }
  }
  
  public func uniform1iv(location: WebGLUniformLocation, v: Int32Array, srcOffset: GLuint, srcLength: GLuint = 0) {
    WebGL2RenderingContextUniform1iv2(reference, location.reference, v.reference, srcOffset, srcLength)
  }
  
  public func uniform1iv(location: WebGLUniformLocation, v: [GLint], srcOffset: GLuint, srcLength: GLuint = 0) {
    v.withUnsafeBufferPointer {
      WebGL2RenderingContextUniform1iv3(reference, location.reference, CInt(v.count), $0.baseAddress!, srcOffset, srcLength)
    }
  }
  
  public func uniform2iv(location: WebGLUniformLocation, v: Int32Array, srcOffset: GLuint, srcLength: GLuint = 0) {
    WebGL2RenderingContextUniform2iv3(reference, location.reference, v.reference, srcOffset, srcLength)
  }
  
  public func uniform2iv(location: WebGLUniformLocation, v: [GLint], srcOffset: GLuint, srcLength: GLuint = 0) {
    v.withUnsafeBufferPointer {
      WebGL2RenderingContextUniform2iv2(reference, location.reference, CInt(v.count), $0.baseAddress!, srcOffset, srcLength)
    }
  }
  
  public func uniform3iv(location: WebGLUniformLocation, v: Int32Array, srcOffset: GLuint, srcLength: GLuint = 0) {
    WebGL2RenderingContextUniform3iv2(reference, location.reference, v.reference, srcOffset, srcLength)
  }
  
  public func uniform3iv(location: WebGLUniformLocation, v: [GLint], srcOffset: GLuint, srcLength: GLuint = 0) {
    v.withUnsafeBufferPointer {
      WebGL2RenderingContextUniform3iv3(reference, location.reference, CInt(v.count), $0.baseAddress!, srcOffset, srcLength)
    }
  }
  
  public func uniform4iv(location: WebGLUniformLocation, v: Int32Array, srcOffset: GLuint, srcLength: GLuint = 0) {
    WebGL2RenderingContextUniform4iv2(reference, location.reference, v.reference, srcOffset, srcLength)
  }
  
  public func uniform4iv(location: WebGLUniformLocation, v: [GLint], srcOffset: GLuint, srcLength: GLuint = 0) {
    v.withUnsafeBufferPointer {
      WebGL2RenderingContextUniform4iv3(reference, location.reference, CInt(v.count), $0.baseAddress!, srcOffset, srcLength)
    }
  }
  
  public func uniform1uiv(location: WebGLUniformLocation, v: Uint32Array, srcOffset: GLuint = 0, srcLength: GLuint = 0) {
    WebGL2RenderingContextUniform1uiv0(reference, location.reference, v.reference, srcOffset , srcLength)
  }
  
  public func uniform1uiv(location: WebGLUniformLocation, v: [GLuint], srcOffset: GLuint = 0, srcLength: GLuint = 0) {
    v.withUnsafeBufferPointer {
      WebGL2RenderingContextUniform1uiv1(reference, location.reference, CInt(v.count), $0.baseAddress!, srcOffset , srcLength)
    }
  }
  
  public func uniform2uiv(location: WebGLUniformLocation, v: Uint32Array, srcOffset: GLuint = 0, srcLength: GLuint = 0) {
    WebGL2RenderingContextUniform2uiv0(reference, location.reference, v.reference, srcOffset , srcLength)
  }
  
  public func uniform2uiv(location: WebGLUniformLocation, v: [GLuint], srcOffset: GLuint = 0, srcLength: GLuint = 0) {
    v.withUnsafeBufferPointer {
      WebGL2RenderingContextUniform2uiv1(reference, location.reference, CInt(v.count), $0.baseAddress!, srcOffset , srcLength)
    }
  }
  
  public func uniform3uiv(location: WebGLUniformLocation, v: Uint32Array, srcOffset: GLuint = 0, srcLength: GLuint = 0) {
    WebGL2RenderingContextUniform3uiv0(reference, location.reference, v.reference, srcOffset , srcLength)
  }
  
  public func uniform3uiv(location: WebGLUniformLocation, v: [GLuint], srcOffset: GLuint = 0, srcLength: GLuint = 0) {
    v.withUnsafeBufferPointer {
      WebGL2RenderingContextUniform3uiv1(reference, location.reference, CInt(v.count), $0.baseAddress!, srcOffset, srcLength)
    }
  }
  
  public func uniform4uiv(location: WebGLUniformLocation, v: Uint32Array, srcOffset: GLuint = 0, srcLength: GLuint = 0) {
    WebGL2RenderingContextUniform4uiv0(reference, location.reference, v.reference, srcOffset, srcLength)
  }
  
  public func uniform4uiv(location: WebGLUniformLocation, v: [GLuint], srcOffset: GLuint = 0, srcLength: GLuint = 0) {
    v.withUnsafeBufferPointer {
      WebGL2RenderingContextUniform4uiv1(reference, location.reference, CInt(v.count), $0.baseAddress!, srcOffset , srcLength)
    }
  }

  public func uniformMatrix2fv(location: WebGLUniformLocation, transpose: GLboolean, array: Float32Array, srcOffset: GLuint, srcLength: GLuint = 0) {
    WebGL2RenderingContextUniformMatrix2fv2(reference, location.reference, transpose, array.reference, srcOffset, srcLength)
  }
  
  public func uniformMatrix2fv(location: WebGLUniformLocation, transpose: GLboolean, array: [GLfloat], srcOffset: GLuint, srcLength: GLuint = 0) {
    array.withUnsafeBufferPointer {
      WebGL2RenderingContextUniformMatrix2fv3(reference, location.reference, transpose, CInt(array.count), $0.baseAddress!, srcOffset, srcLength)
    }
  }
  
  public func uniformMatrix3fv(location: WebGLUniformLocation, transpose: GLboolean, array: Float32Array, srcOffset: GLuint, srcLength: GLuint = 0) {
    WebGL2RenderingContextUniformMatrix3fv2(reference, location.reference, transpose, array.reference, srcOffset, srcLength)
  }
  
  public func uniformMatrix3fv(location: WebGLUniformLocation, transpose: GLboolean, array: [GLfloat], srcOffset: GLuint, srcLength: GLuint = 0) {
    array.withUnsafeBufferPointer {
      WebGL2RenderingContextUniformMatrix3fv3(reference, location.reference, transpose, CInt(array.count), $0.baseAddress!, srcOffset, srcLength)            
    }
  }
  
  public func uniformMatrix4fv(location: WebGLUniformLocation, transpose: GLboolean, array: Float32Array, srcOffset: GLuint, srcLength: GLuint = 0) {
    WebGL2RenderingContextUniformMatrix4fv2(reference, location.reference, transpose, array.reference, srcOffset, srcLength)
  }
  
  public func uniformMatrix4fv(location: WebGLUniformLocation, transpose: GLboolean, array: [GLfloat], srcOffset: GLuint, srcLength: GLuint = 0) {
    array.withUnsafeBufferPointer {                      
      WebGL2RenderingContextUniformMatrix4fv3(reference, location.reference, transpose, CInt(array.count), $0.baseAddress!, srcOffset, srcLength)
    }
  }
  
  public func uniformMatrix2x3fv(location: WebGLUniformLocation, transpose: GLboolean, value: Float32Array, srcOffset: GLuint = 0, srcLength:GLuint = 0) {
    WebGL2RenderingContextUniformMatrix2x3fv0(reference, location.reference, transpose, value.reference, srcOffset, srcLength)
  }
  
  public func uniformMatrix2x3fv(location: WebGLUniformLocation, transpose: GLboolean, value: [GLfloat], srcOffset: GLuint = 0, srcLength: GLuint = 0) {
    value.withUnsafeBufferPointer {
      WebGL2RenderingContextUniformMatrix2x3fv1(reference, location.reference, transpose, CInt(value.count), $0.baseAddress!, srcOffset, srcLength)
    }
  }

  public func uniformMatrix3x2fv(location: WebGLUniformLocation, transpose: GLboolean, value: Float32Array, srcOffset: GLuint = 0, srcLength: GLuint = 0) {
    WebGL2RenderingContextUniformMatrix3x2fv0(reference, location.reference, transpose, value.reference, srcOffset, srcLength)
  }
  
  public func uniformMatrix3x2fv(location: WebGLUniformLocation, transpose: GLboolean, value: [GLfloat], srcOffset: GLuint = 0, srcLength: GLuint = 0) {
    value.withUnsafeBufferPointer {
      WebGL2RenderingContextUniformMatrix3x2fv1(reference, location.reference, transpose, CInt(value.count), $0.baseAddress!, srcOffset, srcLength)
    }
  }
  
  public func uniformMatrix2x4fv(location: WebGLUniformLocation, transpose: GLboolean, value: Float32Array, srcOffset: GLuint = 0, srcLength: GLuint = 0) {
    WebGL2RenderingContextUniformMatrix2x4fv0(reference, location.reference, transpose, value.reference, srcOffset, srcLength)
  }
  
  public func uniformMatrix2x4fv(location: WebGLUniformLocation, transpose: GLboolean, value: [GLfloat], srcOffset:GLuint = 0, srcLength: GLuint = 0) {
    value.withUnsafeBufferPointer {
      WebGL2RenderingContextUniformMatrix2x4fv1(reference, location.reference, transpose, CInt(value.count), $0.baseAddress!, srcOffset, srcLength)
    }
  }
  
  public func uniformMatrix4x2fv(location: WebGLUniformLocation, transpose: GLboolean, value: Float32Array, srcOffset: GLuint = 0, srcLength: GLuint = 0) {
    WebGL2RenderingContextUniformMatrix4x2fv0(reference, location.reference, transpose, value.reference, srcOffset, srcLength)
  }
  
  public func uniformMatrix4x2fv(location: WebGLUniformLocation, transpose: GLboolean, value: [GLfloat], srcOffset: GLuint = 0, srcLength: GLuint = 0) {
    value.withUnsafeBufferPointer {
      WebGL2RenderingContextUniformMatrix4x2fv1(reference, location.reference, transpose,  CInt(value.count), $0.baseAddress!, srcOffset, srcLength)
    }
  }
  
  public func uniformMatrix3x4fv(location: WebGLUniformLocation, transpose: GLboolean, value: Float32Array, srcOffset: GLuint = 0, srcLength: GLuint = 0) {
    WebGL2RenderingContextUniformMatrix3x4fv0(reference, location.reference, transpose, value.reference, srcOffset, srcLength)
  }

  public func uniformMatrix3x4fv(location: WebGLUniformLocation, transpose: GLboolean, value: [GLfloat], srcOffset: GLuint = 0, srcLength: GLuint = 0) {
    value.withUnsafeBufferPointer {
      WebGL2RenderingContextUniformMatrix3x4fv1(reference, location.reference, transpose,  CInt(value.count), $0.baseAddress!, srcOffset, srcLength)
    }
  }
  
  public func uniformMatrix4x3fv(location: WebGLUniformLocation, transpose: GLboolean, value: Float32Array, srcOffset: GLuint = 0, srcLength: GLuint = 0) {
    WebGL2RenderingContextUniformMatrix4x3fv0(reference, location.reference, transpose, value.reference, srcOffset, srcLength)
  }

  public func uniformMatrix4x3fv(location: WebGLUniformLocation, transpose: GLboolean, value: [GLfloat], srcOffset: GLuint = 0, srcLength: GLuint = 0) {
    value.withUnsafeBufferPointer {
      WebGL2RenderingContextUniformMatrix4x3fv1(reference, location.reference, transpose, CInt(value.count), $0.baseAddress!, srcOffset, srcLength)
    }
  }

  public func vertexAttribI4i(index: GLuint, x: GLint, y: GLint, z: GLint, w: GLint) {
    WebGL2RenderingContextVertexAttribI4i(reference, index, x, y, z, w)
  }
  
  public func vertexAttribI4iv(index: GLuint, v: Int32Array) {
    WebGL2RenderingContextVertexAttribI4iv0(reference, index, v.reference)
  }
  
  public func vertexAttribI4iv(index: GLuint, v: [GLint]) {
    v.withUnsafeBufferPointer {
      WebGL2RenderingContextVertexAttribI4iv1(reference, index, CInt(v.count), $0.baseAddress!)
    }
  }
  
  public func vertexAttribI4ui(index: GLuint, x: GLuint, y: GLuint, z: GLuint, w: GLuint) {
    WebGL2RenderingContextVertexAttribI4ui(reference, index, x, y, z, w)
  }
  
  public func vertexAttribI4uiv(index: GLuint, v: Uint32Array) {
    WebGL2RenderingContextVertexAttribI4uiv0(reference, index, v.reference)
  }

  public func vertexAttribI4uiv(index: GLuint, v: [GLuint]) {
    v.withUnsafeBufferPointer {
      WebGL2RenderingContextVertexAttribI4uiv1(reference, index, CInt(v.count), $0.baseAddress!)
    }
  }

  public func vertexAttribIPointer(index: GLuint, size: GLint, type: GLenum, stride: GLsizei, offset: GLintptr) {
    WebGL2RenderingContextVertexAttribIPointer(reference, index, size, type, stride, offset)
  }

  public func vertexAttribDivisor(index: GLuint, divisor: GLuint) {
    WebGL2RenderingContextVertexAttribDivisor(reference, index, divisor)
  }

  public func drawArraysInstanced(mode: GLenum, first: GLint, count: GLsizei, instanceCount: GLsizei) {
    WebGL2RenderingContextDrawArraysInstanced(reference, mode, first, count, instanceCount)
  }
  
  public func drawElementsInstanced(mode: GLenum, count: GLsizei, type: GLenum, offset: GLintptr, instanceCount: GLsizei) {
    WebGL2RenderingContextDrawElementsInstanced(reference, mode, count, type, offset, instanceCount)
  }

  public func drawRangeElements(mode: GLenum, start: GLuint, end: GLuint, count: GLsizei, type: GLenum, offset: GLintptr) {
    WebGL2RenderingContextDrawRangeElements(reference, mode, start, end, count, type, offset)
  }

  public func drawBuffers(_ buffers: [GLenum]) {
    buffers.withUnsafeBufferPointer {
      WebGL2RenderingContextDrawBuffers(reference, CInt(buffers.count), $0.baseAddress!)
    }
  }

  public func clearBufferiv(buffer: GLenum, drawbuffer: GLint, value: Int32Array, srcOffset: GLuint = 0) {
    WebGL2RenderingContextClearBufferiv0(reference, buffer, drawbuffer, value.reference, srcOffset)
  }

  public func clearBufferiv(buffer: GLenum, drawbuffer: GLint, value: [GLint], srcOffset: GLuint = 0) {
    value.withUnsafeBufferPointer {
      WebGL2RenderingContextClearBufferiv1(reference, buffer, drawbuffer, CInt(value.count), $0.baseAddress!, srcOffset)
    }
  }

  public func clearBufferuiv(buffer: GLenum, drawbuffer: GLint, value: Uint32Array, srcOffset: GLuint = 0) {
    WebGL2RenderingContextClearBufferuiv0(reference, buffer, drawbuffer, value.reference, srcOffset)
  }

  public func clearBufferuiv(buffer: GLenum, drawbuffer: GLint, value: [GLuint], srcOffset: GLuint = 0) {
    value.withUnsafeBufferPointer {
      WebGL2RenderingContextClearBufferuiv1(reference, buffer, drawbuffer, CInt(value.count), $0.baseAddress!, srcOffset)
    }
  }

  public func clearBufferfv(buffer: GLenum, drawbuffer: GLint, value: Float32Array, srcOffset: GLuint = 0) {
    WebGL2RenderingContextClearBufferfv0(reference, buffer, drawbuffer, value.reference, srcOffset)
  }

  public func clearBufferfv(buffer: GLenum, drawbuffer: GLint, value: [GLfloat], srcOffset: GLuint = 0) {
    value.withUnsafeBufferPointer {
      WebGL2RenderingContextClearBufferfv1(reference, buffer, drawbuffer, CInt(value.count), $0.baseAddress!, srcOffset)
    }
  }

  public func clearBufferfi(buffer: GLenum, drawbuffer: GLint, depth: GLfloat, stencil: GLint) {
    WebGL2RenderingContextClearBufferfi(reference, buffer, drawbuffer, depth, stencil)
  }

  /* Query Objects */
  public func createQuery() -> WebGLQuery? {
    guard let ref = WebGL2RenderingContextCreateQuery(reference) else {
      return nil
    }
    return WebGLQuery(reference: ref)
  }

  public func deleteQuery(query: WebGLQuery) {
    WebGL2RenderingContextDeleteQuery(reference, query.reference)
  }

  public func isQuery(query: WebGLQuery) -> GLboolean {
    return WebGL2RenderingContextIsQuery(reference, query.reference)
  }

  public func beginQuery(target: GLenum, query: WebGLQuery) {
    WebGL2RenderingContextBeginQuery(reference, target, query.reference)
  }

  public func endQuery(target: GLenum) {
    WebGL2RenderingContextEndQuery(reference, target)
  }

  public func getQuery(target: GLenum, name: GLenum) -> Any? {
    // void* WebGL2RenderingContextGetQuery(reference, target, name)
    return nil
  }

  public func getQueryParameter(query: WebGLQuery, name: GLenum) -> Any? {
    // void* WebGL2RenderingContextGetQueryParameter(reference, WebGLQueryRef query, name)
    return nil
  }

  /* Sampler Objects */
  public func createSampler() -> WebGLSampler {
    return WebGLSampler(reference: WebGL2RenderingContextCreateSampler(reference))
  }

  public func deleteSampler(sampler: WebGLSampler) {
    WebGL2RenderingContextDeleteSampler(reference, sampler.reference)
  }

  public func isSampler(sampler: WebGLSampler) -> GLboolean {
    return WebGL2RenderingContextIsSampler(reference, sampler.reference)
  }

  public func bindSampler(unit: GLuint, sampler: WebGLSampler) {
    WebGL2RenderingContextBindSampler(reference, unit, sampler.reference)
  }

  public func samplerParameteri(sampler: WebGLSampler, name: GLenum, param: GLint) {
    WebGL2RenderingContextSamplerParameteri(reference, sampler.reference, name, param)
  }

  public func samplerParameterf(sampler: WebGLSampler, name: GLenum, param: GLfloat) {
    WebGL2RenderingContextSamplerParameterf(reference, sampler.reference, name, param)
  }

  public func getSamplerParameter(sampler: WebGLSampler, name: GLenum) -> Any? {
    //void* WebGL2RenderingContextGetSamplerParameter(reference, sampler.reference, name)
    return nil
  }


  public func fenceSync(condition: GLenum, flags: GLbitfield) -> WebGLSync? {
    guard let ref = WebGL2RenderingContextFenceSync(reference, condition, flags) else {
      return nil
    }
    return WebGLSync(reference: ref)
  }

  public func isSync(sync: WebGLSync) -> GLboolean {
    WebGL2RenderingContextIsSync(reference, sync.reference)
  }

  public func deleteSync(sync: WebGLSync) {
    WebGL2RenderingContextDeleteSync(reference, sync.reference)
  }

  public func clientWaitSync(sync: WebGLSync, flags: GLbitfield, timeout: GLuint64) -> GLenum {
    WebGL2RenderingContextClientWaitSync(reference, sync.reference, flags, timeout)
  }
  
  public func waitSync(sync: WebGLSync, flags: GLbitfield, timeout: GLint64) {
    WebGL2RenderingContextWaitSync(reference, sync.reference, flags, timeout)
  }

  public func getSyncParameter(sync: WebGLSync, name: GLenum) -> Any? {
    //void* WebGL2RenderingContextGetSyncParameter(reference, WebGLSyncRef sync, name)
    return nil
  }
      /* Transform Feedback */
  public func createTransformFeedback() -> WebGLTransformFeedback {
    return WebGLTransformFeedback(reference: WebGL2RenderingContextCreateTransformFeedback(reference)!)
  }

  public func deleteTransformFeedback(feedback: WebGLTransformFeedback) {
    WebGL2RenderingContextDeleteTransformFeedback(reference, feedback.reference)
  }
  
  public func isTransformFeedback(feedback: WebGLTransformFeedback) -> GLboolean {
    WebGL2RenderingContextIsTransformFeedback(reference, feedback.reference)
  }
  
  public func bindTransformFeedback(target: GLenum, feedback: WebGLTransformFeedback) {
    WebGL2RenderingContextBindTransformFeedback(reference, target, feedback.reference)
  }
  
  public func beginTransformFeedback(primitiveMode: GLenum) {
    WebGL2RenderingContextBeginTransformFeedback(reference, primitiveMode)
  }
  
  public func endTransformFeedback() {
    WebGL2RenderingContextEndTransformFeedback(reference)
  }

  public func transformFeedbackVaryings(program: WebGLProgram, varyings: [String], bufferMode: GLenum) {
    //WebGL2RenderingContextTransformFeedbackVaryings(reference, WebGLProgramRef program, char** varyings, bufferMode)
  }

  public func getTransformFeedbackVarying(program: WebGLProgram, index: GLuint) -> WebGLActiveInfo? {
    guard let ref = WebGL2RenderingContextGetTransformFeedbackVarying(reference, program.reference, index) else {
      return nil
    }
    return WebGLActiveInfo(reference: ref)
  }
  
  public func pauseTransformFeedback() {
    WebGL2RenderingContextPauseTransformFeedback(reference) 
  }
  
  public func resumeTransformFeedback() {
    WebGL2RenderingContextResumeTransformFeedback(reference)
  }

   /* Uniform Buffer Objects and Transform Feedback Buffers */
  public func bindBufferBase(target: GLenum, index: GLuint, buffer: WebGLBuffer) {
    WebGL2RenderingContextBindBufferBase(reference, target, index, buffer.reference)
  }

  public func bindBufferRange(target: GLenum, index: GLuint, buffer: WebGLBuffer, offset: GLintptr, size: GLsizeiptr) {
    WebGL2RenderingContextBindBufferRange(reference, target, index, buffer.reference, offset, size)
  }
  
  public func getIndexedParameter(target: GLenum, index: GLuint) -> Any? {
    // ??
    //void* WebGL2RenderingContextGetIndexedParameter(reference, target, index)
    return nil
  }
  
  public func getUniformIndices(program: WebGLProgram, uniformNames: [String]) -> [GLuint] {
    //WebGL2RenderingContextGetUniformIndices(reference, WebGLProgramRef program, const char** uniformNames, GLuint* indices_out)
    return []
  }

  public func getActiveUniforms(program: WebGLProgram, uniformIndices: [GLuint], name: GLenum) -> Any? {
    // ??
    return nil
    //void* WebGL2RenderingContextGetActiveUniforms(reference, WebGLProgramRef program, GLuint* uniformIndices, name)
  }
  
  public func getUniformBlockIndex(program: WebGLProgram, uniformBlockName: String) -> GLuint {
    return uniformBlockName.withCString {
      return WebGL2RenderingContextGetUniformBlockIndex(reference, program.reference, $0)
    }
  }

  public func getActiveUniformBlockParameter(program: WebGLProgram, uniformBlockIndex: GLuint, name: GLenum) -> Any? {
    return nil // ??
    //void* WebGL2RenderingContextGetActiveUniformBlockParameter(reference, WebGLProgramRef program, uniformBlockIndex, name)
  }

  public func getActiveUniformBlockName(program: WebGLProgram, uniformBlockIndex: GLuint) -> String? {
    var len: CInt = 0      
    guard let ref = WebGL2RenderingContextGetActiveUniformBlockName(reference, program.reference, uniformBlockIndex, &len) else {
      return nil
    }
    return String(bytesNoCopy: ref, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
  }

  public func uniformBlockBinding(program: WebGLProgram, uniformBlockIndex: GLuint, uniformBlockBinding: GLuint) {
    WebGL2RenderingContextUniformBlockBinding(reference, program.reference, uniformBlockIndex, uniformBlockBinding)
  }

  /* Vertex Array Objects */
  public func createVertexArray() -> WebGLVertexArrayObject? {
    guard let ref = WebGL2RenderingContextCreateVertexArray(reference) else {
      return nil
    }
    return WebGLVertexArrayObject(reference: ref)
  }
  
  public func deleteVertexArray(_ vertexArray: WebGLVertexArrayObject) {
    WebGL2RenderingContextDeleteVertexArray(reference, vertexArray.reference)
  }

  public func isVertexArray(_ vertexArray: WebGLVertexArrayObject) -> GLboolean {
    return WebGL2RenderingContextIsVertexArray(reference, vertexArray.reference)
  }
  
  public func bindVertexArray(_ vertexArray: WebGLVertexArrayObject) {
    WebGL2RenderingContextBindVertexArray(reference, vertexArray.reference)
  }

  /* Reading */
  public func readPixels(x: GLint, y: GLint, width: GLsizei, height: GLsizei, format: GLenum, type: GLenum, dstData: ArrayBufferView, offset: GLintptr) {
    WebGL2RenderingContextReadPixels0(reference, x, y, width, height, format, type, dstData.reference, offset);
  }

  public func readPixels(x: GLint, y: GLint, width: GLsizei, height: GLsizei, format: GLenum, type: GLenum, offset: GLintptr) {
    WebGL2RenderingContextReadPixels1(reference, x, y, width, height, format, type, offset)
  }

}
