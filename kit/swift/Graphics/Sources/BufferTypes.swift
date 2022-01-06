// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public enum BufferFormat {
  case ATC
  case ATCIA
  case DXT1
  case DXT5
  case ETC1
  case R_8
  case RGBA_4444
  case RGBX_8888
  case RGBA_8888
  case BGRX_8888
  case BGRA_8888
  case YUV_420
  case YUV_420_BIPLANAR
  case UYVY_422
}

public enum BufferUsage {
  case GpuRead
  case Scanout
  case GpuReadCpuReadWrite
  case GpuReadCpuReadWritePersistent
}
