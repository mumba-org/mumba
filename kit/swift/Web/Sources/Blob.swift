// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class BlobData {
  
  public var contentType: String {
    get {
      var size: CInt = 0
      let buf = _BlobDataGetContentType(reference, &size)
      return buf != nil ? String(bytesNoCopy: buf!, length: Int(size), encoding: String.Encoding.utf8, freeWhenDone: true)! : String()
    }
    set {
      newValue.withCString {
        _BlobDataSetContentType(reference, $0)
      }
    }
  }
  
  public var length: UInt64 {
    return _BlobDataGetLength(reference)
  }

  var reference: BlobDataRef
  
  public init() {
    reference = _BlobDataCreateEmpty()
  }

  public init(file: String) {
    reference = file.withCString {
      return _BlobDataCreateForFile($0)
    }
  }

  init(reference: BlobDataRef) {
    self.reference = reference
  }

  deinit {
    _BlobDataDestroy(reference)
  }

  public func append(bytes: UnsafePointer<UInt8>?, byteCount: UInt) {
    _BlobDataAppendBytes(reference, bytes, Int(byteCount))
  }
  
  public func append(file: String, offset: Int64, length: Int64, expectedModificationTime: Double = 0.0) {
    file.withCString {
    _BlobDataAppendFile(
      reference,
      $0,
      offset,
      length,
      expectedModificationTime)
    }
  }
  
  public func append(blob: BlobData, offset: Int64, length: Int64) {
    _BlobDataAppendBlobData(
      reference,
      blob.reference,
      offset,
      length)
  }

  public func append(handle: BlobDataHandle, offset: Int64, length: Int64) {
    _BlobDataAppendBlobDataHandle(
      reference,
      handle.reference,
      offset,
      length)
  }

  public func append(fileurl: String, offset: Int64, length: Int64, expectedModificationTime: Double = 0.0) {
    fileurl.withCString {
      _BlobDataAppendFileSystemURL(
        reference,
        $0,
        offset,
        length,
        expectedModificationTime)
    }
  }

  public func append(text: String, normalizeLineEndingsToNative: Bool = false) {
    text.withCString {
      _BlobDataAppendText(reference, $0, normalizeLineEndingsToNative ? 1 : 0)
    }
  }

}

public class BlobDataHandle {
  
  var reference: BlobDataHandleRef

  public init() {
    reference = _BlobDataHandleCreateEmpty()
  }

  public init(data: BlobData, size: Int64) {
    reference = _BlobDataHandleCreateData(data.reference, size)
  }

  public init(uuid: String, type: String, size: Int64) {
    reference = uuid.withCString { uuidCstr in
      return type.withCString { typeCstr in
        return _BlobDataHandleCreateUUID(uuidCstr, typeCstr, size)
      }
    }
  }

  init(reference: BlobDataHandleRef) {
    self.reference = reference
  }

  deinit {
    _BlobDataHandleDestroy(reference)
  }

}

public struct Blob {
    
    var reference: BlobRef

    public init() {
      reference = _BlobCreateEmpty()
    }

    public init(bytes: UnsafePointer<UInt8>?, byteCount: UInt, contentType: String) {
      let ref = contentType.withCString {
        return _BlobCreateBytes(bytes, UInt32(byteCount), $0)
      }
      self.reference = ref!
    }

    public init(data: BlobData, size: Int64) {
      reference = _BlobCreateData(data.reference, size)
    }

    public init(handle: BlobDataHandle) {
      reference = _BlobCreateDataHandle(handle.reference);
    }

    init(reference: BlobRef) {
        self.reference = reference
    }

}