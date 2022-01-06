// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class WebHTTPBody {
    
    public struct Element {
        
        public enum Kind : Int { 
            case Data = 0
            case File
            case Blob
            case FileSystemURL 
        }
        
        public var kind: Kind
        public var data: WebData?
        public var filePath: String
        public var fileStart: Int64
        public var fileLength: Int64
        public var modificationTime: Double
        public var fileSystemURL: String
        public var blobUUID: String
    }

    public var elementCount: Int {
        return Int(_WebHTTPBodyGetElementCount(reference))
    }

    public var identifier: Int64 {

        get {
            return _WebHTTPBodyGetIdentifier(reference)
        }
        
        set {
            _WebHTTPBodySetIdentifier(reference, newValue)
        }

    }

    public var containsPasswordData: Bool {
        
        get {
            return _WebHTTPBodyGetContainsPasswordData(reference) == 0 ? false : true
        }

        set {
            _WebHTTPBodySetContainsPasswordData(reference, newValue ? 1 : 0)   
        }

    }

    public subscript(_ index: Int) -> Element? {
        var kind: Int32 = 0
        var dataSize2: Int32 = 0
        var file: UnsafePointer<CChar>?
        var start: Int64 = 0
        var len: Int64 = 0
        var mod: Double = 0.0
        var uuid: UnsafePointer<CChar>?

        let dataSize = _WebHTTPBodyGetElementDataSizeAt(
            reference, 
            Int32(index))

        // -1 = theres no element
        if dataSize == -1 {
            return nil
        }

        let data = UnsafeMutableRawPointer.allocate(byteCount: Int(dataSize), alignment: 1)
        let ptr = data.bindMemory(to: UInt8.self, capacity: Int(dataSize))

        _WebHTTPBodyGetElementAt(
            reference,
            Int32(index),
            &kind,
            ptr,
            &dataSize2,
            &file,
            &start,
            &len,
            &mod,
            &uuid)

        return Element(
            kind: Element.Kind(rawValue: Int(kind))!,
            data: WebData(data: data, size: Int(dataSize), owned: true),
            filePath: String(cString: file!),
            fileStart: start,
            fileLength: len,
            modificationTime: mod,
            fileSystemURL: String(),
            blobUUID: String(cString: uuid!))
    }

    var reference: WebHTTPBodyRef

    public init() {
        reference = _WebHTTPBodyCreate()
    }

    init(reference: WebHTTPBodyRef) {
        self.reference = reference
    }

    deinit {
        _WebHTTPBodyDestroy(reference)
    }
 
    public func append(data: WebData) {
      if let databuf = data.data?.bindMemory(to: UInt8.self, capacity: data.size) {
        _WebHTTPBodyAppendData(reference, databuf, CInt(data.size))
      }
    }

    public func append(file: String){
        file.withCString { filebuf in
            _WebHTTPBodyAppendFile(reference, filebuf)
        }
    }

    public func append(file: String, fileStart: Int64, fileLength: Int64, modificationTime: Double) {
        file.withCString { strbuf in
            _WebHTTPBodyAppendFileRange(reference, strbuf, fileStart, fileLength, modificationTime)
        }
    }

    public func append(blob: String) {
        blob.withCString { strbuf in
            _WebHTTPBodyAppendBlob(reference, strbuf)
        }
    }

    //public func append(filesystem: URL, start: Int64, length: Int64, modificationTime: Double) {
    //    filesystem.absoluteString.withCString { fsurl in
    //        _WebHTTPBodyAppendFileSystemURLRange(reference, fsurl, start, length, modificationTime)
    //    }
    //}

}