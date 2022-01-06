// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Javascript

public struct Url {
    
    public static func createObjectURL(blob: Blob) -> String {
        var len: CInt = 0
        let strbuf = _DOMUrlCreateObjectURLForBlob(blob.reference, &len)
        return String(bytesNoCopy: strbuf!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }

    public static func createObjectURL(document: WebDocument, blob: Blob) -> String {
        var len: CInt = 0
        print("DOMUrl.DOMUrl: execution_context = \(document.reference)")
        let strbuf = _DOMUrlCreateObjectURLForBlobWithContext(document.reference, blob.reference, &len)
        return String(bytesNoCopy: strbuf!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }

    public static func createObjectURL(document: WebDocument, source: MediaSource) -> String {
        var len: CInt = 0
        print("DOMUrl.DOMUrl: execution_context = \(document.reference)")
        let strbuf = _DOMUrlCreateObjectURLForSourceWithContext(document.reference, source.reference, &len)
        return String(bytesNoCopy: strbuf!, length: Int(len), encoding: String.Encoding.utf8, freeWhenDone: true)!
    }

}