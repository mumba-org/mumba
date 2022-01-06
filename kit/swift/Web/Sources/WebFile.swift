// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class WebFileChooserCompletion {
	var reference: WebFileChooserCompletionRef

	init(reference: WebFileChooserCompletionRef) {
		self.reference = reference	
	}
}

public struct WebFileChooserParams {
    public var multiSelect: Bool
    public var directory: Bool
    public var saveAs: Bool
    public var title: String
    public var initialValue: String
    public var acceptTypes: [String]
    public var selectedFiles: [String]
    public var capture: String
    public var useMediaCapture: Bool
    public var needLocalPath: Bool
    public var requestor: String

    public init() {
		multiSelect = false
    	directory = false
    	saveAs = false
    	title = String()
    	initialValue = String()
    	acceptTypes = []
    	selectedFiles = []
    	capture = String()
        requestor = String()
    	useMediaCapture = false
    	needLocalPath = false
    }
 }