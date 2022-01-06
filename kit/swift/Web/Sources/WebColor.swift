// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public protocol WebColorSuggestion {}

public class WebColorChooserClient {
	
	//var reference: WebColorChooserClientRef

	//init(reference: WebColorChooserClientRef) {
	//	self.reference = reference
	//}

}

public class WebColorChooser {
	
	var reference: WebColorChooserRef

	init(reference: WebColorChooserRef) {
		self.reference = reference
	}

}
