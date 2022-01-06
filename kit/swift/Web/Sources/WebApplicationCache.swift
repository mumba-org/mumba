// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class WebApplicationCacheHost {

	var reference: WebApplicationCacheHostRef

	init(reference: WebApplicationCacheHostRef) {
		self.reference = reference
	}

}

public class WebApplicationCacheHostClient {
	
	var reference: WebApplicationCacheHostClientRef

	init(reference: WebApplicationCacheHostClientRef) {
		self.reference = reference
	}

}