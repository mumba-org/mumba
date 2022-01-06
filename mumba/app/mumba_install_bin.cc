// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "runtime/ToolShims/InstallShims.h"

int main(int argc, char** argv) {
 return _mumba_install_main(argc, argv);
}