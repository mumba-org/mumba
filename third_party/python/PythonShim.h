// Copyright (c) 2020 Jabberwock. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef JABBERWOCK_KIT_SWIFT_PYTHON_H_
#define JABBERWOCK_KIT_SWIFT_PYTHON_H_

// helper header to be used by module.modulemap

#ifndef _POSIX_THREADS
#define _POSIX_THREADS
#endif

#include "Include/object.h"
#include "Include/abstract.h"
#include "Include/unicodeobject.h"
#include "Include/pystate.h"
#include "Include/pyerrors.h"
#include "Include/dictobject.h"
#include "Include/pylifecycle.h"
#include "Include/pyarena.h"
#include "Include/compile.h"
#include "Include/ceval.h"
#include "Include/import.h"
#include "Include/sysmodule.h"
#include "Include/sliceobject.h"
#include "Include/tupleobject.h"
#include "Include/bytesobject.h"
#include "Include/longobject.h"
#include "Include/longintrepr.h"
#include "Include/boolobject.h"
#include "Include/sliceobject.h"
#include "Include/listobject.h"
#include "Include/pythonrun.h"
#include "Include/floatobject.h"
#include "Include/bytearrayobject.h"

// struct _longobject _Py_FalseStruct = {
//     PyVarObject_HEAD_INIT(&PyBool_Type, 0)
//     { 0 }
// };

// struct _longobject _Py_TrueStruct = {
//     PyVarObject_HEAD_INIT(&PyBool_Type, 1)
//     { 1 }
// };

#endif