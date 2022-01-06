// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMMON_QUERY_CODE_H_
#define COMMON_QUERY_CODE_H_

namespace common {

// TODO: listar todas as possibilidades de erros
// de acordo com o processado pela db no processo engine
// de forma que o cliente seja devidamente avisado
// sobre qual o tipo de erro aconteceu

enum QueryCode {
 QUERY_ERROR = -1, 
 QUERY_NORESULT = 0, // ok, with no result
 QUERY_RESULT = 1, // ok, result
 QUERY_LAST = QUERY_RESULT,
};

}

#endif
