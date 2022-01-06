// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "runtime/ToolShims/ReplShims.h"

// TODO: 
//
//  1 - Criar ponto de acesso ao processo shel via IPC
//  2 - Na entrada geral verificar se o processo tem
//      um parametro sem -- ou - eg. "mumba build" ou "mumba package"
//  3 - Chamar o binario de acordo com esse parametro
//      "mumba package" chama "mumba_package"
//  4 - O binario entao se comunica com a "nave mãe"
//      o processo shell via IPC, ou se for uma tool
//      mais simples efetua o seu trabalho  

int main(int argc, char** argv) {
 return _mumba_repl_main(argc, argv);
}