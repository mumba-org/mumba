// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_NET_DHT_DHT_STORAGE_H_
#define MUMBA_HOST_NET_DHT_DHT_STORAGE_H_

namespace storage {

/*
 * Implementação do DHTStorage do libtorrent, só que plugando
 * com o disk - no caso com os entries (que são torrents)
 * do disk
 *
 * De início podemos organizar por aqui no layer do disk mesmo
 * e depois caso necessário, se precisarmos de uma visão de todos
 * os discos, podemos reinstalar no processo Host
 *
 * Melhor.. vamos colocar direto no host, assim temos a visão
 * a partir de varios discos e não apenas de um
 */


}

#endif