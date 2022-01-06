// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/cmd/commands.h"

#include "base/command_line.h"
#include "base/callback.h"
#include "base/bind.h"
#include "base/task_scheduler/post_task.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/strings/string_piece.h"
#include "base/memory/ref_counted.h"
#include "base/strings/string_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/run_loop.h"
#include "storage/storage_manager.h"
#include "storage/torrent_manager.h"
#include "net/base/net_errors.h"
#include "net/socket/udp_client_socket.h"
#include "storage/io_completion_callback.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"

namespace storage {


const char kClient[] = "client";
const char kClient_HelpShort[] =
    "client: start a client conn";
const char kClient_Help[] =
    R"(
        just a marker
)";

int RunClient(const std::vector<std::string>& args) {
  net::IPAddress ip_address;
  std::string simple_message("hello world!");

  if (args.size() == 0) {
    printf("defina a porta de destino\n");
    return 1;
  }

  if (!ip_address.AssignFromIPLiteral("127.0.0.1")) {
    printf("error converting ip address\n");
    return 1;
  }
  int port = 8080;
  if (!base::StringToInt(args[0], &port)) {
    printf("falha ao converter %s para int\n", args[0].c_str());
    return 1; 
  }
  net::IPEndPoint address(ip_address, port);

  net::UDPClientSocket client(net::DatagramSocket::DEFAULT_BIND, nullptr, net::NetLogSource());
  int r = client.Connect(address);
  if (r != 0) {
    printf("conexão a 127.0.0.1:%d falhou\n", port);
    return 1;
  } else {
    printf("conexão a 127.0.0.1:%d bem sucedida\n", port);
  }
  scoped_refptr<net::StringIOBuffer> io_buffer(new net::StringIOBuffer(simple_message));
  IOCompletionCallback callback;
  int rv = client.Write(io_buffer.get(), io_buffer->size(),
                        callback.callback(), TRAFFIC_ANNOTATION_FOR_TESTS);
  int result = callback.GetResult(rv);
  printf("resultado ao escrever 'hello world!' = %d\n", result);
  client.Close();

  //base::RunLoop run_loop;
  //run_loop.Run();  
  return 0;
}

}