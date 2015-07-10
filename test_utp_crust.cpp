// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

#include "utp_crust.h"
#define CATCH_CONFIG_PREFIX_ALL
#define CATCH_CONFIG_MAIN
#include "CATCH/single_include/catch.hpp"

static size_t bytes_received;
void handler(utp_crust_socket socket, event_code ev, const void *data, size_t bytes)
{
  switch(ev)
  {
    case UTP_CRUST_SOCKET_CLEANUP:
      printf("HANDLER: socket id %d cleanup\n", socket);
      break;
    case UTP_CRUST_NEW_CONNECTION:
      printf("HANDLER: socket id %d new connection\n", socket);
      break;
    case UTP_CRUST_LOST_CONNECTION:
      printf("HANDLER: socket id %d lost connection\n", socket);
      break;
    case UTP_CRUST_NEW_MESSAGE:
      printf("HANDLER: socket id %d new message sized %u\n", socket, (unsigned) bytes);
      bytes_received+=bytes;
      break;
    case UTP_CRUST_PLEASE_SEND:
      printf("HANDLER: socket id %d has send queue space\n", socket);
      break;
  }
}

CATCH_TEST_CASE( "utp_crust works", "[utp_crust]" )
{
  utp_crust_socket listener, connecter;
  unsigned short port;
  port=0;
  CATCH_CHECK(utp_crust_create_socket(&connecter, &port, handler)==0);
  port=0;
  CATCH_CHECK(utp_crust_create_socket(&listener, &port, handler)==0);
  struct sockaddr_in addr={AF_INET, htons(port)};
  addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
  CATCH_CHECK(utp_crust_connect(connecter, (sockaddr *) &addr, sizeof(addr))==0);
  char buffer[1024];
  memset(buffer, 78, sizeof(buffer));
  bytes_received=0;
  for(size_t n=0; n<100; n++)
  {
    CATCH_CHECK(utp_crust_send(connecter, buffer, sizeof(buffer))==sizeof(buffer));
  }
  CATCH_CHECK(utp_crust_destroy_socket(connecter)==0);
  CATCH_CHECK(utp_crust_destroy_socket(listener)==0);
  CATCH_CHECK(bytes_received==sizeof(buffer)*100);
}
