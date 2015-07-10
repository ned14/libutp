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

#ifndef UTP_CRUST_H
#define UTP_CRUST_H

// Fetch sockaddr_t etc.
#ifdef WIN32
# include <Winsock2.h>
#else
# include <netinet/in.h>
# include <arpa/inet.h>
# include <sys/socket.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef int utp_crust_socket;

typedef enum event_code_t
{
  // Sent when a socket is being destroyed
  UTP_CRUST_SOCKET_CLEANUP,
  // Sent when a new connection was made
  UTP_CRUST_NEW_CONNECTION,    // data=sockaddr_t
  // Sent when a connection was ended
  UTP_CRUST_LOST_CONNECTION,   // data=sockaddr_t
  // Sent when a new message arrives
  UTP_CRUST_NEW_MESSAGE,       // data=message, bytes=length
  // Sent when the send queue has changed
  UTP_CRUST_SEND_QUEUE_STATUS  // bytes=bytes in queue
} event_code;

// The callback invoked when things happen on your socket
typedef void (*utp_crust_event_callback)(utp_crust_socket socket, event_code ev, const void *data, size_t bytes);

// Create a socket on the port suggested, launching a background libutp pumping thread if needed
// callback will be called with events as needed.
extern int utp_crust_create_socket(utp_crust_socket *socket, unsigned short *port, utp_crust_event_callback callback);

// Connect a socket to an endpoint
extern int utp_crust_connect(utp_crust_socket socket, const struct sockaddr *addr, socklen_t len);

// Sends data
extern int utp_crust_send(utp_crust_socket socket, const void *buf, size_t bytes);

// Destroy a previously created socket, closing down any background libutp pumping thread as needed
extern int utp_crust_destroy_socket(utp_crust_socket socket);

#ifdef __cplusplus
}
#endif


#endif
