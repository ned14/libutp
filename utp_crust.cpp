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
#include "utp.h"

//#define LOGGING

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <mutex>
#include <unordered_map>
#include <memory>
#include <thread>
#include <vector>
#include <future>
#include <deque>
#include <utility>

#ifdef WIN32
using socket_type = SOCKET;
#else
# include <fcntl.h>
# include <poll.h>
# include <sys/ioctl.h>
using socket_type = int;
# define closesocket(h) ::close(h)
#endif

struct sockaddr_hash
{
  size_t operator ()(const struct sockaddr &sa) const
  {
    size_t hash = 0;
    switch (sa.sa_family)
    {
      case AF_INET:
      {
        struct sockaddr_in *s4 = (struct sockaddr_in *) &sa;
        hash ^= std::hash<decltype(s4->sin_family)>()(s4->sin_family);
        hash ^= std::hash<decltype(s4->sin_port)>()(s4->sin_port);
        hash ^= std::hash<decltype(s4->sin_addr.s_addr)>()(s4->sin_addr.s_addr);
        break;
      }
      case AF_INET6:
      {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *) &sa;
        hash ^= std::hash<decltype(s6->sin6_family)>()(s6->sin6_family);
        hash ^= std::hash<decltype(s6->sin6_port)>()(s6->sin6_port);
        hash ^= std::hash<decltype(s6->sin6_flowinfo)>()(s6->sin6_flowinfo);
        uint32_t *a = (uint32_t *) s6->sin6_addr.s6_addr;
        for (size_t n = 0; n < 4; n++)
          hash ^= std::hash<uint32_t>()(a[n]);
        hash ^= std::hash<decltype(s6->sin6_scope_id)>()(s6->sin6_scope_id);
        break;
      }
      default:
        abort();
    }
    return hash;
  }
};
inline bool operator==(const struct sockaddr &a, const struct sockaddr &b) noexcept
{
  if (a.sa_family != b.sa_family)
    return false;
  switch (a.sa_family)
  {
    case AF_INET:
    {
      struct sockaddr_in *a4 = (struct sockaddr_in *) &a;
      struct sockaddr_in *b4 = (struct sockaddr_in *) &b;
      return a4->sin_port == b4->sin_port && a4->sin_addr.s_addr == b4->sin_addr.s_addr;
    }
    case AF_INET6:
    {
      struct sockaddr_in6 *a6 = (struct sockaddr_in6 *) &a;
      struct sockaddr_in6 *b6 = (struct sockaddr_in6 *) &b;
      return a6->sin6_port == b6->sin6_port && a6->sin6_flowinfo == b6->sin6_flowinfo && !memcmp(a6->sin6_addr.s6_addr, b6->sin6_addr.s6_addr, 16) && a6->sin6_scope_id == b6->sin6_scope_id;
    }
    default:
      abort();
  }
}

struct socket_info;
struct worker_thread_t;
static std::mutex *sockets_lock(new std::mutex());
static utp_crust_socket socket_id;
static std::unordered_map<utp_crust_socket, std::shared_ptr<socket_info>> sockets_by_id;
static std::unordered_map<utp_socket *, std::shared_ptr<socket_info>> sockets_by_utpsocket;
static std::unordered_map<struct sockaddr, std::shared_ptr<socket_info>, sockaddr_hash> sockets_by_peer_endpoint;
#if defined(_MSC_VER) && _MSC_FULL_VER < 190000000
static __declspec(thread) utp_crust_socket last_socket_id;
#else
static thread_local utp_crust_socket last_socket_id;
#endif
static std::unique_ptr<worker_thread_t> worker_thread;

struct socket_info : std::enable_shared_from_this<socket_info>
{
  utp_crust_socket id;
  socket_type h;
  unsigned short port;                // Locally bound listening port
  unsigned int flags;
  struct sockaddr peer_endpoint;      // Peer connection
  enum class connected_t
  {
    not_connected,
    connecting,
    connected
  } connected;
  bool send_queue_full, already_sending;
  size_t last_send_queue_size;
  utp_socket *utph;
  utp_crust_event_callback callback;
  void *data;
  std::deque<std::pair<std::vector<unsigned char>, size_t>> send_queue;
  std::condition_variable send_queue_empty, socket_closed;
  socket_info(socket_type _h, unsigned short _port, unsigned int _flags, utp_crust_event_callback _callback, void *_data)
    : id(0), h(_h), port(_port), flags(_flags), connected(connected_t::not_connected), send_queue_full(false), already_sending(false), last_send_queue_size(0),
      utph(nullptr), callback(_callback), data(_data)
  {
    memset(&peer_endpoint, 0, sizeof(peer_endpoint));
  }
  ~socket_info()
  {
    if (utph)
    {
      utp_destroy_unconnected_socket(utph);
      utph = nullptr;
    }
    if(h!=(socket_type)-1)
    {
      closesocket(h);
      h=(socket_type)-1;
    }
  }
  std::shared_ptr<socket_info> lock() { return this->shared_from_this(); }
  void close()
  {
    if(utph)
    {
#ifdef LOGGING
      printf("Closing socket %d\n", id);
#endif
      if (connected != connected_t::not_connected)
      {
        auto _utph = utph;
        utph = nullptr;
        int last_id = last_socket_id;
        last_socket_id = id;
        utp_close(_utph);  // libutp will delete this when it gets rounds to it
        last_socket_id = last_id;
      }
    }
  }
  void fill_send_queue()
  {
    assert(!(send_queue_full && send_queue.empty()));
    if (!send_queue.empty())
    {
      if (already_sending)
        fprintf(stderr, "WARNING: Reentered fill_send_queue()!\n");
      else
      {
        if (!send_queue_full)
        {
          std::vector<utp_iovec> vecs;
          ssize_t written = 0;
          //do
          {
            vecs.clear();
            vecs.reserve(send_queue.size());
            for (auto &i : send_queue)
            {
              vecs.push_back({ i.first.data() + i.second, i.first.size() - i.second });
#ifdef LOGGING
              //printf("About to send on socket %d %p-%u (+%u)\n", id, vecs.back().iov_base, (unsigned) vecs.back().iov_len, (unsigned) i.second);
#endif
            }
            already_sending = true;
            int old_id = last_socket_id;
            last_socket_id = id;
            written = utp_writev(utph, vecs.data(), vecs.size());
            last_socket_id = old_id;
            already_sending = false;
#ifdef LOGGING
            //printf("Sent %d bytes\n", (int) written);
#endif
            if (written <= 0)
            {
              send_queue_full = true;
              goto done;
            }
            assert(!send_queue.empty());
            while (written > 0)
            {
              size_t thisbuffer = send_queue.front().first.size() - send_queue.front().second;
              if (thisbuffer <= (size_t)written)
              {
                send_queue.pop_front();
                if (send_queue.empty())
                {
                  send_queue_full = false;
                  send_queue_empty.notify_all();
                  break;
                }
                written -= thisbuffer;
              }
              else
              {
                send_queue.front().second += written;
                written = 0;
              }
            }
          } //while (!send_queue.empty());
done:
          size_t totalbytes = 0;
          for (auto &i : send_queue)
            totalbytes += i.first.size() - i.second;
          if (last_send_queue_size != totalbytes)
          {
            callback(id, UTP_CRUST_SEND_QUEUE_STATUS, nullptr, totalbytes, data);
            last_send_queue_size = totalbytes;
          }
        }
      }
    }
  }
};

static int _do_connect(std::shared_ptr<socket_info> si, const struct sockaddr *addr, socklen_t len)
{
  si->connected = socket_info::connected_t::connecting;
  last_socket_id = si->id;
  int ret = utp_connect(si->utph, addr, len);
  last_socket_id = 0;
  if (-1 != ret)
  {
    memcpy(&si->peer_endpoint, addr, sizeof(si->peer_endpoint));
    sockets_by_peer_endpoint.insert(std::make_pair(*addr, si));
  }
  else
    si->connected = socket_info::connected_t::not_connected;
  return ret;
}

struct worker_thread_t
{
  bool done;
#ifdef WIN32
  HANDLE canceller[2];
#else
  int canceller[2];
#endif
  utp_context *ctx;
  std::unique_ptr<std::thread> threadh;
  /* libutp was written around there being one UDP socket and multiplexing connections across that one socket.
  As a result, it forgets to say which socket a callback refers to a lot of the time, and we need to tag using
  thread local data what some callback means, hence this find_socket complexity.
  */
  static void find_socket(std::shared_ptr<socket_info> &si, utp_crust_socket &id, utp_callback_arguments *args)
  {
    id=0;
    // First try to lookup this callback by socket
    auto it(sockets_by_utpsocket.find(args->socket));
    if(it==sockets_by_utpsocket.end())
    {
      // If that failed (e.g. internal socket), try looking up by thread local data
      if(!sockets_by_id.empty())
      {
        id=last_socket_id;
        if (id)
          si = sockets_by_id[id];
        else if (args->callback_type != UTP_ON_STATE_CHANGE && args->callback_type!= UTP_ON_ERROR)
        {
          fprintf(stderr, "WARNING: Had to look up by peer endpoint for callback %s\n", utp_callback_names[args->callback_type]);
          // If thread local data not set (e.g. timeouts), look up by destination endpoint
          auto it(sockets_by_peer_endpoint.find(*args->address));
          if (it == sockets_by_peer_endpoint.end())
            abort(); // si = sockets_by_id.begin()->second;
          si = it->second;
          id = si->id;
        }
        else
        {
          fprintf(stderr, "FATAL: Could not deduce correct socket for callback %s\n", utp_callback_names[args->callback_type]);
          abort();
        }
      }
    }
    else
    {
      si=it->second;
      id=si->id;
    }
  }
  static uint64 sendto_impl(utp_callback_arguments *args)
  {
    std::shared_ptr<socket_info> si;
    utp_crust_socket id;
    find_socket(si, id, args);
#ifdef LOGGING
    //printf("sendto args->socket=%p fromid=%d packet type=%x conn_id=%u\n", args->socket, id, *args->buf, args->buf[3]);
#endif
    if(!si)
    {
      fprintf(stderr, "ERROR: utp_crust tried to send data when all sockets are destroyed\n");
      errno=ENODEV;
      return -1;
    }
    socket_type h=si->h;
    // Allow reads during sends
    sockets_lock->unlock();
    if(-1==sendto(h, (const char *) args->buf, args->len, 0, args->address, args->address_len))
    {
      fprintf(stderr, "utp sendto failed with errno %d, ignoring\n", errno);
      // TODO: Should I check for EWOULDBLOCK and yield and retry?
    }
    sockets_lock->lock();
    return 0;
  }
  static uint64 invoke_utp_callback(utp_callback_arguments *args)
  {
    worker_thread_t *self=(worker_thread_t *) utp_context_get_userdata(args->context);
    return self->utp_callback(args);
  }
  worker_thread_t() : done(false), ctx(nullptr)
  {
#ifdef WIN32
    if(!(canceller[0]=CreateEvent(NULL, false, false, NULL)))
      throw std::runtime_error("Failed to create event");
    if(!(canceller[1]=CreateEvent(NULL, false, false, NULL)))
      throw std::runtime_error("Failed to create event");
#else
    if(-1==pipe2(canceller, O_NONBLOCK))
      throw std::runtime_error("Failed to create pipe");
#endif
    if(!(ctx=utp_init(2)))
      throw std::runtime_error("Failed to init utp");
    utp_context_set_userdata(ctx, this);
    utp_set_callback(ctx, UTP_SENDTO, &sendto_impl);
    utp_set_callback(ctx, UTP_ON_FIREWALL, &invoke_utp_callback);
    utp_set_callback(ctx, UTP_ON_ERROR, &invoke_utp_callback);
    utp_set_callback(ctx, UTP_ON_STATE_CHANGE, &invoke_utp_callback);
    utp_set_callback(ctx, UTP_ON_READ, &invoke_utp_callback);
    utp_set_callback(ctx, UTP_ON_ACCEPT, &invoke_utp_callback);
  }
  worker_thread_t(worker_thread_t &&)=delete;
  worker_thread_t(const worker_thread_t &)=delete;
  worker_thread_t &operator=(worker_thread_t &&)=delete;
  worker_thread_t &operator=(const worker_thread_t &)=delete;
  ~worker_thread_t()
  {
    if(threadh)
    {
      done=true;
      updated();
      threadh->join();
    }
#ifdef WIN32
    CloseHandle(canceller[0]);
    CloseHandle(canceller[1]);
#else
    close(canceller[0]);
    close(canceller[1]);
#endif
    utp_destroy(ctx);
  }
  void updated() const
  {
#ifdef WIN32
    SetEvent(canceller[0]);
#else
    char c=0;
    (void) write(canceller[1], &c, 1);
#endif
  }
  uint64 utp_callback(utp_callback_arguments *args)
  {
#ifdef LOGGING
    //printf("utp_callback args->socket=%p last_socket_id=%d\n", args->socket, last_socket_id);
#endif
    std::shared_ptr<socket_info> si;
    utp_crust_socket id;
    find_socket(si, id, args);
    if(!si)
    {
      fprintf(stderr, "WARNING: utp_crust callback handler called when all sockets are destroyed\n");
      return 0;
    }
    switch(args->callback_type)
    {
      case UTP_ON_FIREWALL:
      {
#ifdef LOGGING
        printf("Incoming new connection for socket id %d\n", id);
#endif
        if (si)
        {
          if(si->flags & UTP_CRUST_LISTEN)
          {
#ifdef LOGGING
            printf("Listening socket id %d new connection\n", id);
#endif
            si->callback(id, UTP_CRUST_NEW_CONNECTION, args->address, args->address_len, si->data);
            return 1;  // Reject
          }
          else switch (si->connected)
          {
            // Reciprocate connection if I am listening
            case socket_info::connected_t::not_connected:
              if (_do_connect(si, args->address, args->address_len) >= 0)
              {
#ifdef LOGGING
                printf("Reciprocating connection to listening socket\n");
#endif
                si->connected = socket_info::connected_t::connected;
                return 0;  // Accept
              }
              else
              {
                fprintf(stderr, "WARNING: Rejecting incoming connection as failed to reciprocate connection\n");
                return 1;
              }
            // Reciprocate connection if I am listening
            case socket_info::connected_t::connecting:
#ifdef LOGGING
              printf("Allowing reciprocated connection from listening socket\n");
#endif
              si->connected = socket_info::connected_t::connected;
              return 0;
            default:
              // Is this a reconnect from the current connection? If not, reject
              auto it(sockets_by_peer_endpoint.find(*args->address));
              if (it != sockets_by_peer_endpoint.end() && it->second == si)
              {
#ifdef LOGGING
                printf("Reallowing reconnect from previously connected endpoint\n");
#endif
                return 0;
              }
              fprintf(stderr, "WARNING: Rejecting incoming connection from new peer on already connected socket\n");
              return 1;
          }
        }
        fprintf(stderr, "WARNING: Rejecting incoming connection as unknown socket\n");
        return 1;  // Reject
      }
      case UTP_ON_ACCEPT:
      {
#ifdef LOGGING
        printf("Accepted new connection for socket id %d\n", id);
#endif
        if (si)
          si->callback(id, UTP_CRUST_NEW_CONNECTION, args->address, args->address_len, si->data);
        break;
      }
      case UTP_ON_ERROR:
      {
#ifdef LOGGING
        printf("Error on socket id %d\n", id);
#endif
        if(si)
        {
          si->callback(id, UTP_CRUST_LOST_CONNECTION, args->address, args->address_len, si->data);
          if(si->connected!= socket_info::connected_t::not_connected)
            si->close();
        }
        break;
      }
      case UTP_ON_READ:
      {
#ifdef LOGGING
        //printf("New data on socket id %d\n", id);
#endif
        if(si)
        {
          si->callback(id, UTP_CRUST_NEW_MESSAGE, args->buf, args->len, si->data);
          if(si->connected!= socket_info::connected_t::not_connected && si->utph)
            utp_read_drained(si->utph);
        }
        break;
      }
      case UTP_ON_STATE_CHANGE:
      {
        switch(args->state)
        {
          case UTP_STATE_CONNECT:
#ifdef LOGGING
            printf("Connected on socket id %d\n", id);
#endif
            if (si)
              si->send_queue_full = false;
            break;
          case UTP_STATE_WRITABLE:
#ifdef LOGGING
            //printf("Now writable on socket id %d\n", id);
#endif
            if (si)
              si->send_queue_full = false;
            break;
          case UTP_STATE_EOF:
#ifdef LOGGING
            printf("EOF on socket id %d\n", id);
#endif
            if(si)
            {
              si->callback(id, UTP_CRUST_LOST_CONNECTION, args->address, args->address_len, si->data);
              //if(si->connected!= socket_info::connected_t::not_connected)
              //  si->close();
            }
            break;
          case UTP_STATE_DESTROYING:
#ifdef LOGGING
            printf("Destroying socket id %d\n", id);
#endif
            assert(si);
            if (si)
            {
              si->callback(id, UTP_CRUST_SOCKET_CLEANUP, nullptr, 0, si->data);
              if(si->connected!= socket_info::connected_t::not_connected)
                sockets_by_peer_endpoint.erase(si->peer_endpoint);
            }
            sockets_by_utpsocket.erase(args->socket);
            sockets_by_id.erase(id);
#ifdef LOGGING
            printf("sockets remaining = %u,%u\n", (unsigned) sockets_by_utpsocket.size(), (unsigned) sockets_by_id.size());
#endif
            if (si)
              si->socket_closed.notify_all();
            if(sockets_by_id.empty())
            {
#ifdef LOGGING
              printf("No more sockets, so closing down UTP worker thread\n");
#endif
              done=true;
              std::thread([]{
                std::unique_lock<std::mutex> h(*sockets_lock);
                if(sockets_by_id.empty() && worker_thread)
                {
#ifdef LOGGING
                  printf("No more sockets, so destroying UTP worker thread\n");
#endif
                  if(worker_thread->threadh)
                  {
                    worker_thread->threadh->join();
                    worker_thread->threadh.reset();
                  }
                  worker_thread.reset();
                }
              }).detach();
            }
            break;
        }
        break;
      }
    }
    return 0;
  }
  void operator()() const
  {
    unsigned char buffer[65536];
    struct sockaddr_in src_addr;
    socklen_t addrlen = sizeof(src_addr);
    ssize_t len;
#ifdef LOGGING
    printf("UTP worker thread launched\n");
#endif
    while(!done)
    {
      std::vector<std::shared_ptr<socket_info>> sis;
      {
        std::lock_guard<std::mutex> h(*sockets_lock);
        sis.reserve(sockets_by_id.size());
        for(auto &i : sockets_by_id)
        {
          i.second->fill_send_queue();
          sis.push_back(i.second);
        }
      }
#ifdef WIN32
      for (auto &si : sis)
      {
        if (0 != WSAEventSelect(si->h, canceller[1], FD_READ))
        {
          fprintf(stderr, "WARNING: utp_crust WSAEventSelect returned error %d\n", WSAGetLastError());
        }
      }
      if((len = (ssize_t) WaitForMultipleObjects(2, canceller, false, 500))>0)
      {
#ifdef LOGGING
        //printf("UTP worker poll returns %d, updated=%d\n", (int)len, len==0);
#endif
        if(len==0)
          ResetEvent(canceller[0]);
        else if (len == 1)
        {
          ResetEvent(canceller[1]);
          for (auto &si : sis)
          {
            unsigned long toread = 0;
            ioctlsocket(si->h, FIONREAD, &toread);
            if (!toread)
              continue;
            last_socket_id = si->id;
            std::lock_guard<std::mutex> h(*sockets_lock);
            do
            {
              memset(&src_addr, 0, sizeof(src_addr));
              addrlen = sizeof(src_addr);
              len=recvfrom(si->h, (char *) buffer, sizeof(buffer), 0, (struct sockaddr *)&src_addr, &addrlen);
              //printf("Received packet from port %u\n", ntohs(src_addr.sin_port));
#else
      std::vector<pollfd> buf;
      buf.reserve(sis.size()+1);
      buf.push_back({canceller[0], POLLIN, 0});
      for(auto &si : sis)
        buf.push_back({si->h, POLLIN, 0});
#ifdef LOGGING
      //printf("UTP worker thread polls %u fds\n", (unsigned) buf.size());
#endif
      if((len=poll(buf.data(), buf.size(), 1000))>0)
      {
#ifdef LOGGING
        //printf("UTP worker poll returns %d, updated=%d\n", (int) len, !!(buf.front().revents & POLLIN));
#endif
        if(buf.front().revents & POLLIN)
        {
          while(-1!=read(canceller[0], buffer, sizeof(buffer)));
        }
        for(size_t n=1; n<buf.size(); n++)
        {
          if(buf[n].revents & POLLIN)
          {
            last_socket_id=sis[n-1]->id;
#ifdef LOGGING
            //printf("UTP worker thread sees read on socket id %d\n", sis[n-1]->id);
#endif
            std::lock_guard<std::mutex> h(*sockets_lock);
            do
            {
              len=recvfrom(buf[n].fd, buffer, sizeof(buffer), MSG_DONTWAIT, (struct sockaddr *)&src_addr, &addrlen);
#endif      
              if(len>=0)
                utp_process_udp(ctx, buffer, len, (struct sockaddr *)&src_addr, addrlen);
            } while(len>=0);
            utp_issue_deferred_acks(ctx);
            last_socket_id=0;
          }
        }
      }
      std::lock_guard<std::mutex> h(*sockets_lock);
      utp_check_timeouts(ctx);
    }
#ifdef LOGGING
    printf("UTP worker thread shutdown\n");
#endif
  }
};

// Create a socket on the port suggested, launching a background libutp pumping thread if needed
// callback will be called with events as needed.
extern "C" int utp_crust_create_socket(utp_crust_socket *id, unsigned short *port, unsigned int flags, utp_crust_event_callback callback, void *data)
{
  socket_type h=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if(h==(socket_type)-1) return -1;
  struct sockaddr_in res={AF_INET, htons(*port)};
  socklen_t socklen=sizeof(res);
  unsigned long nonblocking = 1;
  if(-1==bind(h, (sockaddr *) &res, socklen) || -1==getsockname(h, (sockaddr *) &res, &socklen) ||
#ifdef WIN32
    -1==ioctlsocket(h, FIONBIO, &nonblocking)
#else
    -1==ioctl(h, FIONBIO, &nonblocking)
#endif
    )
  {
    closesocket(h);
    return -1;
  }
  *port=ntohs(res.sin_port);
  try
  {
    auto newsocket=std::make_shared<socket_info>(h, *port, flags, callback, data);
    std::lock_guard<std::mutex> h(*sockets_lock);
    bool bootstrapping=!worker_thread;
    if(bootstrapping)
      worker_thread=std::make_unique<worker_thread_t>();
    if(!(newsocket->utph=utp_create_socket(worker_thread->ctx)))
      throw std::runtime_error("Failed to create UTP socket");
    *id=newsocket->id=++socket_id;
#ifdef LOGGING
    printf("UTP create socket id %d (addr=%p) uses port %d\n", *id, newsocket.get(), *port);
#endif
    try
    {
      sockets_by_id.insert(std::make_pair(socket_id, newsocket));
      sockets_by_utpsocket.insert(std::make_pair(newsocket->utph, newsocket));
      if(bootstrapping)
        worker_thread->threadh=std::make_unique<std::thread>(std::ref(*worker_thread));
      else
        worker_thread->updated();
    }
    catch(...)
    {
      worker_thread.reset();
      sockets_by_utpsocket.erase(newsocket->utph);
      sockets_by_id.erase(socket_id);
      utp_close(newsocket->utph);
      throw;
    }
    return 0;
  }
  catch(...)
  {
    closesocket(h);
    errno=ENOMEM;
    return -1;
  }
}

// Connect a socket to an endpoint
extern "C" int utp_crust_connect(utp_crust_socket id, const struct sockaddr *addr, socklen_t len)
{
  std::unique_lock<std::mutex> h(*sockets_lock);
  auto it=sockets_by_id.find(id);
  if(it==sockets_by_id.end())
  {
    errno=EINVAL;
    return -1;
  }
  return _do_connect(it->second, addr, len);
}

// Sends data
extern "C" int utp_crust_send(utp_crust_socket id, const void *buf, size_t bytes)
{
  std::unique_lock<std::mutex> h(*sockets_lock);
  auto it=sockets_by_id.find(id);
  if(it==sockets_by_id.end())
  {
    errno=EINVAL;
    return -1;
  }
  std::vector<unsigned char> vec(bytes);
  memcpy(vec.data(), buf, bytes);
  bool was_empty = it->second->send_queue.empty();
  it->second->send_queue.push_back(std::make_pair(vec, 0));
  if (was_empty)
    worker_thread->updated();
  return (int) bytes;
}

// Flushes pending send data
extern "C" int utp_crust_flush(utp_crust_socket id)
{
  std::unique_lock<std::mutex> h(*sockets_lock);
  auto it = sockets_by_id.find(id);
  if (it == sockets_by_id.end())
  {
    errno = EINVAL;
    return -1;
  }
  auto si(it->second);
  if (!si->send_queue.empty())
  {
    si->send_queue_empty.wait(h, [&si] { return si->send_queue.empty(); });
  }
  return 0;
}

// Destroy a previously created socket, closing down any background libutp pumping thread as needed
extern "C" int utp_crust_destroy_socket(utp_crust_socket id, int wait)
{
  std::unique_lock<std::mutex> h(*sockets_lock);
  auto it=sockets_by_id.find(id);
  // Sockets can get destroyed asynchronously, so don't fail if not found.
  if (it != sockets_by_id.end())
  {
    auto si(it->second);
    if (!si->send_queue.empty())
      si->send_queue.clear();
    si->close();
    if (wait)
      si->socket_closed.wait(h, [id] { return sockets_by_id.find(id)!= sockets_by_id.end(); });
    h.unlock();
  }
  return 0;
}
