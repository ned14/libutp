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

#undef _DEBUG

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

#ifdef WIN32
using socket_type = SOCKET;
#else
# include <fcntl.h>
# include <poll.h>
using socket_type = int;
# define closesocket(h) ::close(h)
#endif

struct socket_info;
struct worker_thread_t;
static std::mutex sockets_lock;
static utp_crust_socket socket_id;
static std::unordered_map<utp_crust_socket, std::shared_ptr<socket_info>> sockets_by_id;
static std::unordered_map<utp_socket *, std::shared_ptr<socket_info>> sockets_by_utpsocket;
#ifdef _MSC_VER
static __declspec(thread) utp_crust_socket last_socket_id;
#else
static thread_local utp_crust_socket last_socket_id;
#endif
static std::unique_ptr<worker_thread_t> worker_thread;
struct socket_info : std::enable_shared_from_this<socket_info>
{
  utp_crust_socket id;
  socket_type h;
  unsigned short port;
  bool connected, already_sending;
  utp_socket *utph;
  utp_crust_event_callback callback;
  std::deque<std::pair<std::vector<unsigned char>, size_t>> send_queue;
  socket_info(socket_type _h, unsigned short _port, utp_crust_event_callback _callback) : id(0), h(_h), port(_port), connected(false), already_sending(false), utph(nullptr), callback(_callback) { }
  ~socket_info()
  {
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
#ifdef _DEBUG
      printf("Closing socket %d\n", id);
#endif
      int last_id=last_socket_id;
      last_socket_id=id;
      if(connected)
        utp_close(utph);  // libutp will delete this when it gets rounds to it
      else
        utp_destroy_unconnected_socket(utph);
      last_socket_id=last_id;
      utph=nullptr;
    }
  }
  void fill_send_queue()
  {
    if(!already_sending && !send_queue.empty())
    {
      std::vector<utp_iovec> vecs;
      ssize_t written=0;
      do
      {
        vecs.clear();
        vecs.reserve(send_queue.size());
        for(auto &i : send_queue)
        {
          vecs.push_back({ i.first.data()+i.second, i.first.size()-i.second });
#ifdef _DEBUG
          printf("About to send on socket %d %p-%u (+%u)\n", id, vecs.back().iov_base, (unsigned) vecs.back().iov_len, (unsigned) i.second);
#endif
        }
        already_sending=true;
        written=utp_writev(utph, vecs.data(), vecs.size());
        already_sending=false;
#ifdef _DEBUG
        printf("Sent %d bytes\n", (int) written);
#endif
        if(written<=0)
          break;
        assert(!send_queue.empty());
        while(written>0)
        {
          size_t thisbuffer=send_queue.front().first.size()-send_queue.front().second;
          if(thisbuffer<=written)
          {
            send_queue.pop_front();
            if(send_queue.empty())
              break;
            written-=thisbuffer;
          }
          else
          {
            send_queue.front().second+=written;
            written=0;
          }
        }
      } while(!send_queue.empty());
      size_t totalbytes=0;
      for(auto &i : send_queue)
        totalbytes+=i.first.size()-i.second;
      callback(id, UTP_CRUST_SEND_QUEUE_STATUS, nullptr, totalbytes);
    }
  }
};
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
  static void find_socket(std::shared_ptr<socket_info> &si, utp_crust_socket &id, utp_socket *s)
  {
    id=0;
    auto it(sockets_by_utpsocket.find(s));
    if(it==sockets_by_utpsocket.end())
    {
      if(!sockets_by_id.empty())
      {
        si=sockets_by_id.begin()->second;
        id=last_socket_id;
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
    find_socket(si, id, args->socket);
#ifdef _DEBUG
    printf("sendto args->socket=%p fromid=%d\n", args->socket, id);
#endif
    if(!si)
    {
      fprintf(stderr, "ERROR: utp_crust tried to send data when all sockets are destroyed\n");
      errno=ENODEV;
      return -1;
    }
    socket_type h=si->h;
    // Allow reads during sends
    sockets_lock.unlock();
    if(-1==sendto(h, args->buf, args->len, 0, args->address, args->address_len))
    {
      fprintf(stderr, "utp sendto failed with errno %d, ignoring\n", errno);
      // TODO: Should I check for EWOULDBLOCK and yield and retry?
    }
    sockets_lock.lock();
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
    write(canceller[1], &c, 1);
#endif
  }
  uint64 utp_callback(utp_callback_arguments *args)
  {
#ifdef _DEBUG
    printf("utp_callback args->socket=%p\n", args->socket);
#endif
    std::shared_ptr<socket_info> si;
    utp_crust_socket id;
    find_socket(si, id, args->socket);
    if(!si)
    {
      fprintf(stderr, "WARNING: utp_crust callback handler called when all sockets are destroyed\n");
    }
    switch(args->callback_type)
    {
      case UTP_ON_ACCEPT:
      {
#ifdef _DEBUG
        printf("Accepted new connection for socket id %d\n", id);
#endif
        if(si) si->callback(id, UTP_CRUST_NEW_CONNECTION, args->address, args->address_len);
        break;
      }
      case UTP_ON_ERROR:
      {
#ifdef _DEBUG
        printf("Error on socket id %d\n", id);
#endif
        if(si)
        {
          si->callback(id, UTP_CRUST_LOST_CONNECTION, args->address, args->address_len);
          si->close();
        }
        break;
      }
      case UTP_ON_READ:
      {
#ifdef _DEBUG
        printf("New data on socket id %d\n", id);
#endif
        if(si)
        {
          si->callback(id, UTP_CRUST_NEW_MESSAGE, args->buf, args->len);
          if(si->connected)
            utp_read_drained(si->utph);
        }
        break;
      }
      case UTP_ON_STATE_CHANGE:
      {
        switch(args->state)
        {
          case UTP_STATE_CONNECT:
#ifdef _DEBUG
            printf("Connected on socket id %d\n", id);
#endif
            break;
          case UTP_STATE_WRITABLE:
#ifdef _DEBUG
            printf("Now writable on socket id %d\n", id);
#endif
            if(si) si->fill_send_queue();
            break;
          case UTP_STATE_EOF:
#ifdef _DEBUG
            printf("EOF on socket id %d\n", id);
#endif
            if(si)
            {
              si->callback(id, UTP_CRUST_LOST_CONNECTION, args->address, args->address_len);
              si->close();
            }
            break;
          case UTP_STATE_DESTROYING:
#ifdef _DEBUG
            printf("Destroying socket id %d\n", id);
#endif
            if(si) si->callback(id, UTP_CRUST_SOCKET_CLEANUP, nullptr, 0);
            sockets_by_utpsocket.erase(args->socket);
            sockets_by_id.erase(id);
#ifdef _DEBUG
            printf("sockets remaining = %u,%u\n", (unsigned) sockets_by_utpsocket.size(), (unsigned) sockets_by_id.size());
#endif
            if(sockets_by_id.empty())
            {
#ifdef _DEBUG
              printf("No more sockets, so closing down UTP worker thread\n");
#endif
              done=true;
              std::async(std::launch::async, []{
                std::unique_lock<decltype(sockets_lock)> h(sockets_lock);
                if(sockets_by_id.empty() && worker_thread)
                {
#ifdef _DEBUG
                  printf("No more sockets, so destroying UTP worker thread\n");
#endif
                  if(worker_thread->threadh)
                  {
                    worker_thread->threadh->join();
                    worker_thread->threadh.reset();
                  }
                  worker_thread.reset();
                }
              });
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
#ifdef _DEBUG
    printf("UTP worker thread launched\n");
#endif
    while(!done)
    {
      std::vector<std::shared_ptr<socket_info>> sis;
      {
        std::lock_guard<decltype(sockets_lock)> h(sockets_lock);
        sis.reserve(sockets_by_id.size());
        for(auto &i : sockets_by_id)
        {
          if(i.second->utph)
            sis.push_back(i.second);
        }
      }
#ifdef WIN32
      todo;
#else
      std::vector<pollfd> buf;
      buf.reserve(sis.size()+1);
      buf.push_back({canceller[0], POLLIN, 0});
      for(auto si : sis)
        buf.push_back({si->h, POLLIN, 0});
#ifdef _DEBUG
      printf("UTP worker thread polls %u fds\n", (unsigned) buf.size());
#endif
      if((len=poll(buf.data(), buf.size(), 1000))>0)
      {
#ifdef _DEBUG
        printf("UTP worker poll returns %d, updated=%d\n", (int) len, !!(buf.front().revents & POLLIN));
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
#ifdef _DEBUG
            printf("UTP worker thread sees read on socket id %d\n", sis[n-1]->id);
#endif
            std::lock_guard<decltype(sockets_lock)> h(sockets_lock);
            do
            {
              len=recvfrom(buf[n].fd, buffer, sizeof(buffer), MSG_DONTWAIT, (struct sockaddr *)&src_addr, &addrlen);
              if(len>=0)
                utp_process_udp(ctx, buffer, len, (struct sockaddr *)&src_addr, addrlen);
            } while(len>=0);
            utp_issue_deferred_acks(ctx);
            last_socket_id=0;
          }
        }
      }
      std::lock_guard<decltype(sockets_lock)> h(sockets_lock);
      utp_check_timeouts(ctx);
#endif      
    }
#ifdef _DEBUG
    printf("UTP worker thread shutdown\n");
#endif
  }
};

// Create a socket on the port suggested, launching a background libutp pumping thread if needed
// callback will be called with events as needed.
extern "C" int utp_crust_create_socket(utp_crust_socket *id, unsigned short *port, utp_crust_event_callback callback)
{
  socket_type h=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if(h==(socket_type)-1) return -1;
  struct sockaddr_in res={AF_INET, htons(*port)};
  socklen_t socklen=sizeof(res);
  if(-1==bind(h, (sockaddr *) &res, socklen) || -1==getsockname(h, (sockaddr *) &res, &socklen))
  {
    closesocket(h);
    return -1;
  }
  *port=ntohs(res.sin_port);
  try
  {
    auto newsocket=std::make_shared<socket_info>(h, *port, callback);
    std::lock_guard<decltype(sockets_lock)> h(sockets_lock);
    bool bootstrapping=!worker_thread;
    if(bootstrapping)
      worker_thread=std::make_unique<worker_thread_t>();
    if(!(newsocket->utph=utp_create_socket(worker_thread->ctx)))
      throw std::runtime_error("Failed to create UTP socket");
    *id=newsocket->id=++socket_id;
#ifdef _DEBUG
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
  std::unique_lock<decltype(sockets_lock)> h(sockets_lock);
  auto it=sockets_by_id.find(id);
  if(it==sockets_by_id.end())
  {
    errno=EINVAL;
    return -1;
  }
  last_socket_id=id;
  int ret=utp_connect(it->second->utph, addr, len);
  it->second->connected=true;
  last_socket_id=0;
  return ret;
}

// Sends data
extern "C" int utp_crust_send(utp_crust_socket id, const void *buf, size_t bytes)
{
  std::unique_lock<decltype(sockets_lock)> h(sockets_lock);
  auto it=sockets_by_id.find(id);
  if(it==sockets_by_id.end())
  {
    errno=EINVAL;
    return -1;
  }
  std::vector<unsigned char> vec(bytes);
  memcpy(vec.data(), buf, bytes);
  it->second->send_queue.push_back(std::make_pair(vec, 0));
  it->second->fill_send_queue();
  return (int) bytes;
}

// Destroy a previously created socket, closing down any background libutp pumping thread as needed
extern "C" int utp_crust_destroy_socket(utp_crust_socket id)
{
  std::unique_lock<decltype(sockets_lock)> h(sockets_lock);
  auto it=sockets_by_id.find(id);
  // Sockets can get destroyed asynchronously, so don't fail if not found.
  if(it!=sockets_by_id.end())
    it->second->close();
  return 0;
}
