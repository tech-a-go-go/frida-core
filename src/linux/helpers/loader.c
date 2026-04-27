#include "inject-context.h"
#include "syscall.h"

#include <alloca.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/un.h>

#ifndef SOCK_CLOEXEC
# define SOCK_CLOEXEC 0x80000
#endif

typedef int SundayUnloadPolicy;
typedef struct _SundayLinuxInjectorState SundayLinuxInjectorState;
typedef union _SundayControlMessage SundayControlMessage;

enum _SundayUnloadPolicy
{
  SUNDAY_UNLOAD_POLICY_IMMEDIATE,
  SUNDAY_UNLOAD_POLICY_RESIDENT,
  SUNDAY_UNLOAD_POLICY_DEFERRED,
};

struct _SundayLinuxInjectorState
{
  int sunday_ctrlfd;
  int agent_ctrlfd;
};

union _SundayControlMessage
{
  struct cmsghdr header;
  uint8_t storage[CMSG_SPACE (sizeof (int))];
};

static void * sunday_main (void * user_data);

static int sunday_connect (const char * address, const SundayLibcApi * libc);
static bool sunday_send_hello (int sockfd, pid_t thread_id, const SundayLibcApi * libc);
static bool sunday_send_ready (int sockfd, const SundayLibcApi * libc);
static bool sunday_receive_ack (int sockfd, const SundayLibcApi * libc);
static bool sunday_send_bye (int sockfd, SundayUnloadPolicy unload_policy, const SundayLibcApi * libc);
static bool sunday_send_error (int sockfd, SundayMessageType type, const char * message, const SundayLibcApi * libc);

static bool sunday_receive_chunk (int sockfd, void * buffer, size_t length, const SundayLibcApi * api);
static int sunday_receive_fd (int sockfd, const SundayLibcApi * libc);
static bool sunday_send_chunk (int sockfd, const void * buffer, size_t length, const SundayLibcApi * libc);
static void sunday_enable_close_on_exec (int fd, const SundayLibcApi * libc);

static size_t sunday_strlen (const char * str);

static pid_t sunday_gettid (void);

__attribute__ ((section (".text.entrypoint")))
__attribute__ ((visibility ("default")))
void
sunday_load (SundayLoaderContext * ctx)
{
  ctx->libc->pthread_create (&ctx->worker, NULL, sunday_main, ctx);
}

static void *
sunday_main (void * user_data)
{
  SundayLoaderContext * ctx = user_data;
  const SundayLibcApi * libc = ctx->libc;
  pid_t thread_id;
  SundayUnloadPolicy unload_policy;
  int ctrlfd_for_peer, ctrlfd, agent_codefd, agent_ctrlfd;
  SundayLinuxInjectorState injector_state;

  thread_id = sunday_gettid ();
  unload_policy = SUNDAY_UNLOAD_POLICY_IMMEDIATE;
  ctrlfd = -1;
  agent_codefd = -1;
  agent_ctrlfd = -1;

  ctrlfd_for_peer = ctx->ctrlfds[0];
  if (ctrlfd_for_peer != -1)
    libc->close (ctrlfd_for_peer);

  ctrlfd = ctx->ctrlfds[1];
  if (ctrlfd != -1)
  {
    if (!sunday_send_hello (ctrlfd, thread_id, libc))
    {
      libc->close (ctrlfd);
      ctrlfd = -1;
    }
  }
  if (ctrlfd == -1)
  {
    ctrlfd = sunday_connect (ctx->fallback_address, libc);
    if (ctrlfd == -1)
      goto beach;

    if (!sunday_send_hello (ctrlfd, thread_id, libc))
      goto beach;
  }

  if (ctx->agent_handle == NULL)
  {
    char agent_path[32];
    const void * pretend_caller_addr = libc->close;

    agent_codefd = sunday_receive_fd (ctrlfd, libc);
    if (agent_codefd == -1)
      goto beach;

    libc->sprintf (agent_path, "/proc/self/fd/%d", agent_codefd);

    ctx->agent_handle = libc->dlopen (agent_path, libc->dlopen_flags, pretend_caller_addr);
    if (ctx->agent_handle == NULL)
      goto dlopen_failed;

    if (agent_codefd != -1)
    {
      libc->close (agent_codefd);
      agent_codefd = -1;
    }

    ctx->agent_entrypoint_impl = libc->dlsym (ctx->agent_handle, ctx->agent_entrypoint, pretend_caller_addr);
    if (ctx->agent_entrypoint_impl == NULL)
      goto dlsym_failed;
  }

  agent_ctrlfd = sunday_receive_fd (ctrlfd, libc);
  if (agent_ctrlfd != -1)
    sunday_enable_close_on_exec (agent_ctrlfd, libc);

  if (!sunday_send_ready (ctrlfd, libc))
    goto beach;
  if (!sunday_receive_ack (ctrlfd, libc))
    goto beach;

  injector_state.sunday_ctrlfd = ctrlfd;
  injector_state.agent_ctrlfd = agent_ctrlfd;

  ctx->agent_entrypoint_impl (ctx->agent_data, &unload_policy, &injector_state);

  ctrlfd = injector_state.sunday_ctrlfd;
  agent_ctrlfd = injector_state.agent_ctrlfd;

  goto beach;

dlopen_failed:
  {
    sunday_send_error (ctrlfd,
        SUNDAY_MESSAGE_ERROR_DLOPEN,
        (libc->dlerror != NULL) ? libc->dlerror () : "Unable to load library",
        libc);
    goto beach;
  }
dlsym_failed:
  {
    sunday_send_error (ctrlfd,
        SUNDAY_MESSAGE_ERROR_DLSYM,
        (libc->dlerror != NULL) ? libc->dlerror () : "Unable to find entrypoint",
        libc);
    goto beach;
  }
beach:
  {
    if (unload_policy == SUNDAY_UNLOAD_POLICY_IMMEDIATE && ctx->agent_handle != NULL)
      libc->dlclose (ctx->agent_handle);

    if (unload_policy != SUNDAY_UNLOAD_POLICY_DEFERRED)
      libc->pthread_detach (ctx->worker);

    if (agent_ctrlfd != -1)
      libc->close (agent_ctrlfd);

    if (agent_codefd != -1)
      libc->close (agent_codefd);

    if (ctrlfd != -1)
    {
      sunday_send_bye (ctrlfd, unload_policy, libc);
      libc->close (ctrlfd);
    }

    return NULL;
  }
}

/* TODO: Handle EINTR. */

static int
sunday_connect (const char * address, const SundayLibcApi * libc)
{
  bool success = false;
  int sockfd;
  struct sockaddr_un addr;
  size_t len;
  const char * c;
  char ch;

  sockfd = libc->socket (AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (sockfd == -1)
    goto beach;

  addr.sun_family = AF_UNIX;
  addr.sun_path[0] = '\0';
  for (c = address, len = 0; (ch = *c) != '\0'; c++, len++)
    addr.sun_path[1 + len] = ch;

  if (libc->connect (sockfd, (struct sockaddr *) &addr, offsetof (struct sockaddr_un, sun_path) + 1 + len) == -1)
    goto beach;

  success = true;

beach:
  if (!success && sockfd != -1)
  {
    libc->close (sockfd);
    sockfd = -1;
  }

  return sockfd;
}

static bool
sunday_send_hello (int sockfd, pid_t thread_id, const SundayLibcApi * libc)
{
  SundayMessageType type = SUNDAY_MESSAGE_HELLO;
  SundayHelloMessage hello = {
    .thread_id = thread_id,
  };

  if (!sunday_send_chunk (sockfd, &type, sizeof (type), libc))
    return false;

  return sunday_send_chunk (sockfd, &hello, sizeof (hello), libc);
}

static bool
sunday_send_ready (int sockfd, const SundayLibcApi * libc)
{
  SundayMessageType type = SUNDAY_MESSAGE_READY;

  return sunday_send_chunk (sockfd, &type, sizeof (type), libc);
}

static bool
sunday_receive_ack (int sockfd, const SundayLibcApi * libc)
{
  SundayMessageType type;

  if (!sunday_receive_chunk (sockfd, &type, sizeof (type), libc))
    return false;

  return type == SUNDAY_MESSAGE_ACK;
}

static bool
sunday_send_bye (int sockfd, SundayUnloadPolicy unload_policy, const SundayLibcApi * libc)
{
  SundayMessageType type = SUNDAY_MESSAGE_BYE;
  SundayByeMessage bye = {
    .unload_policy = unload_policy,
  };

  if (!sunday_send_chunk (sockfd, &type, sizeof (type), libc))
    return false;

  return sunday_send_chunk (sockfd, &bye, sizeof (bye), libc);
}

static bool
sunday_send_error (int sockfd, SundayMessageType type, const char * message, const SundayLibcApi * libc)
{
  uint16_t length;

  length = sunday_strlen (message);

  #define SUNDAY_SEND_VALUE(v) \
      if (!sunday_send_chunk (sockfd, &(v), sizeof (v), libc)) \
        return false
  #define SUNDAY_SEND_BYTES(data, size) \
      if (!sunday_send_chunk (sockfd, data, size, libc)) \
        return false

  SUNDAY_SEND_VALUE (type);
  SUNDAY_SEND_VALUE (length);
  SUNDAY_SEND_BYTES (message, length);

  return true;
}

static bool
sunday_receive_chunk (int sockfd, void * buffer, size_t length, const SundayLibcApi * libc)
{
  void * cursor = buffer;
  size_t remaining = length;

  while (remaining != 0)
  {
    struct iovec io = {
      .iov_base = cursor,
      .iov_len = remaining
    };
    struct msghdr msg;
    ssize_t n;

    /*
     * Avoid inline initialization to prevent the compiler attempting to insert
     * a call to memset.
     */
    msg.msg_name = NULL,
    msg.msg_namelen = 0,
    msg.msg_iov = &io,
    msg.msg_iovlen = 1,
    msg.msg_control = NULL,
    msg.msg_controllen = 0,

    n = libc->recvmsg (sockfd, &msg, 0);
    if (n <= 0)
      return false;

    cursor += n;
    remaining -= n;
  }

  return true;
}

static int
sunday_receive_fd (int sockfd, const SundayLibcApi * libc)
{
  int res;
  uint8_t dummy;
  struct iovec io = {
    .iov_base = &dummy,
    .iov_len = sizeof (dummy)
  };
  SundayControlMessage control;
  struct msghdr msg;

  /*
   * Avoid inline initialization to prevent the compiler attempting to insert
   * a call to memset.
   */
  msg.msg_name = NULL,
  msg.msg_namelen = 0,
  msg.msg_iov = &io,
  msg.msg_iovlen = 1,
  msg.msg_control = &control,
  msg.msg_controllen = sizeof (control),

  res = libc->recvmsg (sockfd, &msg, 0);
  if (res == -1 || res == 0 || msg.msg_controllen == 0)
    return -1;

  return *((int *) CMSG_DATA (CMSG_FIRSTHDR (&msg)));
}

static bool
sunday_send_chunk (int sockfd, const void * buffer, size_t length, const SundayLibcApi * libc)
{
  const void * cursor = buffer;
  size_t remaining = length;

  while (remaining != 0)
  {
    ssize_t n;

    n = libc->send (sockfd, cursor, remaining, MSG_NOSIGNAL);
    if (n == -1)
      return false;

    cursor += n;
    remaining -= n;
  }

  return true;
}

static void
sunday_enable_close_on_exec (int fd, const SundayLibcApi * libc)
{
  libc->fcntl (fd, F_SETFD, libc->fcntl (fd, F_GETFD) | FD_CLOEXEC);
}

static size_t
sunday_strlen (const char * str)
{
  size_t n = 0;
  const char * cursor;

  for (cursor = str; *cursor != '\0'; cursor++)
  {
    asm ("");
    n++;
  }

  return n;
}

static pid_t
sunday_gettid (void)
{
  return sunday_syscall_0 (SYS_gettid);
}
