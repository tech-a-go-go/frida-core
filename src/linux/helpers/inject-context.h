#ifndef __SUNDAY_INJECT_CONTEXT_H__
#define __SUNDAY_INJECT_CONTEXT_H__

#ifdef NOLIBC
# ifdef __ANDROID__
typedef long pthread_t;
# else
typedef void * pthread_t;
typedef struct _pthread_attr_t pthread_attr_t;
typedef unsigned int socklen_t;
# endif
struct msghdr;
struct sockaddr;
#else
# include <dlfcn.h>
# include <pthread.h>
# include <stdint.h>
# include <sys/mman.h>
# include <sys/socket.h>
#endif

typedef size_t SundayBootstrapStatus;
typedef struct _SundayBootstrapContext SundayBootstrapContext;
typedef struct _SundayLoaderContext SundayLoaderContext;
typedef struct _SundayLibcApi SundayLibcApi;
typedef uint8_t SundayMessageType;
typedef struct _SundayHelloMessage SundayHelloMessage;
typedef struct _SundayByeMessage SundayByeMessage;
typedef int SundayRtldFlavor;

enum _SundayBootstrapStatus
{
  SUNDAY_BOOTSTRAP_ALLOCATION_SUCCESS,
  SUNDAY_BOOTSTRAP_ALLOCATION_ERROR,

  SUNDAY_BOOTSTRAP_SUCCESS,
  SUNDAY_BOOTSTRAP_AUXV_NOT_FOUND,
  SUNDAY_BOOTSTRAP_TOO_EARLY,
  SUNDAY_BOOTSTRAP_LIBC_LOAD_ERROR,
  SUNDAY_BOOTSTRAP_LIBC_UNSUPPORTED,
};

struct _SundayBootstrapContext
{
  void * allocation_base;
  size_t allocation_size;

  size_t page_size;
  const char * fallback_ld;
  const char * fallback_libc;
  SundayRtldFlavor rtld_flavor;
  void * rtld_base;
  void * r_brk;
  int enable_ctrlfds;
  int ctrlfds[2];
  SundayLibcApi * libc;
};

struct _SundayLoaderContext
{
  int ctrlfds[2];
  const char * agent_entrypoint;
  const char * agent_data;
  const char * fallback_address;
  SundayLibcApi * libc;

  pthread_t worker;
  void * agent_handle;
  void (* agent_entrypoint_impl) (const char * data, int * unload_policy, void * injector_state);
};

struct _SundayLibcApi
{
  int (* printf) (const char * format, ...);
  int (* sprintf) (char * str, const char * format, ...);

  void * (* mmap) (void * addr, size_t length, int prot, int flags, int fd, off_t offset);
  int (* munmap) (void * addr, size_t length);
  int (* socket) (int domain, int type, int protocol);
  int (* socketpair) (int domain, int type, int protocol, int sv[2]);
  int (* connect) (int sockfd, const struct sockaddr * addr, socklen_t addrlen);
  ssize_t (* recvmsg) (int sockfd, struct msghdr * msg, int flags);
  ssize_t (* send) (int sockfd, const void * buf, size_t len, int flags);
  int (* fcntl) (int fd, int cmd, ...);
  int (* close) (int fd);

  int (* pthread_create) (pthread_t * thread, const pthread_attr_t * attr, void * (* start_routine) (void *), void * arg);
  int (* pthread_detach) (pthread_t thread);

  void * (* dlopen) (const char * filename, int flags, const void * caller_addr);
  int dlopen_flags;
  int (* dlclose) (void * handle);
  void * (* dlsym) (void * handle, const char * symbol, const void * caller_addr);
  char * (* dlerror) (void);
};

enum _SundayMessageType
{
  SUNDAY_MESSAGE_HELLO,
  SUNDAY_MESSAGE_READY,
  SUNDAY_MESSAGE_ACK,
  SUNDAY_MESSAGE_BYE,
  SUNDAY_MESSAGE_ERROR_DLOPEN,
  SUNDAY_MESSAGE_ERROR_DLSYM,
};

struct _SundayHelloMessage
{
  pid_t thread_id;
};

struct _SundayByeMessage
{
  int unload_policy;
};

enum _SundayRtldFlavor
{
  SUNDAY_RTLD_UNKNOWN,
  SUNDAY_RTLD_NONE,
  SUNDAY_RTLD_GLIBC,
  SUNDAY_RTLD_UCLIBC,
  SUNDAY_RTLD_MUSL,
  SUNDAY_RTLD_ANDROID,
};

#endif
