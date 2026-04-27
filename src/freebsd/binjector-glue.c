#include "frida-core.h"

#include <dlfcn.h>
#include <glib-unix.h>
#include <libelf.h>
#include <string.h>
#include <gio/gunixinputstream.h>
#include <gum/gumfreebsd.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/thr.h>
#include <sys/types.h>
#include <sys/wait.h>

#define SUNDAY_STACK_ALIGNMENT 16
#define SUNDAY_RED_ZONE_SIZE 128
#if GLIB_SIZEOF_VOID_P == 8
# define SUNDAY_MAP_FAILED G_MAXUINT64
#else
# define SUNDAY_MAP_FAILED G_MAXUINT32
#endif

#define CHECK_OS_RESULT(n1, cmp, n2, op) \
  if (!(n1 cmp n2)) \
  { \
    failed_operation = op; \
    goto os_failure; \
  }

typedef struct reg SundayRegs;

#define SUNDAY_REMOTE_DATA_FIELD(n) \
    (remote_address + params->data.offset + G_STRUCT_OFFSET (SundayTrampolineData, n))

#define SUNDAY_DUMMY_RETURN_ADDRESS 0x320

typedef struct _SundaySpawnInstance SundaySpawnInstance;
typedef struct _SundayExecInstance SundayExecInstance;
typedef struct _SundayNotifyExecPendingContext SundayNotifyExecPendingContext;
typedef struct _SundayInjectInstance SundayInjectInstance;
typedef struct _SundayInjectParams SundayInjectParams;
typedef struct _SundayInjectRegion SundayInjectRegion;
typedef struct _SundayCodeChunk SundayCodeChunk;
typedef struct _SundayTrampolineData SundayTrampolineData;
typedef struct _SundayRemoteApi SundayRemoteApi;

typedef void (* SundayInjectEmitFunc) (const SundayInjectParams * params, GumAddress remote_address, SundayCodeChunk * code);

struct _SundayRemoteApi
{
  GumAddress mmap_impl;
  GumAddress munmap_impl;
  GumAddress mprotect_impl;

  GumAddress open_impl;
  GumAddress close_impl;
  GumAddress write_impl;

  GumAddress dlopen_impl;
  GumAddress dlclose_impl;
  GumAddress dlsym_impl;
};

struct _SundaySpawnInstance
{
  pid_t pid;
  lwpid_t interruptible_thread;

  SundayBinjector * binjector;
};

struct _SundayExecInstance
{
  pid_t pid;
  lwpid_t interruptible_thread;

  SundayBinjector * binjector;
};

struct _SundayNotifyExecPendingContext
{
  pid_t pid;
  gboolean pending;
};

struct _SundayInjectInstance
{
  guint id;

  pid_t pid;
  SundayRemoteApi api;
  gchar * executable_path;
  gboolean already_attached;
  gboolean exec_pending;

  gchar * temp_path;

  gchar * fifo_path;
  gint fifo;
  gint previous_fifo;

  GumAddress remote_payload;
  guint remote_size;
  GumAddress entrypoint;
  GumAddress stack_top;
  GumAddress trampoline_data;

  SundayBinjector * binjector;
};

struct _SundayInjectRegion
{
  guint offset;
  guint size;
};

struct _SundayInjectParams
{
  pid_t pid;

  SundayRemoteApi api;

  const gchar * so_path;
  const gchar * entrypoint_name;
  const gchar * entrypoint_data;

  const gchar * fifo_path;

  SundayInjectRegion code;
  SundayInjectRegion data;
  SundayInjectRegion guard;
  SundayInjectRegion stack;

  GumAddress remote_address;
  guint remote_size;
};

struct _SundayCodeChunk
{
  guint8 * cur;
  gsize size;
};

struct _SundayTrampolineData
{
  gchar pthread_so_string[32];
  gchar pthread_create_string[16];
  gchar pthread_detach_string[16];
  gchar pthread_getthreadid_np_string[32];
  gchar fifo_path[256];
  gchar so_path[256];
  gchar entrypoint_name[256];
  gchar entrypoint_data[256];
  guint8 hello_byte;

  gpointer pthread_so;
  pthread_t worker_thread;
  gpointer module_handle;
};

static gboolean sunday_set_matching_inject_instances_exec_pending (GeeMapEntry * entry, SundayNotifyExecPendingContext * ctx);

static SundaySpawnInstance * sunday_spawn_instance_new (SundayBinjector * binjector);
static void sunday_spawn_instance_free (SundaySpawnInstance * instance);
static void sunday_spawn_instance_resume (SundaySpawnInstance * self);

static SundayExecInstance * sunday_exec_instance_new (SundayBinjector * binjector, pid_t pid);
static void sunday_exec_instance_free (SundayExecInstance * instance);
static gboolean sunday_exec_instance_prepare_transition (SundayExecInstance * self, GError ** error);
static gboolean sunday_exec_instance_try_perform_transition (SundayExecInstance * self, GError ** error);
static void sunday_exec_instance_suspend (SundayExecInstance * self);
static void sunday_exec_instance_resume (SundayExecInstance * self);

static SundayInjectInstance * sunday_inject_instance_new (SundayBinjector * binjector, guint id, guint pid, const SundayRemoteApi * api,
    const gchar * temp_path);
static void sunday_inject_instance_recreate_fifo (SundayInjectInstance * self);
static SundayInjectInstance * sunday_inject_instance_clone (const SundayInjectInstance * instance, guint id);
static void sunday_inject_instance_init_fifo (SundayInjectInstance * self);
static void sunday_inject_instance_close_previous_fifo (SundayInjectInstance * self);
static void sunday_inject_instance_free (SundayInjectInstance * instance, SundayUnloadPolicy unload_policy);
static gboolean sunday_inject_instance_did_not_exec (SundayInjectInstance * self);
static gboolean sunday_inject_instance_attach (SundayInjectInstance * self, SundayRegs * saved_regs, GError ** error);
static gboolean sunday_inject_instance_detach (SundayInjectInstance * self, const SundayRegs * saved_regs, GError ** error);
static gboolean sunday_inject_instance_start_remote_thread (SundayInjectInstance * self, gboolean * exited, GError ** error);
static gboolean sunday_inject_instance_emit_and_transfer_payload (SundayInjectEmitFunc func, const SundayInjectParams * params, GumAddress * entrypoint, GError ** error);
static void sunday_inject_instance_emit_payload_code (const SundayInjectParams * params, GumAddress remote_address, SundayCodeChunk * code);

static gboolean sunday_wait_for_attach_signal (pid_t pid);
static gboolean sunday_wait_for_child_signal (pid_t pid, int signal, gboolean * exited);
static gint sunday_get_regs (pid_t pid, SundayRegs * regs);
static gint sunday_set_regs (pid_t pid, const SundayRegs * regs);

static gboolean sunday_run_to_entrypoint (pid_t pid, GError ** error);

static gboolean sunday_remote_api_try_init (SundayRemoteApi * api, pid_t pid);
static GumAddress sunday_remote_alloc (pid_t pid, size_t size, int prot, const SundayRemoteApi * api, GError ** error);
static gboolean sunday_remote_dealloc (pid_t pid, GumAddress address, size_t size, const SundayRemoteApi * api, GError ** error);
static gboolean sunday_remote_mprotect (pid_t pid, GumAddress address, size_t size, int prot, const SundayRemoteApi * api, GError ** error);
static gboolean sunday_remote_read (pid_t pid, GumAddress remote_address, gpointer data, gsize size, GError ** error);
static gboolean sunday_remote_write (pid_t pid, GumAddress remote_address, gconstpointer data, gsize size, GError ** error);
static gboolean sunday_remote_call (pid_t pid, GumAddress func, const GumAddress * args, gint args_length, GumAddress * retval,
    gboolean * exited, GError ** error);
static gboolean sunday_remote_exec (pid_t pid, GumAddress remote_address, GumAddress remote_stack, GumAddress * result, gboolean * exited,
    GError ** error);

guint
_sunday_binjector_do_spawn (SundayBinjector * self, const gchar * path, SundayHostSpawnOptions * options, SundayStdioPipes ** pipes, GError ** error)
{
  SundaySpawnInstance * instance;
  gchar ** argv, ** envp;
  SundayFileDescriptor * in_fd = NULL;
  SundayFileDescriptor * out_fd = NULL;
  SundayFileDescriptor * err_fd = NULL;
  GError * stdio_error = NULL;
  gchar * old_cwd = NULL;
  gboolean success;
  const gchar * failed_operation;

  instance = sunday_spawn_instance_new (self);

  argv = sunday_host_spawn_options_compute_argv (options, path, NULL);
  envp = sunday_host_spawn_options_compute_envp (options, NULL);

  *pipes = sunday_make_stdio_pipes (options->stdio, TRUE, &in_fd, NULL, &out_fd, NULL, &err_fd, NULL, &stdio_error);
  if (stdio_error != NULL)
    goto propagate_stdio_error;

  if (strlen (options->cwd) > 0)
  {
    old_cwd = g_get_current_dir ();
    if (chdir (options->cwd) != 0)
      goto chdir_failed;
  }

  instance->pid = fork ();
  if (instance->pid == 0)
  {
    setsid ();

    if (options->stdio == SUNDAY_STDIO_PIPE)
    {
      dup2 (in_fd->handle, 0);
      dup2 (out_fd->handle, 1);
      dup2 (err_fd->handle, 2);
    }

    ptrace (PT_TRACE_ME, 0, NULL, 0);
    if (execve (path, argv, envp) == -1)
    {
      g_printerr ("Unexpected error while spawning process (execve failed: %s)\n", strerror (errno));
      _exit (1);
    }
  }

  if (old_cwd != NULL)
  {
    if (chdir (old_cwd) != 0)
      g_warning ("Failed to restore working directory");
  }

  success = sunday_wait_for_child_signal (instance->pid, SIGTRAP, NULL);
  CHECK_OS_RESULT (success, !=, FALSE, "wait(SIGTRAP)");

  if (!sunday_run_to_entrypoint (instance->pid, error))
    goto failure;

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->spawn_instances), GUINT_TO_POINTER (instance->pid), instance);

  goto beach;

propagate_stdio_error:
  {
    g_propagate_error (error, stdio_error);
    goto failure;
  }
chdir_failed:
  {
    g_set_error (error,
        SUNDAY_ERROR,
        SUNDAY_ERROR_INVALID_ARGUMENT,
        "Unable to change directory to '%s'",
        options->cwd);
    goto failure;
  }
os_failure:
  {
    (void) failed_operation;
    g_set_error (error,
        SUNDAY_ERROR,
        SUNDAY_ERROR_PERMISSION_DENIED,
        "Unable to spawn executable at '%s'",
        path);
    goto failure;
  }
failure:
  {
    g_clear_pointer (&instance, sunday_spawn_instance_free);
    goto beach;
  }
beach:
  {
    g_clear_object (&in_fd);
    g_clear_object (&out_fd);
    g_clear_object (&err_fd);

    g_free (old_cwd);
    g_strfreev (envp);
    g_strfreev (argv);

    return (instance != NULL) ? instance->pid : 0;
  }
}

void
_sunday_binjector_resume_spawn_instance (SundayBinjector * self, void * instance)
{
  sunday_spawn_instance_resume (instance);
}

void
_sunday_binjector_free_spawn_instance (SundayBinjector * self, void * instance)
{
  sunday_spawn_instance_free (instance);
}

void
_sunday_binjector_do_prepare_exec_transition (SundayBinjector * self, guint pid, GError ** error)
{
  SundayExecInstance * instance;

  instance = sunday_exec_instance_new (self, pid);

  if (!sunday_exec_instance_prepare_transition (instance, error))
    goto failure;

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->exec_instances), GUINT_TO_POINTER (pid), instance);

  return;

failure:
  {
    sunday_exec_instance_free (instance);
    return;
  }
}

void
_sunday_binjector_notify_exec_pending (SundayBinjector * self, guint pid, gboolean pending)
{
  SundayNotifyExecPendingContext ctx;

  ctx.pid = pid;
  ctx.pending = pending;

  gee_abstract_map_foreach (GEE_ABSTRACT_MAP (self->inject_instances),
      (GeeForallFunc) sunday_set_matching_inject_instances_exec_pending, &ctx);
}

static gboolean
sunday_set_matching_inject_instances_exec_pending (GeeMapEntry * entry, SundayNotifyExecPendingContext * ctx)
{
  SundayInjectInstance * instance;

  instance = (SundayInjectInstance *) gee_map_entry_get_value (entry);
  if (instance->pid == ctx->pid)
  {
    instance->exec_pending = ctx->pending;
  }

  return TRUE;
}

gboolean
_sunday_binjector_try_transition_exec_instance (SundayBinjector * self, void * instance, GError ** error)
{
  return sunday_exec_instance_try_perform_transition (instance, error);
}

void
_sunday_binjector_suspend_exec_instance (SundayBinjector * self, void * instance)
{
  sunday_exec_instance_suspend (instance);
}

void
_sunday_binjector_resume_exec_instance (SundayBinjector * self, void * instance)
{
  sunday_exec_instance_resume (instance);
}

void
_sunday_binjector_free_exec_instance (SundayBinjector * self, void * instance)
{
  sunday_exec_instance_free (instance);
}

void
_sunday_binjector_do_inject (SundayBinjector * self, guint pid, const gchar * path, const gchar * entrypoint, const gchar * data, const gchar * temp_path, guint id, GError ** error)
{
  SundayInjectParams params;
  guint offset, page_size;
  SundayInjectInstance * instance;
  SundayRegs saved_regs;
  gboolean exited;

  params.pid = pid;

  if (kill (pid, 0) != 0 && errno == EPERM)
    goto permission_denied;

  if (!sunday_remote_api_try_init (&params.api, pid))
    goto no_libc;

  params.so_path = path;
  params.entrypoint_name = entrypoint;
  params.entrypoint_data = data;

  params.fifo_path = NULL;

  offset = 0;
  page_size = gum_query_page_size ();

  params.code.offset = offset;
  params.code.size = page_size;
  offset += params.code.size;

  params.data.offset = offset;
  params.data.size = page_size;
  offset += params.data.size;

  params.guard.offset = offset;
  params.guard.size = page_size;
  offset += params.guard.size;

  params.stack.offset = offset;
  params.stack.size = 512 * 1024;
  offset += params.stack.size;

  params.remote_address = 0;
  params.remote_size = offset;

  instance = sunday_inject_instance_new (self, id, pid, &params.api, temp_path);
  if (instance->executable_path == NULL)
    goto premature_termination;

  if (!sunday_inject_instance_attach (instance, &saved_regs, error))
    goto premature_termination;

  params.fifo_path = instance->fifo_path;
  params.remote_address = sunday_remote_alloc (pid, params.remote_size, PROT_READ | PROT_WRITE, &params.api, error);
  if (params.remote_address == 0)
    goto premature_termination;
  instance->remote_payload = params.remote_address;
  instance->remote_size = params.remote_size;

  if (!sunday_inject_instance_emit_and_transfer_payload (sunday_inject_instance_emit_payload_code, &params, &instance->entrypoint, error))
    goto premature_termination;
  instance->stack_top = params.remote_address + params.stack.offset + params.stack.size;
  instance->trampoline_data = params.remote_address + params.data.offset;

  if (!sunday_inject_instance_start_remote_thread (instance, &exited, error) && !exited)
    goto premature_termination;

  if (!exited)
    sunday_inject_instance_detach (instance, &saved_regs, NULL);
  else
    g_clear_error (error);

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->inject_instances), GUINT_TO_POINTER (id), instance);

  return;

permission_denied:
  {
    g_set_error (error,
        SUNDAY_ERROR,
        SUNDAY_ERROR_PERMISSION_DENIED,
        "Unable to access process with pid %u due to system restrictions;"
        " try running Frida as root",
        pid);
    return;
  }
no_libc:
  {
    g_set_error (error,
        SUNDAY_ERROR,
        SUNDAY_ERROR_NOT_SUPPORTED,
        "Unable to inject library into process without libc");
    return;
  }
premature_termination:
  {
    sunday_inject_instance_free (instance, SUNDAY_UNLOAD_POLICY_IMMEDIATE);
    return;
  }
}

void
_sunday_binjector_demonitor (SundayBinjector * self, void * raw_instance)
{
  SundayInjectInstance * instance = raw_instance;

  sunday_inject_instance_recreate_fifo (instance);
}

guint
_sunday_binjector_demonitor_and_clone_injectee_state (SundayBinjector * self, void * raw_instance, guint clone_id)
{
  SundayInjectInstance * instance = raw_instance;
  SundayInjectInstance * clone;

  sunday_inject_instance_recreate_fifo (instance);

  clone = sunday_inject_instance_clone (instance, clone_id);

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->inject_instances), GUINT_TO_POINTER (clone->id), clone);

  return clone->id;
}

void
_sunday_binjector_recreate_injectee_thread (SundayBinjector * self, void * raw_instance, guint pid, GError ** error)
{
  SundayInjectInstance * instance = raw_instance;
  gboolean is_uninitialized_clone;
  SundayRegs saved_regs;
  gboolean exited;

  is_uninitialized_clone = instance->pid == 0;

  instance->pid = pid;

  sunday_inject_instance_close_previous_fifo (instance);

  if (!sunday_inject_instance_attach (instance, &saved_regs, error))
    goto failure;

  if (is_uninitialized_clone)
  {
    if (!sunday_remote_write (pid, instance->trampoline_data + G_STRUCT_OFFSET (SundayTrampolineData, fifo_path),
        instance->fifo_path, strlen (instance->fifo_path) + 1, error))
      goto failure;
  }

  if (!sunday_inject_instance_start_remote_thread (instance, &exited, error) && !exited)
    goto failure;

  if (!exited)
    sunday_inject_instance_detach (instance, &saved_regs, NULL);
  else
    g_clear_error (error);

  return;

failure:
  {
    _sunday_binjector_destroy_inject_instance (self, instance->id, SUNDAY_UNLOAD_POLICY_IMMEDIATE);
    return;
  }
}

GInputStream *
_sunday_binjector_get_fifo_for_inject_instance (SundayBinjector * self, void * instance)
{
  return g_unix_input_stream_new (((SundayInjectInstance *) instance)->fifo, FALSE);
}

void
_sunday_binjector_free_inject_instance (SundayBinjector * self, void * instance, SundayUnloadPolicy unload_policy)
{
  sunday_inject_instance_free (instance, unload_policy);
}

gboolean
_sunday_process_has_thread (guint pid, glong tid)
{
  return thr_kill2 (pid, tid, 0) == 0;
}

static SundaySpawnInstance *
sunday_spawn_instance_new (SundayBinjector * binjector)
{
  SundaySpawnInstance * instance;

  instance = g_slice_new0 (SundaySpawnInstance);
  instance->binjector = g_object_ref (binjector);

  return instance;
}

static void
sunday_spawn_instance_free (SundaySpawnInstance * instance)
{
  g_object_unref (instance->binjector);

  g_slice_free (SundaySpawnInstance, instance);
}

static void
sunday_spawn_instance_resume (SundaySpawnInstance * self)
{
  if (self->interruptible_thread != 0)
  {
    thr_kill2 (self->pid, self->interruptible_thread, SIGSTOP);
    sunday_wait_for_child_signal (self->pid, SIGSTOP, NULL);
  }

  ptrace (PT_DETACH, self->pid, NULL, 0);
}

static SundayExecInstance *
sunday_exec_instance_new (SundayBinjector * binjector, pid_t pid)
{
  SundayExecInstance * instance;

  instance = g_slice_new0 (SundayExecInstance);
  instance->pid = pid;

  instance->binjector = g_object_ref (binjector);

  return instance;
}

static void
sunday_exec_instance_free (SundayExecInstance * instance)
{
  g_object_unref (instance->binjector);

  g_slice_free (SundayExecInstance, instance);
}

static gboolean
sunday_exec_instance_prepare_transition (SundayExecInstance * self, GError ** error)
{
  int pt_result;
  const gchar * failed_operation;
  int status;
  pid_t wait_result;

  pt_result = ptrace (PT_ATTACH, self->pid, NULL, 0);
  CHECK_OS_RESULT (pt_result, ==, 0, "PT_ATTACH");

  status = 0;
  wait_result = waitpid (self->pid, &status, 0);
  if (wait_result != self->pid || !WIFSTOPPED (status) || WSTOPSIG (status) != SIGSTOP)
    goto wait_failed;

  pt_result = ptrace (PT_CONTINUE, self->pid, GSIZE_TO_POINTER (1), 0);
  CHECK_OS_RESULT (pt_result, ==, 0, "PT_CONTINUE");

  return TRUE;

os_failure:
  {
    g_set_error (error,
        SUNDAY_ERROR,
        SUNDAY_ERROR_PERMISSION_DENIED,
        "Unable to prepare for exec transition: %s failed", failed_operation);
    goto failure;
  }
wait_failed:
  {
    g_set_error (error,
        SUNDAY_ERROR,
        SUNDAY_ERROR_PERMISSION_DENIED,
        "Unable to prepare for exec transition: waitpid() failed");
    goto failure;
  }
failure:
  {
    return FALSE;
  }
}

static gboolean
sunday_exec_instance_try_perform_transition (SundayExecInstance * self, GError ** error)
{
  int status;
  pid_t wait_result;

  status = 0;
  wait_result = waitpid (self->pid, &status, WNOHANG);
  if (wait_result != self->pid)
    return FALSE;
  if (!WIFSTOPPED (status) || WSTOPSIG (status) != SIGTRAP)
    goto wait_failed;

  if (!sunday_run_to_entrypoint (self->pid, error))
    goto failure;

  return TRUE;

wait_failed:
  {
    g_set_error (error,
        SUNDAY_ERROR,
        SUNDAY_ERROR_PERMISSION_DENIED,
        "Unable to wait for exec transition: waitpid() failed");
    goto failure;
  }
failure:
  {
    return FALSE;
  }
}

static void
sunday_exec_instance_suspend (SundayExecInstance * self)
{
  kill (self->pid, SIGSTOP);
  sunday_wait_for_child_signal (self->pid, SIGSTOP, NULL);
}

static void
sunday_exec_instance_resume (SundayExecInstance * self)
{
  if (self->interruptible_thread != 0)
  {
    thr_kill2 (self->pid, self->interruptible_thread, SIGSTOP);
    sunday_wait_for_child_signal (self->pid, SIGSTOP, NULL);
  }

  ptrace (PT_DETACH, self->pid, NULL, 0);
}

static SundayInjectInstance *
sunday_inject_instance_new (SundayBinjector * binjector, guint id, guint pid, const SundayRemoteApi * api, const gchar * temp_path)
{
  SundayInjectInstance * instance;

  instance = g_slice_new0 (SundayInjectInstance);
  instance->id = id;

  instance->pid = pid;
  instance->api = *api;
  instance->executable_path = gum_freebsd_query_program_path_for_pid (pid, NULL);
  instance->already_attached = FALSE;
  instance->exec_pending = FALSE;

  instance->temp_path = g_strdup (temp_path);

  sunday_inject_instance_init_fifo (instance);
  instance->previous_fifo = -1;

  instance->binjector = g_object_ref (binjector);

  return instance;
}

static void
sunday_inject_instance_recreate_fifo (SundayInjectInstance * self)
{
  sunday_inject_instance_close_previous_fifo (self);
  self->previous_fifo = self->fifo;
  unlink (self->fifo_path);
  g_free (self->fifo_path);

  sunday_inject_instance_init_fifo (self);
}

static SundayInjectInstance *
sunday_inject_instance_clone (const SundayInjectInstance * instance, guint id)
{
  SundayInjectInstance * clone;

  clone = g_slice_dup (SundayInjectInstance, instance);
  clone->id = id;

  clone->pid = 0;
  clone->executable_path = g_strdup (instance->executable_path);
  clone->already_attached = FALSE;
  clone->exec_pending = FALSE;

  clone->temp_path = g_strdup (instance->temp_path);

  sunday_inject_instance_init_fifo (clone);
  clone->previous_fifo = -1;

  g_object_ref (clone->binjector);

  return clone;
}

static void
sunday_inject_instance_init_fifo (SundayInjectInstance * self)
{
  const int mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;

  self->fifo_path = g_strdup_printf ("%s/binjector-%u", self->temp_path, self->id);

  mkfifo (self->fifo_path, mode);
  chmod (self->fifo_path, mode);

  self->fifo = open (self->fifo_path, O_RDONLY | O_NONBLOCK);
  g_assert (self->fifo != -1);
}

static void
sunday_inject_instance_close_previous_fifo (SundayInjectInstance * self)
{
  if (self->previous_fifo != -1)
  {
    close (self->previous_fifo);
    self->previous_fifo = -1;
  }
}

static void
sunday_inject_instance_free (SundayInjectInstance * instance, SundayUnloadPolicy unload_policy)
{
  if (instance->pid != 0 && instance->remote_payload != 0 && unload_policy == SUNDAY_UNLOAD_POLICY_IMMEDIATE && !instance->exec_pending)
  {
    SundayRegs saved_regs;

    if (sunday_inject_instance_did_not_exec (instance) &&
        sunday_inject_instance_attach (instance, &saved_regs, NULL))
    {
      sunday_remote_dealloc (instance->pid, instance->remote_payload, instance->remote_size, &instance->api, NULL);
      sunday_inject_instance_detach (instance, &saved_regs, NULL);
    }
  }

  sunday_inject_instance_close_previous_fifo (instance);
  close (instance->fifo);
  unlink (instance->fifo_path);
  g_free (instance->fifo_path);

  g_free (instance->temp_path);

  g_free (instance->executable_path);

  g_object_unref (instance->binjector);

  g_slice_free (SundayInjectInstance, instance);
}

static gboolean
sunday_inject_instance_did_not_exec (SundayInjectInstance * self)
{
  gchar * executable_path;
  gboolean probably_did_not_exec;

  executable_path = gum_freebsd_query_program_path_for_pid (self->pid, NULL);
  if (executable_path == NULL)
    return FALSE;

  probably_did_not_exec = strcmp (executable_path, self->executable_path) == 0;

  g_free (executable_path);

  return probably_did_not_exec;
}

static gboolean
sunday_inject_instance_attach (SundayInjectInstance * self, SundayRegs * saved_regs, GError ** error)
{
  const pid_t pid = self->pid;
  int ret;
  int attach_errno;
  const gchar * failed_operation;
  gboolean maybe_already_attached, success;

  ret = ptrace (PT_ATTACH, pid, NULL, 0);
  attach_errno = errno;

  maybe_already_attached = (ret != 0 && attach_errno == EBUSY);
  if (maybe_already_attached)
  {
    ret = sunday_get_regs (pid, saved_regs);
    CHECK_OS_RESULT (ret, ==, 0, "sunday_get_regs");

    self->already_attached = TRUE;
  }
  else
  {
    CHECK_OS_RESULT (ret, ==, 0, "PT_ATTACH");

    self->already_attached = FALSE;

    success = sunday_wait_for_attach_signal (pid);
    if (!success)
      goto wait_failed;

    ret = sunday_get_regs (pid, saved_regs);
    if (ret != 0)
      goto wait_failed;
  }

  return TRUE;

os_failure:
  {
    if (attach_errno == EPERM)
    {
      g_set_error (error,
          SUNDAY_ERROR,
          SUNDAY_ERROR_PERMISSION_DENIED,
          "Unable to access process with pid %u due to system restrictions;"
          " try running Frida as root",
          pid);
    }
    else
    {
      g_set_error (error,
          SUNDAY_ERROR,
          SUNDAY_ERROR_NOT_SUPPORTED,
          "Unexpected error while attaching to process with pid %u (%s returned '%s')",
          pid, failed_operation, strerror (errno));
    }

    return FALSE;
  }
wait_failed:
  {
    ptrace (PT_DETACH, pid, NULL, 0);

    g_set_error (error,
        SUNDAY_ERROR,
        SUNDAY_ERROR_NOT_SUPPORTED,
        "Unexpected error while attaching to process with pid %u",
        pid);

    return FALSE;
  }
}

static gboolean
sunday_inject_instance_detach (SundayInjectInstance * self, const SundayRegs * saved_regs, GError ** error)
{
  const pid_t pid = self->pid;
  int ret;
  const gchar * failed_operation;

  ret = sunday_set_regs (pid, saved_regs);
  CHECK_OS_RESULT (ret, ==, 0, "sunday_set_regs");

  if (self->already_attached)
  {
    lwpid_t * interruptible_thread;
    SundaySpawnInstance * spawn;
    struct ptrace_lwpinfo lwp_info;
    lwpid_t main_thread, threads[2], non_main_thread;

    interruptible_thread = NULL;
    spawn = gee_abstract_map_get (GEE_ABSTRACT_MAP (self->binjector->spawn_instances), GUINT_TO_POINTER (pid));
    if (spawn != NULL)
    {
      interruptible_thread = &spawn->interruptible_thread;
    }
    else
    {
      SundayExecInstance * exec = gee_abstract_map_get (GEE_ABSTRACT_MAP (self->binjector->exec_instances), GUINT_TO_POINTER (pid));
      if (exec != NULL)
        interruptible_thread = &exec->interruptible_thread;
    }
    if (interruptible_thread == NULL)
      return TRUE;

    ret = ptrace (PT_LWPINFO, pid, (caddr_t) &lwp_info, sizeof (lwp_info));
    CHECK_OS_RESULT (ret, ==, 0, "PT_LWPINFO");
    main_thread = lwp_info.pl_lwpid;

    ret = ptrace (PT_GETLWPLIST, pid, (caddr_t) threads, G_N_ELEMENTS (threads));
    CHECK_OS_RESULT (ret, ==, G_N_ELEMENTS (threads), "PT_GETLWPLIST");
    non_main_thread = (threads[0] != main_thread) ? threads[0] : threads[1];
    *interruptible_thread = non_main_thread;

    ret = ptrace (PT_SUSPEND, main_thread, NULL, 0);
    CHECK_OS_RESULT (ret, ==, 0, "PT_SUSPEND");

    ret = ptrace (PT_CONTINUE, pid, GSIZE_TO_POINTER (1), 0);
    CHECK_OS_RESULT (ret, ==, 0, "PT_CONTINUE");
  }
  else
  {
    ret = ptrace (PT_DETACH, pid, NULL, 0);
    CHECK_OS_RESULT (ret, ==, 0, "PT_DETACH");
  }

  return TRUE;

os_failure:
  {
    g_set_error (error,
        SUNDAY_ERROR,
        SUNDAY_ERROR_INVALID_OPERATION,
        "detach_from_process %s failed: %s",
        failed_operation, g_strerror (errno));
    return FALSE;
  }
}

static gboolean
sunday_inject_instance_start_remote_thread (SundayInjectInstance * self, gboolean * exited, GError ** error)
{
  return sunday_remote_exec (self->pid, self->entrypoint, self->stack_top, NULL, exited, error);
}

static gboolean
sunday_inject_instance_emit_and_transfer_payload (SundayInjectEmitFunc func, const SundayInjectParams * params, GumAddress * entrypoint, GError ** error)
{
  const pid_t pid = params->pid;
  const SundayRemoteApi * api = &params->api;
  gboolean success = FALSE;
  gpointer scratch_buffer;
  SundayCodeChunk code;
  SundayTrampolineData * data;
  gchar * libthr_name;

  scratch_buffer = g_malloc0 (params->remote_size);

  code.cur = scratch_buffer + params->code.offset;
  code.size = 0;

  func (params, params->remote_address, &code);

  data = (SundayTrampolineData *) (scratch_buffer + params->data.offset);
  libthr_name = _sunday_detect_libthr_name ();
  strcpy (data->pthread_so_string, libthr_name);
  g_free (libthr_name);
  strcpy (data->pthread_create_string, "pthread_create");
  strcpy (data->pthread_detach_string, "pthread_detach");
  strcpy (data->pthread_getthreadid_np_string, "pthread_getthreadid_np");
  strcpy (data->fifo_path, params->fifo_path);
  strcpy (data->so_path, params->so_path);
  strcpy (data->entrypoint_name, params->entrypoint_name);
  strcpy (data->entrypoint_data, params->entrypoint_data);
  data->hello_byte = SUNDAY_PROGRESS_MESSAGE_TYPE_HELLO;

  if (!sunday_remote_write (pid, params->remote_address + params->code.offset, scratch_buffer + params->code.offset, code.size, error))
    goto beach;
  if (!sunday_remote_write (pid, params->remote_address + params->data.offset, data, sizeof (SundayTrampolineData), error))
    goto beach;

  if (!sunday_remote_mprotect (pid, params->remote_address + params->code.offset, params->code.size, PROT_READ | PROT_EXEC, api, error))
    goto beach;
  if (!sunday_remote_mprotect (pid, params->remote_address + params->guard.offset, params->guard.size, PROT_NONE, api, error))
    goto beach;

  *entrypoint = (params->remote_address + params->code.offset);

  success = TRUE;

beach:
  g_free (scratch_buffer);

  return success;
}

#define ARG_IMM(value) \
    GUM_ARG_ADDRESS, GUM_ADDRESS (value)

#if defined (HAVE_I386)

#define EMIT_MOVE(dst, src) \
    gum_x86_writer_put_mov_reg_reg (&cw, GUM_X86_##dst, GUM_X86_##src)
#define EMIT_LEA(dst, src, offset) \
    gum_x86_writer_put_lea_reg_reg_offset (&cw, GUM_X86_##dst, GUM_X86_##src, offset)
#define EMIT_SUB(reg, value) \
    gum_x86_writer_put_sub_reg_imm (&cw, GUM_X86_##reg, value)
#define EMIT_PUSH(reg) \
    gum_x86_writer_put_push_reg (&cw, GUM_X86_##reg)
#define EMIT_POP(reg) \
    gum_x86_writer_put_pop_reg (&cw, GUM_X86_##reg)
#define EMIT_LOAD_FIELD(reg, field) \
    gum_x86_writer_put_mov_reg_near_ptr (&cw, GUM_X86_##reg, SUNDAY_REMOTE_DATA_FIELD (field))
#define EMIT_STORE_FIELD(field, reg) \
    gum_x86_writer_put_mov_near_ptr_reg (&cw, SUNDAY_REMOTE_DATA_FIELD (field), GUM_X86_##reg)
#define EMIT_LOAD_IMM(reg, value) \
    gum_x86_writer_put_mov_reg_address (&cw, GUM_X86_##reg, value)
#define EMIT_LOAD_REG(dst, src, offset) \
    gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_X86_##dst, GUM_X86_##src, offset)
#define EMIT_LOAD_REGV(dst, src, offset) \
    gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, dst, GUM_X86_##src, offset)
#define EMIT_STORE_IMM(dst, offset, value) \
    gum_x86_writer_put_mov_reg_offset_ptr_u32 (&cw, GUM_X86_##dst, offset, value)
#define EMIT_STORE_REG(dst, offset, src) \
    gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw, GUM_X86_##dst, offset, GUM_X86_##src)
#define EMIT_CALL_IMM(func, n_args, ...) \
    gum_x86_writer_put_call_address_with_aligned_arguments (&cw, GUM_CALL_CAPI, func, n_args, __VA_ARGS__)
#define EMIT_CALL_REG(reg, n_args, ...) \
    gum_x86_writer_put_call_reg_with_aligned_arguments (&cw, GUM_CALL_CAPI, GUM_X86_##reg, n_args, __VA_ARGS__)
#define EMIT_RET() \
    gum_x86_writer_put_ret (&cw)
#define EMIT_LABEL(name) \
    gum_x86_writer_put_label (&cw, name)
#define EMIT_CMP(reg, value) \
    gum_x86_writer_put_cmp_reg_i32 (&cw, GUM_X86_##reg, value)
#define EMIT_JE(label) \
    gum_x86_writer_put_jcc_short_label (&cw, X86_INS_JE, label, GUM_NO_HINT)
#define EMIT_JNE(label) \
    gum_x86_writer_put_jcc_short_label (&cw, X86_INS_JNE, label, GUM_NO_HINT)

#define ARG_REG(reg) \
    GUM_ARG_REGISTER, GUM_X86_##reg
#define ARG_REGV(reg) \
    GUM_ARG_REGISTER, reg

static void
sunday_inject_instance_commit_x86_code (GumX86Writer * cw, SundayCodeChunk * code)
{
  gum_x86_writer_flush (cw);
  code->cur = gum_x86_writer_cur (cw);
  code->size += gum_x86_writer_offset (cw);
}

static void
sunday_inject_instance_emit_payload_code (const SundayInjectParams * params, GumAddress remote_address, SundayCodeChunk * code)
{
  const SundayRemoteApi * api = &params->api;
  GumX86Writer cw;
  const guint worker_offset = 172;
  gssize fd_offset, unload_policy_offset, tid_offset;
  const gchar * skip_dlopen = "skip_dlopen";
  const gchar * skip_dlclose = "skip_dlclose";
  const gchar * skip_detach = "skip_detach";
  GumX86Reg fd_reg;

  gum_x86_writer_init (&cw, code->cur);
  cw.pc = remote_address + params->code.offset + code->size;

  EMIT_CALL_IMM (api->dlopen_impl,
      2,
      ARG_IMM (SUNDAY_REMOTE_DATA_FIELD (pthread_so_string)),
      ARG_IMM (RTLD_GLOBAL | RTLD_LAZY));
  EMIT_STORE_FIELD (pthread_so, XAX);

  EMIT_CALL_IMM (api->dlsym_impl,
      2,
      ARG_REG (XAX),
      ARG_IMM (SUNDAY_REMOTE_DATA_FIELD (pthread_create_string)));

  EMIT_CALL_REG (XAX,
      4,
      ARG_IMM (SUNDAY_REMOTE_DATA_FIELD (worker_thread)),
      ARG_IMM (0),
      ARG_IMM (remote_address + worker_offset),
      ARG_IMM (0));

  gum_x86_writer_put_breakpoint (&cw);
  gum_x86_writer_flush (&cw);
  g_assert (gum_x86_writer_offset (&cw) <= worker_offset);
  while (gum_x86_writer_offset (&cw) != worker_offset - code->size)
    gum_x86_writer_put_nop (&cw);
  sunday_inject_instance_commit_x86_code (&cw, code);
  gum_x86_writer_clear (&cw);

  gum_x86_writer_init (&cw, code->cur);
  cw.pc = remote_address + params->code.offset + worker_offset;

  EMIT_PUSH (XBP);
  EMIT_MOVE (XBP, XSP);
  EMIT_SUB (XSP, 32 + ((cw.target_cpu == GUM_CPU_IA32) ? 4 : 8));
  EMIT_PUSH (XBX);

  fd_offset = -4;
  unload_policy_offset = -8;
  tid_offset = -12;

  EMIT_CALL_IMM (api->open_impl,
      2,
      ARG_IMM (SUNDAY_REMOTE_DATA_FIELD (fifo_path)),
      ARG_IMM (O_WRONLY | O_CLOEXEC));
  EMIT_STORE_REG (XBP, fd_offset, EAX);

  EMIT_CALL_IMM (api->write_impl,
      3,
      ARG_REG (EAX),
      ARG_IMM (SUNDAY_REMOTE_DATA_FIELD (hello_byte)),
      ARG_IMM (1));

  EMIT_LOAD_FIELD (XAX, module_handle);
  EMIT_CMP (XAX, 0);
  EMIT_JNE (skip_dlopen);
  {
    EMIT_CALL_IMM (api->dlopen_impl,
        2,
        ARG_IMM (SUNDAY_REMOTE_DATA_FIELD (so_path)),
        ARG_IMM (RTLD_LAZY));
    EMIT_STORE_FIELD (module_handle, XAX);
  }
  EMIT_LABEL (skip_dlopen);

  EMIT_CALL_IMM (api->dlsym_impl,
      2,
      ARG_REG (XAX),
      ARG_IMM (SUNDAY_REMOTE_DATA_FIELD (entrypoint_name)));

  EMIT_STORE_IMM (XBP, unload_policy_offset, SUNDAY_UNLOAD_POLICY_IMMEDIATE);
  EMIT_LEA (XCX, XBP, unload_policy_offset);
  EMIT_LEA (XDX, XBP, fd_offset);
  EMIT_CALL_REG (XAX,
      3,
      ARG_IMM (SUNDAY_REMOTE_DATA_FIELD (entrypoint_data)),
      ARG_REG (XCX),
      ARG_REG (XDX));

  EMIT_LOAD_REG (EAX, XBP, unload_policy_offset);
  EMIT_CMP (EAX, SUNDAY_UNLOAD_POLICY_IMMEDIATE);
  EMIT_JNE (skip_dlclose);
  {
    EMIT_LOAD_FIELD (XAX, module_handle);
    EMIT_CALL_IMM (api->dlclose_impl,
        1,
        ARG_REG (XAX));
  }
  EMIT_LABEL (skip_dlclose);

  EMIT_LOAD_REG (EAX, XBP, unload_policy_offset);
  EMIT_CMP (EAX, SUNDAY_UNLOAD_POLICY_DEFERRED);
  EMIT_JE (skip_detach);
  {
    EMIT_LOAD_FIELD (XAX, pthread_so);
    EMIT_CALL_IMM (api->dlsym_impl,
        2,
        ARG_REG (XAX),
        ARG_IMM (SUNDAY_REMOTE_DATA_FIELD (pthread_detach_string)));
    EMIT_LOAD_FIELD (XCX, worker_thread);
    EMIT_CALL_REG (XAX,
        1,
        ARG_REG (XCX));
  }
  EMIT_LABEL (skip_detach);

  EMIT_LOAD_FIELD (XAX, pthread_so);
  EMIT_CALL_IMM (api->dlsym_impl,
      2,
      ARG_REG (XAX),
      ARG_IMM (SUNDAY_REMOTE_DATA_FIELD (pthread_getthreadid_np_string)));
  gum_x86_writer_put_call_reg (&cw, GUM_X86_XAX);
  EMIT_STORE_REG (XBP, tid_offset, EAX);

  EMIT_LOAD_FIELD (XAX, pthread_so);
  EMIT_CALL_IMM (api->dlclose_impl,
      1,
      ARG_REG (XAX));

  fd_reg = (cw.target_cpu == GUM_CPU_IA32) ? GUM_X86_EDX : GUM_X86_EDI;

  EMIT_LOAD_REGV (fd_reg, XBP, fd_offset);
  EMIT_LEA (XCX, XBP, unload_policy_offset);
  EMIT_CALL_IMM (api->write_impl,
      3,
      ARG_REGV (fd_reg),
      ARG_REG (XCX),
      ARG_IMM (1));

  EMIT_LOAD_REGV (fd_reg, XBP, fd_offset);
  EMIT_LEA (XCX, XBP, tid_offset);
  EMIT_CALL_IMM (api->write_impl,
      3,
      ARG_REGV (fd_reg),
      ARG_REG (XCX),
      ARG_IMM (4));

  EMIT_LOAD_REG (ECX, XBP, fd_offset);
  EMIT_CALL_IMM (api->close_impl,
      1,
      ARG_REG (ECX));

  EMIT_POP (XBX);
  EMIT_MOVE (XSP, XBP);
  EMIT_POP (XBP);
  EMIT_RET ();

  sunday_inject_instance_commit_x86_code (&cw, code);
  gum_x86_writer_clear (&cw);
}

#elif defined (HAVE_ARM64)

#define EMIT_MOVE(dst, src) \
    gum_arm64_writer_put_mov_reg_reg (&cw, ARM64_REG_##dst, ARM64_REG_##src)
#define EMIT_ADD(dst, src, offset) \
    gum_arm64_writer_put_add_reg_reg_imm (&cw, ARM64_REG_##dst, ARM64_REG_##src, offset)
#define EMIT_PUSH(a, b) \
    gum_arm64_writer_put_push_reg_reg (&cw, ARM64_REG_##a, ARM64_REG_##b)
#define EMIT_POP(a, b) \
    gum_arm64_writer_put_pop_reg_reg (&cw, ARM64_REG_##a, ARM64_REG_##b)
#define EMIT_LOAD_FIELD(reg, field) \
    gum_arm64_writer_put_ldr_reg_reg_offset (&cw, ARM64_REG_##reg, ARM64_REG_X20, G_STRUCT_OFFSET (SundayTrampolineData, field))
#define EMIT_STORE_FIELD(field, reg) \
    gum_arm64_writer_put_str_reg_reg_offset (&cw, ARM64_REG_##reg, ARM64_REG_X20, G_STRUCT_OFFSET (SundayTrampolineData, field))
#define EMIT_LDR(dst, src, offset) \
    gum_arm64_writer_put_ldr_reg_reg_offset (&cw, ARM64_REG_##dst, ARM64_REG_##src, offset)
#define EMIT_LDR_ADDRESS(reg, value) \
    gum_arm64_writer_put_ldr_reg_address (&cw, ARM64_REG_##reg, value)
#define EMIT_LDR_U64(reg, value) \
    gum_arm64_writer_put_ldr_reg_u64 (&cw, ARM64_REG_##reg, value)
#define EMIT_CALL_IMM(func, n_args, ...) \
    gum_arm64_writer_put_call_address_with_arguments (&cw, func, n_args, __VA_ARGS__)
#define EMIT_CALL_REG(reg, n_args, ...) \
    gum_arm64_writer_put_call_reg_with_arguments (&cw, ARM64_REG_##reg, n_args, __VA_ARGS__)
#define EMIT_RET() \
    gum_arm64_writer_put_ret (&cw)
#define EMIT_LABEL(name) \
    gum_arm64_writer_put_label (&cw, name)
#define EMIT_CBNZ(reg, label) \
    gum_arm64_writer_put_cbnz_reg_label (&cw, ARM64_REG_##reg, label)
#define EMIT_CMP(a, b) \
    gum_arm64_writer_put_cmp_reg_reg (&cw, ARM64_REG_##a, ARM64_REG_##b)
#define EMIT_B_COND(cond, label) \
    gum_arm64_writer_put_b_cond_label (&cw, ARM64_CC_##cond, label)

#define ARG_REG(reg) \
    GUM_ARG_REGISTER, ARM64_REG_##reg

static void
sunday_inject_instance_commit_arm64_code (GumArm64Writer * cw, SundayCodeChunk * code)
{
  gum_arm64_writer_flush (cw);
  code->cur = gum_arm64_writer_cur (cw);
  code->size += gum_arm64_writer_offset (cw);
}

static void
sunday_inject_instance_emit_payload_code (const SundayInjectParams * params, GumAddress remote_address, SundayCodeChunk * code)
{
  const SundayRemoteApi * api = &params->api;
  GumArm64Writer cw;
  const guint worker_offset = 128;
  const gchar * skip_dlopen = "skip_dlopen";
  const gchar * skip_dlclose = "skip_dlclose";
  const gchar * skip_detach = "skip_detach";

  gum_arm64_writer_init (&cw, code->cur);
  cw.pc = remote_address + params->code.offset + code->size;

  EMIT_LDR_ADDRESS (X20, remote_address + params->data.offset);

  EMIT_CALL_IMM (api->dlopen_impl,
      2,
      ARG_IMM (SUNDAY_REMOTE_DATA_FIELD (pthread_so_string)),
      ARG_IMM (RTLD_GLOBAL | RTLD_LAZY));
  EMIT_STORE_FIELD (pthread_so, X0);

  EMIT_CALL_IMM (api->dlsym_impl,
      2,
      ARG_REG (X0),
      ARG_IMM (SUNDAY_REMOTE_DATA_FIELD (pthread_create_string)));
  EMIT_MOVE (X5, X0);

  EMIT_CALL_REG (X5,
      4,
      ARG_IMM (SUNDAY_REMOTE_DATA_FIELD (worker_thread)),
      ARG_IMM (0),
      ARG_IMM (remote_address + worker_offset),
      ARG_IMM (remote_address + params->data.offset));

  gum_arm64_writer_put_brk_imm (&cw, 0);
  gum_arm64_writer_flush (&cw);
  g_assert (gum_arm64_writer_offset (&cw) <= worker_offset);
  while (gum_arm64_writer_offset (&cw) != worker_offset - code->size)
    gum_arm64_writer_put_nop (&cw);
  sunday_inject_instance_commit_arm64_code (&cw, code);
  gum_arm64_writer_clear (&cw);

  gum_arm64_writer_init (&cw, code->cur);
  cw.pc = remote_address + params->code.offset + worker_offset;

  EMIT_PUSH (FP, LR);
  EMIT_MOVE (FP, SP);
  EMIT_PUSH (X23, X24);
  EMIT_PUSH (X21, X22);
  EMIT_PUSH (X19, X20);

  EMIT_MOVE (X20, X0);

  EMIT_CALL_IMM (api->open_impl,
      2,
      ARG_IMM (SUNDAY_REMOTE_DATA_FIELD (fifo_path)),
      ARG_IMM (O_WRONLY | O_CLOEXEC));
  EMIT_MOVE (W21, W0);

  EMIT_CALL_IMM (api->write_impl,
      3,
      ARG_REG (W21),
      ARG_IMM (SUNDAY_REMOTE_DATA_FIELD (hello_byte)),
      ARG_IMM (1));

  EMIT_LOAD_FIELD (X19, module_handle);
  EMIT_CBNZ (X19, skip_dlopen);
  {
    EMIT_CALL_IMM (api->dlopen_impl,
        2,
        ARG_IMM (SUNDAY_REMOTE_DATA_FIELD (so_path)),
        ARG_IMM (RTLD_LAZY));
    EMIT_MOVE (X19, X0);
    EMIT_STORE_FIELD (module_handle, X19);
  }
  EMIT_LABEL (skip_dlopen);

  EMIT_CALL_IMM (api->dlsym_impl,
      2,
      ARG_REG (X19),
      ARG_IMM (SUNDAY_REMOTE_DATA_FIELD (entrypoint_name)));
  EMIT_MOVE (X5, X0);

  EMIT_LDR_U64 (X0, SUNDAY_UNLOAD_POLICY_IMMEDIATE);
  EMIT_PUSH (X0, X21);
  EMIT_MOVE (X1, SP);
  EMIT_ADD (X2, SP, 8);
  EMIT_CALL_REG (X5,
      3,
      ARG_IMM (SUNDAY_REMOTE_DATA_FIELD (entrypoint_data)),
      ARG_REG (X1),
      ARG_REG (X2));

  EMIT_LDR (W21, SP, 8);
  EMIT_LDR (W22, SP, 0);

  EMIT_LDR_U64 (X1, SUNDAY_UNLOAD_POLICY_IMMEDIATE);
  EMIT_CMP (W22, W1);
  EMIT_B_COND (NE, skip_dlclose);
  {
    EMIT_CALL_IMM (api->dlclose_impl,
        1,
        ARG_REG (X19));
  }
  EMIT_LABEL (skip_dlclose);

  EMIT_LDR_U64 (X1, SUNDAY_UNLOAD_POLICY_DEFERRED);
  EMIT_CMP (W22, W1);
  EMIT_B_COND (EQ, skip_detach);
  {
    EMIT_LOAD_FIELD (X0, pthread_so);
    EMIT_CALL_IMM (api->dlsym_impl,
        2,
        ARG_REG (X0),
        ARG_IMM (SUNDAY_REMOTE_DATA_FIELD (pthread_detach_string)));
    EMIT_MOVE (X5, X0);
    EMIT_LOAD_FIELD (X0, worker_thread);
    EMIT_CALL_REG (X5,
        1,
        ARG_REG (X0));
  }
  EMIT_LABEL (skip_detach);

  EMIT_LOAD_FIELD (X0, pthread_so);
  EMIT_CALL_IMM (api->dlsym_impl,
      2,
      ARG_REG (X0),
      ARG_IMM (SUNDAY_REMOTE_DATA_FIELD (pthread_getthreadid_np_string)));
  gum_arm64_writer_put_blr_reg (&cw, ARM64_REG_X0);
  EMIT_MOVE (W23, W0);

  EMIT_LOAD_FIELD (X0, pthread_so);
  EMIT_CALL_IMM (api->dlclose_impl,
      1,
      ARG_REG (X0));

  EMIT_MOVE (X1, SP);
  EMIT_CALL_IMM (api->write_impl,
      3,
      ARG_REG (W21),
      ARG_REG (X1),
      ARG_IMM (1));

  EMIT_POP (X0, X1);

  EMIT_PUSH (X23, X24);
  EMIT_MOVE (X1, SP);
  EMIT_CALL_IMM (api->write_impl,
      3,
      ARG_REG (W21),
      ARG_REG (X1),
      ARG_IMM (4));
  EMIT_POP (X23, X24);

  EMIT_CALL_IMM (api->close_impl,
      1,
      ARG_REG (W21));

  EMIT_POP (X19, X20);
  EMIT_POP (X21, X22);
  EMIT_POP (X23, X24);
  EMIT_POP (FP, LR);
  EMIT_RET ();

  sunday_inject_instance_commit_arm64_code (&cw, code);
  gum_arm64_writer_clear (&cw);
}

#endif

static gboolean
sunday_wait_for_attach_signal (pid_t pid)
{
  int status = 0;
  pid_t res;
  int stop_signal;

  res = waitpid (pid, &status, 0);
  if (res != pid || !WIFSTOPPED (status))
    return FALSE;
  stop_signal = WSTOPSIG (status);

  switch (stop_signal)
  {
    case SIGTRAP:
      if (ptrace (PT_CONTINUE, pid, GSIZE_TO_POINTER (1), 0) != 0)
        return FALSE;
      if (!sunday_wait_for_child_signal (pid, SIGSTOP, NULL))
        return FALSE;
      /* fall through */
    case SIGSTOP:
      return TRUE;
    default:
      break;
  }

  return FALSE;
}

static gboolean
sunday_wait_for_child_signal (pid_t pid, int signal, gboolean * exited)
{
  gboolean success = FALSE;
  gboolean child_did_exit = TRUE;
  int status = 0;
  pid_t res;

  res = waitpid (pid, &status, 0);
  if (res != pid || WIFEXITED (status))
    goto beach;

  child_did_exit = FALSE;

  if (!WIFSTOPPED (status))
    goto beach;

  if (signal == SIGTRAP)
  {
    switch (WSTOPSIG (status))
    {
      case SIGTRAP:
      case SIGTTIN:
      case SIGTTOU:
        success = TRUE;
        break;
      default:
        success = FALSE;
        break;
    }
  }
  else
  {
    success = WSTOPSIG (status) == signal;
  }

beach:
  if (exited != NULL)
    *exited = child_did_exit;

  return success;
}

static gint
sunday_get_regs (pid_t pid, SundayRegs * regs)
{
  return ptrace (PT_GETREGS, pid, (caddr_t) regs, 0);
}

static gint
sunday_set_regs (pid_t pid, const SundayRegs * regs)
{
  return ptrace (PT_SETREGS, pid, (caddr_t) regs, 0);
}

static gboolean
sunday_run_to_entrypoint (pid_t pid, GError ** error)
{
  GumAddress entrypoint;
#if defined (HAVE_I386)
  guint8 original_entry_insn;
  const guint8 patched_entry_insn = 0xcc;
#elif defined (HAVE_ARM64)
  guint32 original_entry_insn;
  const guint32 patched_entry_insn = 0xd4200000;
#else
# error Unsupported architecture
#endif
  int ret;
  const gchar * failed_operation;
  gboolean success;
  SundayRegs regs;

  entrypoint = _sunday_find_entrypoint (pid, error);
  if (entrypoint == 0)
    goto propagate_error;

  if (!sunday_remote_read (pid, entrypoint, &original_entry_insn, sizeof (original_entry_insn), error))
    goto propagate_error;

  if (!sunday_remote_write (pid, entrypoint, &patched_entry_insn, sizeof (patched_entry_insn), error))
    goto propagate_error;

  ret = ptrace (PT_CONTINUE, pid, GSIZE_TO_POINTER (1), 0);
  CHECK_OS_RESULT (ret, ==, 0, "PT_CONTINUE");

  success = sunday_wait_for_child_signal (pid, SIGTRAP, NULL);
  CHECK_OS_RESULT (success, !=, FALSE, "WAIT(SIGTRAP)");

  if (!sunday_remote_write (pid, entrypoint, &original_entry_insn, sizeof (original_entry_insn), error))
    goto propagate_error;

  ret = sunday_get_regs (pid, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "sunday_get_regs");

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  regs.r_eip = entrypoint;
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  regs.r_rip = entrypoint;
#elif defined (HAVE_ARM64)
  regs.elr = entrypoint;
#else
# error Unsupported architecture
#endif

  ret = sunday_set_regs (pid, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "sunday_set_regs");

  return TRUE;

propagate_error:
  {
    return FALSE;
  }
os_failure:
  {
    g_set_error (error,
        SUNDAY_ERROR,
        SUNDAY_ERROR_PERMISSION_DENIED,
        "%s failed: %s",
        failed_operation, g_strerror (errno));
    return FALSE;
  }
}

static gboolean
sunday_remote_api_try_init (SundayRemoteApi * api, pid_t pid)
{
  gboolean success = FALSE;
  SundaySymbolResolver * resolver;

  resolver = sunday_symbol_resolver_new (pid);

#define SUNDAY_TRY_RESOLVE(kind, name) \
    api->name##_impl = sunday_symbol_resolver_find_##kind##_function (resolver, G_STRINGIFY (name)); \
    if (api->name##_impl == 0) \
      goto beach

  SUNDAY_TRY_RESOLVE (ld, dlopen);
  SUNDAY_TRY_RESOLVE (ld, dlclose);
  SUNDAY_TRY_RESOLVE (ld, dlsym);

  SUNDAY_TRY_RESOLVE (libc, mmap);
  SUNDAY_TRY_RESOLVE (libc, munmap);
  SUNDAY_TRY_RESOLVE (libc, mprotect);

  SUNDAY_TRY_RESOLVE (libc, open);
  SUNDAY_TRY_RESOLVE (libc, close);
  SUNDAY_TRY_RESOLVE (libc, write);

#undef SUNDAY_TRY_RESOLVE

  success = TRUE;
  goto beach;

beach:
  {
    g_object_unref (resolver);

    return success;
  }
}

static GumAddress
sunday_remote_alloc (pid_t pid, size_t size, int prot, const SundayRemoteApi * api, GError ** error)
{
  GumAddress args[] = {
    0,
    size,
    prot,
    MAP_PRIVATE | MAP_ANONYMOUS,
    -1,
    0
  };
  GumAddress retval;

  if (!sunday_remote_call (pid, api->mmap_impl, args, G_N_ELEMENTS (args), &retval, NULL, error))
    return 0;

  if (retval == SUNDAY_MAP_FAILED)
    goto mmap_failed;

  return retval;

mmap_failed:
  {
    g_set_error (error,
        SUNDAY_ERROR,
        SUNDAY_ERROR_NOT_SUPPORTED,
        "Unable to allocate memory in the specified process");
    goto failure;
  }
failure:
  {
    return 0;
  }
}

static gboolean
sunday_remote_dealloc (pid_t pid, GumAddress address, size_t size, const SundayRemoteApi * api, GError ** error)
{
  GumAddress args[] = {
    address,
    size
  };
  GumAddress retval;

  if (!sunday_remote_call (pid, api->munmap_impl, args, G_N_ELEMENTS (args), &retval, NULL, error))
    return FALSE;

  return retval == 0;
}

static gboolean
sunday_remote_mprotect (pid_t pid, GumAddress address, size_t size, int prot, const SundayRemoteApi * api, GError ** error)
{
  GumAddress args[] = {
    address,
    size,
    prot
  };
  GumAddress retval;

  if (!sunday_remote_call (pid, api->mprotect_impl, args, G_N_ELEMENTS (args), &retval, NULL, error))
    return FALSE;

  return retval == 0;
}

static gboolean
sunday_remote_read (pid_t pid, GumAddress remote_address, gpointer data, gsize size, GError ** error)
{
  struct ptrace_io_desc d;

  d.piod_op = PIOD_READ_D;
  d.piod_offs = GSIZE_TO_POINTER (remote_address);
  d.piod_addr = data;
  d.piod_len = size;

  if (ptrace (PT_IO, pid, (caddr_t) &d, 0) != 0)
    goto failure;

  return TRUE;

failure:
  {
    g_set_error (error,
        SUNDAY_ERROR,
        SUNDAY_ERROR_NOT_SUPPORTED,
        "remote_read failed: %s",
        strerror (errno));
    return FALSE;
  }
}

static gboolean
sunday_remote_write (pid_t pid, GumAddress remote_address, gconstpointer data, gsize size, GError ** error)
{
  struct ptrace_io_desc d;

  d.piod_op = PIOD_WRITE_D;
  d.piod_offs = GSIZE_TO_POINTER (remote_address);
  d.piod_addr = (void *) data;
  d.piod_len = size;

  if (ptrace (PT_IO, pid, (caddr_t) &d, 0) != 0)
    goto failure;

  return TRUE;

failure:
  {
    g_set_error (error,
        SUNDAY_ERROR,
        SUNDAY_ERROR_NOT_SUPPORTED,
        "remote_write failed: %s",
        strerror (errno));
    return FALSE;
  }
}

static gboolean
sunday_remote_call (pid_t pid, GumAddress func, const GumAddress * args, gint args_length, GumAddress * retval, gboolean * exited,
    GError ** error)
{
  int ret;
  const gchar * failed_operation;
  SundayRegs regs;
  gint i;
  gboolean success;

  ret = sunday_get_regs (pid, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "sunday_get_regs");

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  regs.r_esp -= SUNDAY_RED_ZONE_SIZE;
  regs.r_esp -= (regs.r_esp - (args_length * 4)) % SUNDAY_STACK_ALIGNMENT;

  regs.r_eip = func;

  if (args_length != 0)
  {
    guintptr * stack_args;

    stack_args = g_newa (guintptr, args_length);
    for (i = 0; i != args_length; i++)
      stack_args[i] = args[i];

    regs.r_esp -= args_length * sizeof (guintptr);
    if (!sunday_remote_write (pid, regs.r_esp, stack_args, args_length * sizeof (guintptr), error))
      goto propagate_error;
  }

  {
    guintptr dummy_return_address = SUNDAY_DUMMY_RETURN_ADDRESS;

    regs.r_esp -= 4;
    if (!sunday_remote_write (pid, regs.r_esp, &dummy_return_address, sizeof (dummy_return_address), error))
      goto propagate_error;
  }
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  regs.r_rsp -= SUNDAY_RED_ZONE_SIZE;
  regs.r_rsp -= (regs.r_rsp - (MAX (args_length - 6, 0) * 8)) % SUNDAY_STACK_ALIGNMENT;

  regs.r_rip = func;

  for (i = 0; i != args_length && i < 6; i++)
  {
    switch (i)
    {
      case 0:
        regs.r_rdi = args[i];
        break;
      case 1:
        regs.r_rsi = args[i];
        break;
      case 2:
        regs.r_rdx = args[i];
        break;
      case 3:
        regs.r_rcx = args[i];
        break;
      case 4:
        regs.r_r8 = args[i];
        break;
      case 5:
        regs.r_r9 = args[i];
        break;
      default:
        g_assert_not_reached ();
    }
  }

  {
    gint num_stack_args = args_length - 6;
    if (num_stack_args > 0)
    {
      guintptr * stack_args;

      stack_args = g_newa (guintptr, num_stack_args);
      for (i = 0; i != num_stack_args; i++)
        stack_args[i] = args[6 + i];

      regs.r_rsp -= num_stack_args * sizeof (guintptr);
      if (!sunday_remote_write (pid, regs.r_rsp, stack_args, num_stack_args * sizeof (guintptr), error))
        goto propagate_error;
    }
  }

  {
    guintptr dummy_return_address = SUNDAY_DUMMY_RETURN_ADDRESS;

    regs.r_rsp -= 8;
    if (!sunday_remote_write (pid, regs.r_rsp, &dummy_return_address, sizeof (dummy_return_address), error))
      goto propagate_error;
  }
#elif defined (HAVE_ARM64)
  regs.sp -= regs.sp % SUNDAY_STACK_ALIGNMENT;

  regs.elr = func;

  g_assert (args_length <= 8);
  for (i = 0; i != args_length; i++)
    regs.x[i] = args[i];

  regs.lr = SUNDAY_DUMMY_RETURN_ADDRESS;
#else
# error Unsupported architecture
#endif

  ret = sunday_set_regs (pid, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "sunday_set_regs");

  ret = ptrace (PT_CONTINUE, pid, GSIZE_TO_POINTER (1), 0);
  CHECK_OS_RESULT (ret, ==, 0, "PT_CONTINUE");

  success = sunday_wait_for_child_signal (pid, SIGSEGV, exited);
  CHECK_OS_RESULT (success, !=, FALSE, "PT_CONTINUE wait");

  ret = sunday_get_regs (pid, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "sunday_get_regs");

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  *retval = regs.r_eax;
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  *retval = regs.r_rax;
#elif defined (HAVE_ARM64)
  *retval = regs.x[0];
#else
# error Unsupported architecture
#endif

  return TRUE;

os_failure:
  {
    g_set_error (error,
        SUNDAY_ERROR,
        SUNDAY_ERROR_NOT_SUPPORTED,
        "remote_call %s failed: %s",
        failed_operation, g_strerror (errno));
    return FALSE;
  }
#ifdef HAVE_I386
propagate_error:
  {
    return FALSE;
  }
#endif
}

static gboolean
sunday_remote_exec (pid_t pid, GumAddress remote_address, GumAddress remote_stack, GumAddress * result, gboolean * exited, GError ** error)
{
  int ret;
  const gchar * failed_operation;
  SundayRegs regs;
  gboolean success;

  ret = sunday_get_regs (pid, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "sunday_get_regs");

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  regs.r_eip = remote_address;
  regs.r_esp = remote_stack;
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  regs.r_rip = remote_address;
  regs.r_rsp = remote_stack;
#elif defined (HAVE_ARM64)
  regs.elr = remote_address;
  regs.sp = remote_stack;
#else
# error Unsupported architecture
#endif

  ret = sunday_set_regs (pid, &regs);
  CHECK_OS_RESULT (ret, ==, 0, "sunday_set_regs");

  ret = ptrace (PT_CONTINUE, pid, GSIZE_TO_POINTER (1), 0);
  CHECK_OS_RESULT (ret, ==, 0, "PT_CONTINUE");

  success = sunday_wait_for_child_signal (pid, SIGTRAP, exited);
  CHECK_OS_RESULT (success, !=, FALSE, "PT_CONTINUE wait");

  if (result != NULL)
  {
    ret = sunday_get_regs (pid, &regs);
    CHECK_OS_RESULT (ret, ==, 0, "sunday_get_regs");

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
    *result = regs.r_eax;
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
    *result = regs.r_rax;
#elif defined (HAVE_ARM64)
    *result = regs.x[0];
#else
# error Unsupported architecture
#endif
  }

  return TRUE;

os_failure:
  {
    g_set_error (error,
        SUNDAY_ERROR,
        SUNDAY_ERROR_NOT_SUPPORTED,
        "remote_exec %s failed: %s",
        failed_operation, g_strerror (errno));
    return FALSE;
  }
}
