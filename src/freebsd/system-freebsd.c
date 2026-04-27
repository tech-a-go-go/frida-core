#include "frida-core.h"

#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/user.h>

typedef struct _SundayEnumerateProcessesOperation SundayEnumerateProcessesOperation;

struct _SundayEnumerateProcessesOperation
{
  SundayScope scope;

  GArray * result;
};

static void sunday_collect_process_info_from_pid (guint pid, SundayEnumerateProcessesOperation * op);
static void sunday_collect_process_info_from_kinfo (struct kinfo_proc * process, SundayEnumerateProcessesOperation * op);

static void sunday_add_process_metadata (GHashTable * parameters, const struct kinfo_proc * process);

static struct kinfo_proc * sunday_system_query_kinfo_procs (guint * count);
static gboolean sunday_system_query_proc_pathname (pid_t pid, gchar * path, gsize size);
static GVariant * sunday_uid_to_name (uid_t uid);

void
sunday_system_get_frontmost_application (SundayFrontmostQueryOptions * options, SundayHostApplicationInfo * result, GError ** error)
{
  g_set_error (error,
      SUNDAY_ERROR,
      SUNDAY_ERROR_NOT_SUPPORTED,
      "Not implemented");
}

SundayHostApplicationInfo *
sunday_system_enumerate_applications (SundayApplicationQueryOptions * options, int * result_length)
{
  *result_length = 0;

  return NULL;
}

SundayHostProcessInfo *
sunday_system_enumerate_processes (SundayProcessQueryOptions * options, int * result_length)
{
  SundayEnumerateProcessesOperation op;

  op.scope = sunday_process_query_options_get_scope (options);

  op.result = g_array_new (FALSE, FALSE, sizeof (SundayHostProcessInfo));

  if (sunday_process_query_options_has_selected_pids (options))
  {
    sunday_process_query_options_enumerate_selected_pids (options, (GFunc) sunday_collect_process_info_from_pid, &op);
  }
  else
  {
    struct kinfo_proc * processes;
    guint count, i;

    processes = sunday_system_query_kinfo_procs (&count);

    for (i = 0; i != count; i++)
      sunday_collect_process_info_from_kinfo (&processes[i], &op);

    g_free (processes);
  }

  *result_length = op.result->len;

  return (SundayHostProcessInfo *) g_array_free (op.result, FALSE);
}

static void
sunday_collect_process_info_from_pid (guint pid, SundayEnumerateProcessesOperation * op)
{
  struct kinfo_proc process;
  size_t size;
  int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
  gint err G_GNUC_UNUSED;

  size = sizeof (process);

  err = sysctl (mib, G_N_ELEMENTS (mib), &process, &size, NULL, 0);
  g_assert (err != -1);

  if (size == 0)
    return;

  sunday_collect_process_info_from_kinfo (&process, op);
}

static void
sunday_collect_process_info_from_kinfo (struct kinfo_proc * process, SundayEnumerateProcessesOperation * op)
{
  SundayHostProcessInfo info = { 0, };
  SundayScope scope = op->scope;
  gboolean still_alive;
  gchar path[PATH_MAX];

  info.pid = process->ki_pid;

  info.parameters = sunday_make_parameters_dict ();

  if (scope != SUNDAY_SCOPE_MINIMAL)
    sunday_add_process_metadata (info.parameters, process);

  still_alive = sunday_system_query_proc_pathname (info.pid, path, sizeof (path));
  if (still_alive)
  {
    if (path[0] != '\0')
      info.name = g_path_get_basename (path);
    else
      info.name = g_strdup (process->ki_comm);

    if (scope != SUNDAY_SCOPE_MINIMAL)
      g_hash_table_insert (info.parameters, g_strdup ("path"), g_variant_ref_sink (g_variant_new_string (path)));
  }

  if (still_alive)
    g_array_append_val (op->result, info);
  else
    sunday_host_process_info_destroy (&info);
}

void
sunday_system_kill (guint pid)
{
  kill (pid, SIGKILL);
}

gchar *
sunday_temporary_directory_get_system_tmp (void)
{
  return g_strdup (g_get_tmp_dir ());
}

static void
sunday_add_process_metadata (GHashTable * parameters, const struct kinfo_proc * process)
{
  const struct timeval * started = &process->ki_start;
  GDateTime * t0, * t1;

  g_hash_table_insert (parameters, g_strdup ("user"), sunday_uid_to_name (process->ki_uid));

  g_hash_table_insert (parameters, g_strdup ("ppid"), g_variant_ref_sink (g_variant_new_int64 (process->ki_ppid)));

  t0 = g_date_time_new_from_unix_utc (started->tv_sec);
  t1 = g_date_time_add (t0, started->tv_usec);
  g_hash_table_insert (parameters, g_strdup ("started"), g_variant_ref_sink (g_variant_new_take_string (g_date_time_format_iso8601 (t1))));
  g_date_time_unref (t1);
  g_date_time_unref (t0);
}

static struct kinfo_proc *
sunday_system_query_kinfo_procs (guint * count)
{
  gboolean success = FALSE;
  int mib[3];
  struct kinfo_proc * processes = NULL;
  size_t size;

  mib[0] = CTL_KERN;
  mib[1] = KERN_PROC;
  mib[2] = KERN_PROC_PROC;

  size = 0;
  if (sysctl (mib, G_N_ELEMENTS (mib), NULL, &size, NULL, 0) != 0)
    goto beach;

  while (TRUE)
  {
    size_t previous_size;
    gboolean still_too_small;

    processes = g_realloc (processes, size);

    previous_size = size;
    if (sysctl (mib, G_N_ELEMENTS (mib), processes, &size, NULL, 0) == 0)
      break;

    still_too_small = errno == ENOMEM && size == previous_size;
    if (!still_too_small)
      goto beach;

    size += size / 10;
  }

  *count = size / sizeof (struct kinfo_proc);

  success = TRUE;

beach:
  if (!success)
    g_clear_pointer (&processes, g_free);

  return processes;
}

static gboolean
sunday_system_query_proc_pathname (pid_t pid, gchar * path, gsize size)
{
  gboolean success;
  int mib[4];
  size_t n;

  mib[0] = CTL_KERN;
  mib[1] = KERN_PROC;
  mib[2] = KERN_PROC_PATHNAME;
  mib[3] = pid;

  n = size;

  success = sysctl (mib, G_N_ELEMENTS (mib), path, &n, NULL, 0) == 0;

  if (n == 0)
    path[0] = '\0';

  return success;
}

static GVariant *
sunday_uid_to_name (uid_t uid)
{
  GVariant * name;
  static size_t cached_buffer_size = 0;
  char * buffer;
  size_t size;
  struct passwd pwd, * entry;
  int error;

  if (cached_buffer_size == 0)
  {
    long n = sysconf (_SC_GETPW_R_SIZE_MAX);
    if (n > 0)
      cached_buffer_size = n;
  }

  size = (cached_buffer_size != 0) ? cached_buffer_size : 128;
  buffer = g_malloc (size);
  entry = NULL;

  while ((error = getpwuid_r (uid, &pwd, buffer, size, &entry)) == ERANGE)
  {
    size *= 2;
    buffer = g_realloc (buffer, size);
  }

  if (error == 0 && size > cached_buffer_size)
    cached_buffer_size = size;

  if (entry != NULL)
    name = g_variant_new_string (entry->pw_name);
  else
    name = g_variant_new_take_string (g_strdup_printf ("%u", uid));
  name = g_variant_ref_sink (name);

  g_free (buffer);

  return name;
}
