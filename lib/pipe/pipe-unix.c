#include "pipe-glue.h"

#include <unistd.h>

#if defined (HAVE_ANDROID)
# define SUNDAY_TEMP_PATH "/data/local/tmp"
#else
# define SUNDAY_TEMP_PATH "/tmp"
#endif

typedef struct _SundayPipeTransportBackend SundayPipeTransportBackend;

struct _SundayPipeTransportBackend
{
  gchar * path;
};

static gchar * sunday_pipe_generate_name (void);

static gchar * temp_directory = NULL;

static const gchar *
sunday_pipe_transport_get_temp_directory (void)
{
  if (temp_directory != NULL)
    return temp_directory;
  else
    return SUNDAY_TEMP_PATH;
}

void
sunday_pipe_transport_set_temp_directory (const gchar * path)
{
  g_free (temp_directory);
  temp_directory = g_strdup (path);
}

void *
_sunday_pipe_transport_create_backend (gchar ** local_address, gchar ** remote_address, GError ** error)
{
  SundayPipeTransportBackend * backend;

  backend = g_slice_new (SundayPipeTransportBackend);
  backend->path = sunday_pipe_generate_name ();

  *local_address = g_strdup_printf ("pipe:role=server,path=%s", backend->path);
  *remote_address = g_strdup_printf ("pipe:role=client,path=%s", backend->path);

  return backend;
}

void
_sunday_pipe_transport_destroy_backend (void * opaque_backend)
{
  SundayPipeTransportBackend * backend = opaque_backend;

  unlink (backend->path);
  g_free (backend->path);

  g_slice_free (SundayPipeTransportBackend, backend);
}

static gchar *
sunday_pipe_generate_name (void)
{
  GString * s;
  guint i;

  s = g_string_new (sunday_pipe_transport_get_temp_directory ());
  g_string_append (s, "/pipe-");
  for (i = 0; i != 16; i++)
    g_string_append_printf (s, "%02x", g_random_int_range (0, 255));

  return g_string_free (s, FALSE);
}
