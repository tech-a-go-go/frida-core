#include "frida-core.h"

#include <gum/gum.h>
#if defined (HAVE_GIOAPPLE)
# include <gioapple.h>
#elif defined (HAVE_GIOOPENSSL)
# include <gioopenssl.h>
#endif

static SundayRuntime runtime;
static GThread * main_thread;
static GMainLoop * main_loop;
static GMainContext * main_context;

#ifndef HAVE_EMBEDDED_ASSETS
extern void _sunday_init_asset_paths (void);
extern void _sunday_deinit_asset_paths (void);
#endif

static gpointer run_main_loop (gpointer data);
static gboolean dummy_callback (gpointer data);
static gboolean stop_main_loop (gpointer data);

void
sunday_init (void)
{
  sunday_init_with_runtime (SUNDAY_RUNTIME_OTHER);
}

void
sunday_init_with_runtime (SundayRuntime rt)
{
  static gsize sunday_initialized = FALSE;

#ifdef HAVE_FRIDA_GLIB
  g_thread_set_garbage_handler (sunday_on_pending_garbage, NULL);
  glib_init ();
#endif

  if (g_once_init_enter (&sunday_initialized))
  {
    runtime = rt;

#ifdef HAVE_FRIDA_GLIB
    gio_init ();
#endif
    gum_init ();
#ifndef HAVE_EMBEDDED_ASSETS
    _sunday_init_asset_paths ();
#endif
    sunday_error_quark (); /* Initialize early so GDBus will pick it up */

#if defined (HAVE_GIOAPPLE)
    g_io_module_apple_register ();
#elif defined (HAVE_GIOOPENSSL)
    g_io_module_openssl_register ();
#endif

    if (runtime == SUNDAY_RUNTIME_OTHER)
    {
      main_context = g_main_context_ref (g_main_context_default ());
      main_loop = g_main_loop_new (main_context, FALSE);
      main_thread = g_thread_new ("frida-main-loop", run_main_loop, NULL);
    }

    g_once_init_leave (&sunday_initialized, TRUE);
  }
}

void
sunday_unref (gpointer obj)
{
  if (runtime == SUNDAY_RUNTIME_GLIB)
  {
    g_object_unref (obj);
  }
  else if (runtime == SUNDAY_RUNTIME_OTHER)
  {
    GSource * source;

    source = g_idle_source_new ();
    g_source_set_priority (source, G_PRIORITY_HIGH);
    g_source_set_callback (source, dummy_callback, obj, g_object_unref);
    g_source_attach (source, main_context);
    g_source_unref (source);
  }
}

void
sunday_shutdown (void)
{
  if (runtime == SUNDAY_RUNTIME_OTHER)
  {
    GSource * source;

    g_assert (main_loop != NULL);

    source = g_idle_source_new ();
    g_source_set_priority (source, G_PRIORITY_LOW);
    g_source_set_callback (source, stop_main_loop, NULL, NULL);
    g_source_attach (source, main_context);
    g_source_unref (source);

    g_thread_join (main_thread);
    main_thread = NULL;
  }
}

void
sunday_deinit (void)
{
  if (runtime == SUNDAY_RUNTIME_OTHER)
  {
    g_assert (main_loop != NULL);

    if (main_thread != NULL)
      sunday_shutdown ();

    g_main_loop_unref (main_loop);
    main_loop = NULL;
    g_main_context_unref (main_context);
    main_context = NULL;
  }

  sunday_invalidate_dbus_context ();

  gum_shutdown ();
#ifdef HAVE_FRIDA_GLIB
  gio_shutdown ();
  glib_shutdown ();
#endif

#ifndef HAVE_EMBEDDED_ASSETS
  _sunday_deinit_asset_paths ();
#endif

  gum_deinit ();
#ifdef HAVE_FRIDA_GLIB
  gio_deinit ();
  glib_deinit ();
#endif
}

GMainContext *
sunday_get_main_context (void)
{
  if (runtime == SUNDAY_RUNTIME_GLIB)
    return g_main_context_get_thread_default ();
  else if (runtime == SUNDAY_RUNTIME_OTHER)
    return main_context;
  else
    g_assert_not_reached ();
}

void
sunday_version (guint * major, guint * minor, guint * micro, guint * nano)
{
  if (major != NULL)
    *major = FRIDA_MAJOR_VERSION;

  if (minor != NULL)
    *minor = FRIDA_MINOR_VERSION;

  if (micro != NULL)
    *micro = FRIDA_MICRO_VERSION;

  if (nano != NULL)
    *nano = FRIDA_NANO_VERSION;
}

const gchar *
sunday_version_string (void)
{
  return FRIDA_VERSION;
}

static gpointer
run_main_loop (gpointer data)
{
  (void) data;

  g_main_context_push_thread_default (main_context);
  g_main_loop_run (main_loop);
  g_main_context_pop_thread_default (main_context);

  return NULL;
}

static gboolean
dummy_callback (gpointer data)
{
  (void) data;

  return FALSE;
}

static gboolean
stop_main_loop (gpointer data)
{
  (void) data;

  g_main_loop_quit (main_loop);

  return FALSE;
}
