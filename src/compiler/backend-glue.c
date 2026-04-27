#if defined (_MSC_VER) && defined (HAVE_COMPILER_BACKEND_LINKED)

#include <glib.h>

#ifdef HAVE_ARM64
# define SUNDAY_CGO_INIT_FUNC _st0_arm64_windows_lib
#elif GLIB_SIZEOF_VOID_P == 8
# define SUNDAY_CGO_INIT_FUNC _st0_amd64_windows_lib
#else
# define SUNDAY_CGO_INIT_FUNC st0_386_windows_lib
#endif

extern void SUNDAY_CGO_INIT_FUNC ();

void
_sunday_compiler_backend_init_go_runtime (void)
{
  SUNDAY_CGO_INIT_FUNC ();
}

#else

void
_sunday_compiler_backend_init_go_runtime (void)
{
}

#endif
