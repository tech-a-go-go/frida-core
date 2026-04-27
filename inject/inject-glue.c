#include "inject-glue.h"

#include "frida-core.h"
#ifdef HAVE_ANDROID
# include "frida-selinux.h"
#endif

void
sunday_inject_environment_init (void)
{
  sunday_init_with_runtime (SUNDAY_RUNTIME_GLIB);

#ifdef HAVE_ANDROID
  sunday_selinux_patch_policy ();
#endif
}
