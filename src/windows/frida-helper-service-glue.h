#ifndef __SUNDAY_HELPER_SERVICE_GLUE_H__
#define __SUNDAY_HELPER_SERVICE_GLUE_H__

#include "frida-helper-backend.h"

G_BEGIN_DECLS

G_GNUC_INTERNAL void * sunday_helper_manager_start_services (const char * service_basename, gchar ** archs, gint archs_length,
    SundayPrivilegeLevel level);
G_GNUC_INTERNAL void sunday_helper_manager_stop_services (void * context);

G_GNUC_INTERNAL char * sunday_helper_service_derive_basename (void);
G_GNUC_INTERNAL char * sunday_helper_service_derive_filename_for_suffix (const char * suffix);
G_GNUC_INTERNAL char * sunday_helper_service_derive_svcname_for_self (void);
G_GNUC_INTERNAL char * sunday_helper_service_derive_svcname_for_suffix (const char * suffix);

G_GNUC_INTERNAL void sunday_managed_helper_service_enter_dispatcher_and_main_loop (void);

G_END_DECLS

#endif
