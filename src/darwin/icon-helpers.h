#ifndef __SUNDAY_DARWIN_ICON_HELPERS_H__
#define __SUNDAY_DARWIN_ICON_HELPERS_H__

#include "frida-core.h"

typedef gpointer SundayNativeImage;

GVariant * _sunday_icon_from_file (const gchar * filename, guint target_width, guint target_height);
GVariant * _sunday_icon_from_native_image_scaled_to (SundayNativeImage native_image, guint target_width, guint target_height);

#endif
