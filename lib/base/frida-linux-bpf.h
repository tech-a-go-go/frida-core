#ifndef __SUNDAY_LINUX_BPF_H__
#define __SUNDAY_LINUX_BPF_H__

#include <glib.h>

G_BEGIN_DECLS

#define SUNDAY_BPF_RINGBUF_HEADER_SIZE 8

typedef guint32 SundayBpfRingbufFlags;

enum _SundayBpfRingbufFlags
{
  SUNDAY_BPF_RINGBUF_BUSY    = (1U << 31),
  SUNDAY_BPF_RINGBUF_DISCARD = (1U << 30),
};

G_END_DECLS

#endif
