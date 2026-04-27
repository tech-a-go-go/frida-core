#include <dlfcn.h>
#include <stdlib.h>
#include <mach-o/loader.h>
#include <mach-o/dyld_images.h>
#include <stdbool.h>

typedef struct _SundayLibdyldApi SundayLibdyldApi;
typedef struct _SundayMachO SundayMachO;

struct _SundayLibdyldApi
{
  void * (* dlopen) (const char * path, int mode);
  void * (* dlsym) (void * handle, const char * symbol);
};

struct _SundayMachO
{
  const void * base;
  uintptr_t slide;
  const void * linkedit;
  const void * exports;
};

static void sunday_get_libdyld_api (const struct dyld_all_image_infos * all_image_info, SundayLibdyldApi * api);
static void sunday_parse_macho (const void * macho, SundayMachO * result);
static const void * sunday_find_libdyld (const struct dyld_all_image_infos * all_image_info);
static uint64_t sunday_exports_trie_find (const uint8_t * exports, const char * name);
uint64_t sunday_read_uleb128 (const uint8_t ** data);

static bool sunday_str_equals (const char * str, const char * other);

void
sunday_resolve_symbols (const char ** input_vector, void ** output_vector, const struct dyld_all_image_infos * all_image_info)
{
  SundayLibdyldApi api;
  const char ** input;
  void ** output;
  const char * module_name;

  sunday_get_libdyld_api (all_image_info, &api);

  input = input_vector;
  output = output_vector;
  while ((module_name = *input++) != NULL)
  {
    void * module;
    const char * symbol_name;

    module = api.dlopen (module_name, RTLD_LAZY | RTLD_GLOBAL);
    if (module != NULL)
    {
      while ((symbol_name = *input++) != NULL)
        *output++ = api.dlsym (module, symbol_name);
    }
    else
    {
      while (*input++ != NULL)
        *output++ = NULL;
    }
  }
}

static void
sunday_get_libdyld_api (const struct dyld_all_image_infos * all_image_info, SundayLibdyldApi * api)
{
  SundayMachO libdyld;

  sunday_parse_macho (sunday_find_libdyld (all_image_info), &libdyld);

  api->dlopen = libdyld.base + sunday_exports_trie_find (libdyld.exports, "_dlopen");
  api->dlsym = libdyld.base + sunday_exports_trie_find (libdyld.exports, "_dlsym");
}

static const void *
sunday_find_libdyld (const struct dyld_all_image_infos * all_image_info)
{
  uint32_t i;

  for (i = 0; i != all_image_info->infoArrayCount; i++)
  {
    const struct dyld_image_info * image = &all_image_info->infoArray[i];

    if (sunday_str_equals (image->imageFilePath, "/usr/lib/system/libdyld.dylib"))
    {
      return image->imageLoadAddress;
    }
  }

  return NULL;
}

static void
sunday_parse_macho (const void * macho, SundayMachO * result)
{
  const struct mach_header_64 * header;
  const struct load_command * lc;
  uint32_t i;
  const void * preferred_base;
  const void * linkedit;
  const struct dyld_info_command * dyld_info;
  const struct linkedit_data_command * exports_trie;

  header = macho;
  lc = (const struct load_command *) (header + 1);

  preferred_base = NULL;
  linkedit = NULL;
  dyld_info = NULL;
  exports_trie = NULL;

  for (i = 0; i != header->ncmds; i++)
  {
    switch (lc->cmd)
    {
      case LC_SEGMENT_64:
      {
        const struct segment_command_64 * sc = (const struct segment_command_64 *) lc;

        if (sunday_str_equals (sc->segname, "__TEXT"))
          preferred_base = (const void *) sc->vmaddr;
        else if (sunday_str_equals (sc->segname, "__LINKEDIT"))
          linkedit = (const void *) sc->vmaddr - sc->fileoff;

        break;
      }
      case LC_DYLD_INFO_ONLY:
        dyld_info = (const struct dyld_info_command *) lc;
        break;
      case LC_DYLD_EXPORTS_TRIE:
        exports_trie = (const struct linkedit_data_command *) lc;
        break;
      default:
        break;
    }

    lc = (const struct load_command *) ((uint8_t *) lc + lc->cmdsize);
  }

  result->base = macho;
  result->slide = macho - preferred_base;
  result->linkedit = linkedit + result->slide;

  if (dyld_info != NULL)
  {
    result->exports = result->linkedit + dyld_info->export_off;
  }
  else if (exports_trie != NULL)
  {
    result->exports = result->linkedit + exports_trie->dataoff;
  }
  else
  {
    result->exports = NULL;
  }
}

static uint64_t
sunday_exports_trie_find (const uint8_t * exports, const char * name)
{
  const char * s;
  const uint8_t * p;

  s = name;
  p = exports;
  while (p != NULL)
  {
    int64_t terminal_size;
    const uint8_t * children;
    uint8_t child_count, i;
    uint64_t node_offset;

    terminal_size = sunday_read_uleb128 (&p);

    if (*s == '\0' && terminal_size != 0)
    {
      /* Skip flags. */
      sunday_read_uleb128 (&p);

      /* Assume it's a plain export. */
      return sunday_read_uleb128 (&p);
    }

    children = p + terminal_size;
    child_count = *children++;
    p = children;
    node_offset = 0;
    for (i = 0; i != child_count; i++)
    {
      const char * symbol_cur;
      bool matching_edge;

      symbol_cur = s;
      matching_edge = true;
      while (*p != '\0')
      {
        if (matching_edge)
        {
          if (*p != *symbol_cur)
            matching_edge = false;
          symbol_cur++;
        }
        p++;
      }
      p++;

      if (matching_edge)
      {
        node_offset = sunday_read_uleb128 (&p);
        s = symbol_cur;
        break;
      }
      else
      {
        sunday_read_uleb128 (&p);
      }
    }

    if (node_offset != 0)
      p = exports + node_offset;
    else
      p = NULL;
  }

  return 0;
}

uint64_t
sunday_read_uleb128 (const uint8_t ** data)
{
  const uint8_t * p = *data;
  uint64_t result = 0;
  int offset = 0;

  do
  {
    uint64_t chunk;

    chunk = *p & 0x7f;
    result |= (chunk << offset);
    offset += 7;
  }
  while (*p++ & 0x80);

  *data = p;

  return result;
}

static bool
sunday_str_equals (const char * str, const char * other)
{
  char a, b;

  do
  {
    a = *str;
    b = *other;
    if (a != b)
      return false;
    str++;
    other++;
  }
  while (a != '\0');

  return true;
}

#ifdef BUILDING_TEST_PROGRAM

#include <assert.h>
#include <stdio.h>
#include <mach/mach.h>

int
main (void)
{
  mach_port_t task;
  struct task_dyld_info info;
  mach_msg_type_number_t count;
  kern_return_t kr;
  const struct dyld_all_image_infos * dyld_info;
  const char * input_vector[] = {
    "/usr/lib/libSystem.B.dylib",
    "open",
    "close",
    NULL,
    "/usr/lib/libresolv.dylib",
    "res_9_init",
    NULL,
    NULL
  };
  void * output_vector[3];

  task = mach_task_self ();

  count = TASK_DYLD_INFO_COUNT;
  kr = task_info (task, TASK_DYLD_INFO, (task_info_t) &info, &count);
  assert (kr == KERN_SUCCESS);

  dyld_info = (const struct dyld_all_image_infos *) info.all_image_info_addr;

  sunday_resolve_symbols (input_vector, output_vector, dyld_info);

  printf ("open=%p, correct=%p\n", output_vector[0], dlsym (RTLD_DEFAULT, "open"));
  printf ("close=%p, correct=%p\n", output_vector[1], dlsym (RTLD_DEFAULT, "close"));
  printf ("res_9_init=%p, correct=%p\n", output_vector[2], dlsym (RTLD_DEFAULT, "res_9_init"));

  return 0;
}

#endif
