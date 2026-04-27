#include "upload-api.h"

#include <ptrauth.h>
#include <stdbool.h>
#include <stdint.h>
#include <mach-o/loader.h>

#define SUNDAY_INT2_MASK  0x00000003U
#define SUNDAY_INT11_MASK 0x000007ffU
#define SUNDAY_INT16_MASK 0x0000ffffU
#define SUNDAY_INT32_MASK 0xffffffffU

typedef uint8_t SundayUploadCommandType;
typedef uint8_t SundayDarwinThreadedItemType;

typedef void (* SundayConstructorFunc) (int argc, const char * argv[], const char * env[], const char * apple[], int * result);

typedef struct _SundayChainedFixupsHeader SundayChainedFixupsHeader;

typedef struct _SundayChainedStartsInImage SundayChainedStartsInImage;
typedef struct _SundayChainedStartsInSegment SundayChainedStartsInSegment;
typedef uint16_t SundayChainedPtrFormat;

typedef struct _SundayChainedPtr64Rebase SundayChainedPtr64Rebase;
typedef struct _SundayChainedPtr64Bind SundayChainedPtr64Bind;
typedef struct _SundayChainedPtrArm64eRebase SundayChainedPtrArm64eRebase;
typedef struct _SundayChainedPtrArm64eBind SundayChainedPtrArm64eBind;
typedef struct _SundayChainedPtrArm64eBind24 SundayChainedPtrArm64eBind24;
typedef struct _SundayChainedPtrArm64eAuthRebase SundayChainedPtrArm64eAuthRebase;
typedef struct _SundayChainedPtrArm64eAuthBind SundayChainedPtrArm64eAuthBind;
typedef struct _SundayChainedPtrArm64eAuthBind24 SundayChainedPtrArm64eAuthBind24;

typedef uint32_t SundayChainedImportFormat;
typedef uint32_t SundayChainedSymbolFormat;

typedef struct _SundayChainedImport SundayChainedImport;
typedef struct _SundayChainedImportAddend SundayChainedImportAddend;
typedef struct _SundayChainedImportAddend64 SundayChainedImportAddend64;

enum _SundayUploadCommandType
{
  SUNDAY_UPLOAD_COMMAND_WRITE = 1,
  SUNDAY_UPLOAD_COMMAND_APPLY_THREADED,
  SUNDAY_UPLOAD_COMMAND_PROCESS_FIXUPS,
  SUNDAY_UPLOAD_COMMAND_PROTECT,
  SUNDAY_UPLOAD_COMMAND_CONSTRUCT_FROM_POINTERS,
  SUNDAY_UPLOAD_COMMAND_CONSTRUCT_FROM_OFFSETS,
  SUNDAY_UPLOAD_COMMAND_CHECK,
};

enum _SundayDarwinThreadedItemType
{
  SUNDAY_DARWIN_THREADED_REBASE,
  SUNDAY_DARWIN_THREADED_BIND
};

struct _SundayChainedFixupsHeader
{
  uint32_t fixups_version;
  uint32_t starts_offset;
  uint32_t imports_offset;
  uint32_t symbols_offset;
  uint32_t imports_count;
  SundayChainedImportFormat imports_format;
  SundayChainedSymbolFormat symbols_format;
};

struct _SundayChainedStartsInImage
{
  uint32_t seg_count;
  uint32_t seg_info_offset[1];
};

struct _SundayChainedStartsInSegment
{
  uint32_t size;
  uint16_t page_size;
  SundayChainedPtrFormat pointer_format;
  uint64_t segment_offset;
  uint32_t max_valid_pointer;
  uint16_t page_count;
  uint16_t page_start[1];
};

enum _SundayChainedPtrStart
{
  SUNDAY_CHAINED_PTR_START_NONE  = 0xffff,
  SUNDAY_CHAINED_PTR_START_MULTI = 0x8000,
  SUNDAY_CHAINED_PTR_START_LAST  = 0x8000,
};

enum _SundayChainedPtrFormat
{
  SUNDAY_CHAINED_PTR_ARM64E              =  1,
  SUNDAY_CHAINED_PTR_64                  =  2,
  SUNDAY_CHAINED_PTR_32                  =  3,
  SUNDAY_CHAINED_PTR_32_CACHE            =  4,
  SUNDAY_CHAINED_PTR_32_FIRMWARE         =  5,
  SUNDAY_CHAINED_PTR_64_OFFSET           =  6,
  SUNDAY_CHAINED_PTR_ARM64E_OFFSET       =  7,
  SUNDAY_CHAINED_PTR_ARM64E_KERNEL       =  7,
  SUNDAY_CHAINED_PTR_64_KERNEL_CACHE     =  8,
  SUNDAY_CHAINED_PTR_ARM64E_USERLAND     =  9,
  SUNDAY_CHAINED_PTR_ARM64E_FIRMWARE     = 10,
  SUNDAY_CHAINED_PTR_X86_64_KERNEL_CACHE = 11,
  SUNDAY_CHAINED_PTR_ARM64E_USERLAND24   = 12,
};

struct _SundayChainedPtr64Rebase
{
  uint64_t target   : 36,
           high8    :  8,
           reserved :  7,
           next     : 12,
           bind     :  1;
};

struct _SundayChainedPtr64Bind
{
  uint64_t ordinal  : 24,
           addend   :  8,
           reserved : 19,
           next     : 12,
           bind     :  1;
};

struct _SundayChainedPtrArm64eRebase
{
  uint64_t target : 43,
           high8  :  8,
           next   : 11,
           bind   :  1,
           auth   :  1;
};

struct _SundayChainedPtrArm64eBind
{
  uint64_t ordinal : 16,
           zero    : 16,
           addend  : 19,
           next    : 11,
           bind    :  1,
           auth    :  1;
};

struct _SundayChainedPtrArm64eBind24
{
  uint64_t ordinal : 24,
           zero    :  8,
           addend  : 19,
           next    : 11,
           bind    :  1,
           auth    :  1;
};

struct _SundayChainedPtrArm64eAuthRebase
{
  uint64_t target    : 32,
           diversity : 16,
           addr_div  :  1,
           key       :  2,
           next      : 11,
           bind      :  1,
           auth      :  1;
};

struct _SundayChainedPtrArm64eAuthBind
{
  uint64_t ordinal   : 16,
           zero      : 16,
           diversity : 16,
           addr_div  :  1,
           key       :  2,
           next      : 11,
           bind      :  1,
           auth      :  1;
};

struct _SundayChainedPtrArm64eAuthBind24
{
  uint64_t ordinal   : 24,
           zero      :  8,
           diversity : 16,
           addr_div  :  1,
           key       :  2,
           next      : 11,
           bind      :  1,
           auth      :  1;
};

enum _SundayChainedImportFormat
{
  SUNDAY_CHAINED_IMPORT          = 1,
  SUNDAY_CHAINED_IMPORT_ADDEND   = 2,
  SUNDAY_CHAINED_IMPORT_ADDEND64 = 3,
};

enum _SundayChainedSymbolFormat
{
  SUNDAY_CHAINED_SYMBOL_UNCOMPRESSED,
  SUNDAY_CHAINED_SYMBOL_ZLIB_COMPRESSED,
};

struct _SundayChainedImport
{
  uint32_t lib_ordinal :  8,
           weak_import :  1,
           name_offset : 23;
};

struct _SundayChainedImportAddend
{
  uint32_t lib_ordinal :  8,
           weak_import :  1,
           name_offset : 23;
  int32_t  addend;
};

struct _SundayChainedImportAddend64
{
  uint64_t lib_ordinal : 16,
           weak_import :  1,
           reserved    : 15,
           name_offset : 32;
  uint64_t addend;
};

#define SUNDAY_TEMP_FAILURE_RETRY(expression) \
  ({ \
    ssize_t __result; \
    \
    do __result = expression; \
    while (__result == -1 && *(api->get_errno_storage ()) == EINTR); \
    \
    __result; \
  })

static void sunday_apply_threaded_items (uint64_t preferred_base_address, uint64_t slide, uint16_t num_symbols, const uint64_t * symbols,
    uint16_t num_regions, uint64_t * regions);

static void sunday_process_chained_fixups (const SundayChainedFixupsHeader * fixups_header, struct mach_header_64 * mach_header,
    size_t preferred_base_address, const SundayUploadApi * api);
static void sunday_process_chained_fixups_in_segment_generic64 (void * cursor, SundayChainedPtrFormat format, uint64_t actual_base_address,
    uint64_t preferred_base_address, void ** bound_pointers);
static void sunday_process_chained_fixups_in_segment_arm64e (void * cursor, SundayChainedPtrFormat format, uint64_t actual_base_address,
    uint64_t preferred_base_address, void ** bound_pointers);
static void * sunday_resolve_import (void ** dylib_handles, int dylib_ordinal, const char * symbol_strings, uint32_t symbol_offset,
    const SundayUploadApi * api);

static void * sunday_sign_pointer (void * ptr, uint8_t key, uintptr_t diversity, bool use_address_diversity, void * address_of_ptr);
static const char * sunday_symbol_name_from_darwin (const char * name);
static int64_t sunday_sign_extend_int19 (uint64_t i19);

static bool sunday_read_chunk (int fd, void * buffer, size_t length, size_t * bytes_read, const SundayUploadApi * api);
static bool sunday_write_chunk (int fd, const void * buffer, size_t length, size_t * bytes_written, const SundayUploadApi * api);

int64_t
sunday_receive (int listener_fd, uint64_t session_id_top, uint64_t session_id_bottom, const char * apple[], const SundayUploadApi * api)
{
  int result = 0;
  mach_port_t task;
  bool expecting_client;
  int res;
  struct sockaddr_in addr;
  socklen_t addr_len;
  int client_fd;
  uint32_t ACK_MAGIC = 0xac4ac4ac;

  task = api->_mach_task_self ();

  expecting_client = true;

  do
  {
    uint64_t client_sid[2];

    addr_len = sizeof (addr);

    res = SUNDAY_TEMP_FAILURE_RETRY (api->accept (listener_fd, (struct sockaddr *) &addr, &addr_len));
    if (res == -1)
      goto beach;
    client_fd = res;

    #define SUNDAY_READ_VALUE(v) \
        if (!sunday_read_chunk (client_fd, &(v), sizeof (v), NULL, api)) \
          goto next_client

    #define SUNDAY_WRITE_VALUE(v) \
        if (!sunday_write_chunk (client_fd, &(v), sizeof (v), NULL, api)) \
          goto next_client

    SUNDAY_READ_VALUE (client_sid);
    if (client_sid[0] != session_id_top || client_sid[1] != session_id_bottom)
      goto next_client;

    expecting_client = false;

    SUNDAY_WRITE_VALUE (ACK_MAGIC);

    while (true)
    {
      bool success = false;
      SundayUploadCommandType command_type;

      SUNDAY_READ_VALUE (command_type);

      switch (command_type)
      {
        case SUNDAY_UPLOAD_COMMAND_WRITE:
        {
          uint64_t address;
          uint32_t size;
          vm_address_t writable_address;
          vm_prot_t cur_prot, max_prot;
          size_t n;

          SUNDAY_READ_VALUE (address);
          SUNDAY_READ_VALUE (size);

          writable_address = 0;
          success = api->vm_remap (task, &writable_address, size, 0, VM_FLAGS_ANYWHERE, task, address, FALSE, &cur_prot, &max_prot,
              VM_INHERIT_NONE) == 0;
          if (!success)
            break;

          success = api->mprotect ((void *) writable_address, size, VM_PROT_READ | VM_PROT_WRITE) == 0;
          if (!success)
            goto unmap_writable;

          success = sunday_read_chunk (client_fd, (void *) writable_address, size, &n, api);
          if (!success)
            goto unmap_writable;

          api->sys_icache_invalidate ((void *) address, n);
          api->sys_dcache_flush ((void *) address, n);

unmap_writable:
          api->mach_vm_deallocate (task, writable_address, size);

          break;
        }
        case SUNDAY_UPLOAD_COMMAND_APPLY_THREADED:
        {
          uint64_t preferred_base_address, slide;
          uint16_t num_symbols, num_regions;

          SUNDAY_READ_VALUE (preferred_base_address);
          SUNDAY_READ_VALUE (slide);

          SUNDAY_READ_VALUE (num_symbols);
          uint64_t symbols[num_symbols];
          if (!sunday_read_chunk (client_fd, symbols, num_symbols * sizeof (uint64_t), NULL, api))
            goto next_client;

          SUNDAY_READ_VALUE (num_regions);
          uint64_t regions[num_regions];
          if (!sunday_read_chunk (client_fd, regions, num_regions * sizeof (uint64_t), NULL, api))
            goto next_client;

          sunday_apply_threaded_items (preferred_base_address, slide, num_symbols, symbols, num_regions, regions);

          success = true;

          break;
        }
        case SUNDAY_UPLOAD_COMMAND_PROCESS_FIXUPS:
        {
          uint64_t fixups_header_address, mach_header_address, preferred_base_address;

          SUNDAY_READ_VALUE (fixups_header_address);
          SUNDAY_READ_VALUE (mach_header_address);
          SUNDAY_READ_VALUE (preferred_base_address);

          sunday_process_chained_fixups ((const SundayChainedFixupsHeader *) fixups_header_address,
              (struct mach_header_64 *) mach_header_address, (size_t) preferred_base_address, api);

          success = true;

          break;
        }
        case SUNDAY_UPLOAD_COMMAND_PROTECT:
        {
          uint64_t address;
          uint32_t size;
          int32_t prot;

          SUNDAY_READ_VALUE (address);
          SUNDAY_READ_VALUE (size);
          SUNDAY_READ_VALUE (prot);

          success = api->mprotect ((void *) address, size, prot) == 0;

          break;
        }
        case SUNDAY_UPLOAD_COMMAND_CONSTRUCT_FROM_POINTERS:
        {
          uint64_t address;
          uint32_t count;
          SundayConstructorFunc * constructors;
          uint32_t i;

          SUNDAY_READ_VALUE (address);
          SUNDAY_READ_VALUE (count);

          constructors = (SundayConstructorFunc *) address;

          for (i = 0; i != count; i++)
          {
            const int argc = 0;
            const char * argv[] = { NULL };
            const char * env[] = { NULL };

            constructors[i] (argc, argv, env, apple, &result);
          }

          success = true;

          break;
        }
        case SUNDAY_UPLOAD_COMMAND_CONSTRUCT_FROM_OFFSETS:
        {
          uint64_t address;
          uint32_t count;
          uint64_t mach_header_address;
          uint32_t * constructor_offsets;
          uint32_t i;

          SUNDAY_READ_VALUE (address);
          SUNDAY_READ_VALUE (count);
          SUNDAY_READ_VALUE (mach_header_address);

          constructor_offsets = (uint32_t *) address;

          for (i = 0; i != count; i++)
          {
            SundayConstructorFunc constructor;
            const int argc = 0;
            const char * argv[] = { NULL };
            const char * env[] = { NULL };

            constructor = (SundayConstructorFunc) (mach_header_address + constructor_offsets[i]);

            constructor (argc, argv, env, apple, &result);
          }

          success = true;

          break;
        }
        case SUNDAY_UPLOAD_COMMAND_CHECK:
        {
          SUNDAY_WRITE_VALUE (ACK_MAGIC);

          success = true;

          break;
        }
      }

      if (!success)
        goto next_client;
    }

next_client:
    api->close (client_fd);
  }
  while (expecting_client);

beach:
  api->close (listener_fd);

#ifndef BUILDING_TEST_PROGRAM
  asm volatile (
      "mov x0, %0\n\t"
      "mov x1, #1337\n\t"
      "mov x2, #1337\n\t"
      "mov x3, #0\n\t"
      "brk #1337\n\t"
      :
      : "r" ((uint64_t) result)
      : "x0", "x1", "x2", "x3"
  );
#endif

  return result;
}

static void
sunday_apply_threaded_items (uint64_t preferred_base_address, uint64_t slide, uint16_t num_symbols, const uint64_t * symbols,
    uint16_t num_regions, uint64_t * regions)
{
  uint16_t i;

  for (i = 0; i != num_regions; i++)
  {
    uint64_t * slot = (uint64_t *) regions[i];
    uint16_t delta;

    do
    {
      uint64_t value;
      bool is_authenticated;
      SundayDarwinThreadedItemType type;
      uint8_t key;
      bool has_address_diversity;
      uint16_t diversity;
      uint64_t bound_value;

      value = *slot;

      is_authenticated      = (value >> 63) & 1;
      type                  = (value >> 62) & 1;
      delta                 = (value >> 51) & SUNDAY_INT11_MASK;
      key                   = (value >> 49) & SUNDAY_INT2_MASK;
      has_address_diversity = (value >> 48) & 1;
      diversity             = (value >> 32) & SUNDAY_INT16_MASK;

      if (type == SUNDAY_DARWIN_THREADED_BIND)
      {
        uint16_t bind_ordinal;

        bind_ordinal = value & SUNDAY_INT16_MASK;

        bound_value = symbols[bind_ordinal];
      }
      else if (type == SUNDAY_DARWIN_THREADED_REBASE)
      {
        uint64_t rebase_address;

        if (is_authenticated)
        {
          rebase_address = value & SUNDAY_INT32_MASK;
        }
        else
        {
          uint64_t top_8_bits, bottom_43_bits, sign_bits;
          bool sign_bit_set;

          top_8_bits = (value << 13) & 0xff00000000000000UL;
          bottom_43_bits = value     & 0x000007ffffffffffUL;

          sign_bit_set = (value >> 42) & 1;
          if (sign_bit_set)
            sign_bits = 0x00fff80000000000UL;
          else
            sign_bits = 0;

          rebase_address = top_8_bits | sign_bits | bottom_43_bits;
        }

        bound_value = rebase_address;

        if (is_authenticated)
          bound_value += preferred_base_address;

        bound_value += slide;
      }

      if (is_authenticated)
      {
        *slot = (uint64_t) sunday_sign_pointer ((void *) bound_value, key, diversity, has_address_diversity, slot);
      }
      else
      {
        *slot = bound_value;
      }

      slot += delta;
    }
    while (delta != 0);
  }
}

static void
sunday_process_chained_fixups (const SundayChainedFixupsHeader * fixups_header, struct mach_header_64 * mach_header,
    size_t preferred_base_address, const SundayUploadApi * api)
{
  mach_port_t task;
  mach_vm_address_t slab_start;
  size_t slab_size;
  void * slab_cursor;
  void ** dylib_handles;
  size_t dylib_count;
  const void * command;
  uint32_t command_index;
  void ** bound_pointers;
  size_t bound_count, i;
  const char * symbols;
  const SundayChainedStartsInImage * image_starts;
  uint32_t seg_index;

  task = api->_mach_task_self ();

  slab_start = 0;
  slab_size = 64 * 1024;
  api->mach_vm_allocate (task, &slab_start, slab_size, VM_FLAGS_ANYWHERE);
  slab_cursor = (void *) slab_start;

  dylib_handles = slab_cursor;
  dylib_count = 0;

  command = mach_header + 1;
  for (command_index = 0; command_index != mach_header->ncmds; command_index++)
  {
    const struct load_command * lc = command;

    switch (lc->cmd)
    {
      case LC_LOAD_DYLIB:
      case LC_LOAD_WEAK_DYLIB:
      case LC_REEXPORT_DYLIB:
      case LC_LOAD_UPWARD_DYLIB:
      {
        const struct dylib_command * dc = command;
        const char * name = command + dc->dylib.name.offset;

        dylib_handles[dylib_count++] = api->dlopen (name, RTLD_LAZY | RTLD_GLOBAL);

        break;
      }
      default:
        break;
    }

    command += lc->cmdsize;
  }

  slab_cursor += dylib_count * sizeof (void *);

  bound_pointers = slab_cursor;
  bound_count = fixups_header->imports_count;
  slab_cursor += bound_count * sizeof (void *);

  symbols = (const char *) fixups_header + fixups_header->symbols_offset;

  switch (fixups_header->imports_format)
  {
    case SUNDAY_CHAINED_IMPORT:
    {
      const SundayChainedImport * imports = ((const void *) fixups_header + fixups_header->imports_offset);

      for (i = 0; i != bound_count; i++)
      {
        const SundayChainedImport * import = &imports[i];

        bound_pointers[i] = sunday_resolve_import (dylib_handles,
            import->lib_ordinal, symbols, import->name_offset, api);
      }

      break;
    }
    case SUNDAY_CHAINED_IMPORT_ADDEND:
    {
      const SundayChainedImportAddend * imports = ((const void *) fixups_header + fixups_header->imports_offset);

      for (i = 0; i != bound_count; i++)
      {
        const SundayChainedImportAddend * import = &imports[i];

        bound_pointers[i] = sunday_resolve_import (dylib_handles,
            import->lib_ordinal, symbols, import->name_offset, api);
        bound_pointers[i] += import->addend;
      }

      break;
    }
    case SUNDAY_CHAINED_IMPORT_ADDEND64:
    {
      const SundayChainedImportAddend64 * imports = ((const void *) fixups_header + fixups_header->imports_offset);

      for (i = 0; i != bound_count; i++)
      {
        const SundayChainedImportAddend64 * import = &imports[i];

        bound_pointers[i] = sunday_resolve_import (dylib_handles,
            import->lib_ordinal, symbols, import->name_offset, api);
        bound_pointers[i] += import->addend;
      }

      break;
    }
  }

  image_starts = (const SundayChainedStartsInImage *) ((const void *) fixups_header + fixups_header->starts_offset);

  for (seg_index = 0; seg_index != image_starts->seg_count; seg_index++)
  {
    const uint32_t seg_offset = image_starts->seg_info_offset[seg_index];
    const SundayChainedStartsInSegment * seg_starts;
    SundayChainedPtrFormat format;
    uint16_t page_index;

    if (seg_offset == 0)
      continue;

    seg_starts = (const SundayChainedStartsInSegment *) ((const void *) image_starts + seg_offset);
    format = seg_starts->pointer_format;

    for (page_index = 0; page_index != seg_starts->page_count; page_index++)
    {
      uint16_t start;
      void * cursor;

      start = seg_starts->page_start[page_index];
      if (start == SUNDAY_CHAINED_PTR_START_NONE)
        continue;
      /* Ignoring MULTI for now as it only applies to 32-bit formats. */

      cursor = (void *) mach_header + seg_starts->segment_offset + (page_index * seg_starts->page_size) + start;

      if (format == SUNDAY_CHAINED_PTR_64 || format == SUNDAY_CHAINED_PTR_64_OFFSET)
      {
        sunday_process_chained_fixups_in_segment_generic64 (cursor, format, (uintptr_t) mach_header, preferred_base_address, bound_pointers);
      }
      else
      {
        sunday_process_chained_fixups_in_segment_arm64e (cursor, format, (uintptr_t) mach_header, preferred_base_address, bound_pointers);
      }
    }
  }

  api->mach_vm_deallocate (task, slab_start, slab_size);
}

static void
sunday_process_chained_fixups_in_segment_generic64 (void * cursor, SundayChainedPtrFormat format, uint64_t actual_base_address,
    uint64_t preferred_base_address, void ** bound_pointers)
{
  const int64_t slide = actual_base_address - preferred_base_address;
  const size_t stride = 4;

  while (TRUE)
  {
    uint64_t * slot = cursor;
    size_t delta;

    if ((*slot >> 63) == 0)
    {
      SundayChainedPtr64Rebase * item = cursor;
      uint64_t top_8_bits, bottom_36_bits, unpacked_target;

      delta = item->next;

      top_8_bits = (uint64_t) item->high8 << (64 - 8);
      bottom_36_bits = item->target;
      unpacked_target = top_8_bits | bottom_36_bits;

      if (format == SUNDAY_CHAINED_PTR_64_OFFSET)
        *slot = actual_base_address + unpacked_target;
      else
        *slot = unpacked_target + slide;
    }
    else
    {
      SundayChainedPtr64Bind * item = cursor;

      delta = item->next;

      *slot = (uint64_t) (bound_pointers[item->ordinal] + item->addend);
    }

    if (delta == 0)
      break;

    cursor += delta * stride;
  }
}

static void
sunday_process_chained_fixups_in_segment_arm64e (void * cursor, SundayChainedPtrFormat format, uint64_t actual_base_address,
    uint64_t preferred_base_address, void ** bound_pointers)
{
  const int64_t slide = actual_base_address - preferred_base_address;
  const size_t stride = 8;

  while (TRUE)
  {
    uint64_t * slot = cursor;
    size_t delta;

    switch (*slot >> 62)
    {
      case 0b00:
      {
        SundayChainedPtrArm64eRebase * item = cursor;
        uint64_t top_8_bits, bottom_43_bits, unpacked_target;

        delta = item->next;

        top_8_bits = (uint64_t) item->high8 << (64 - 8);
        bottom_43_bits = item->target;

        unpacked_target = top_8_bits | bottom_43_bits;

        if (format == SUNDAY_CHAINED_PTR_ARM64E)
          *slot = unpacked_target + slide;
        else
          *slot = actual_base_address + unpacked_target;

        break;
      }
      case 0b01:
      {
        SundayChainedPtrArm64eBind * item = cursor;
        SundayChainedPtrArm64eBind24 * item24 = cursor;
        uint32_t ordinal;

        delta = item->next;

        ordinal = (format == SUNDAY_CHAINED_PTR_ARM64E_USERLAND24)
            ? item24->ordinal
            : item->ordinal;

        *slot = (uint64_t) (bound_pointers[ordinal] +
            sunday_sign_extend_int19 (item->addend));

        break;
      }
      case 0b10:
      {
        SundayChainedPtrArm64eAuthRebase * item = cursor;

        delta = item->next;

        *slot = (uint64_t) sunday_sign_pointer ((void *) (preferred_base_address + item->target + slide), item->key, item->diversity,
            item->addr_div, slot);

        break;
      }
      case 0b11:
      {
        SundayChainedPtrArm64eAuthBind * item = cursor;
        SundayChainedPtrArm64eAuthBind24 * item24 = cursor;
        uint32_t ordinal;

        delta = item->next;

        ordinal = (format == SUNDAY_CHAINED_PTR_ARM64E_USERLAND24)
            ? item24->ordinal
            : item->ordinal;

        *slot = (uint64_t) sunday_sign_pointer (bound_pointers[ordinal], item->key, item->diversity, item->addr_div, slot);

        break;
      }
    }

    if (delta == 0)
      break;

    cursor += delta * stride;
  }
}

static void *
sunday_resolve_import (void ** dylib_handles, int dylib_ordinal, const char * symbol_strings, uint32_t symbol_offset,
    const SundayUploadApi * api)
{
  void * result;
  const char * raw_name, * name;

  if (dylib_ordinal <= 0)
    return NULL; /* Placeholder if we ever need to support this. */

  raw_name = symbol_strings + symbol_offset;
  name = sunday_symbol_name_from_darwin (raw_name);

  result = api->dlsym (dylib_handles[dylib_ordinal - 1], name);

  result = ptrauth_strip (result, ptrauth_key_asia);

  return result;
}

static void *
sunday_sign_pointer (void * ptr, uint8_t key, uintptr_t diversity, bool use_address_diversity, void * address_of_ptr)
{
  void * p = ptr;
  uintptr_t d = diversity;

  if (use_address_diversity)
    d = ptrauth_blend_discriminator (address_of_ptr, d);

  switch (key)
  {
    case ptrauth_key_asia:
      p = ptrauth_sign_unauthenticated (p, ptrauth_key_asia, d);
      break;
    case ptrauth_key_asib:
      p = ptrauth_sign_unauthenticated (p, ptrauth_key_asib, d);
      break;
    case ptrauth_key_asda:
      p = ptrauth_sign_unauthenticated (p, ptrauth_key_asda, d);
      break;
    case ptrauth_key_asdb:
      p = ptrauth_sign_unauthenticated (p, ptrauth_key_asdb, d);
      break;
  }

  return p;
}

static const char *
sunday_symbol_name_from_darwin (const char * name)
{
  return (name[0] == '_') ? name + 1 : name;
}

static int64_t
sunday_sign_extend_int19 (uint64_t i19)
{
  int64_t result;
  bool sign_bit_set;

  result = i19;

  sign_bit_set = i19 >> (19 - 1);
  if (sign_bit_set)
    result |= 0xfffffffffff80000ULL;

  return result;
}

static bool
sunday_read_chunk (int fd, void * buffer, size_t length, size_t * bytes_read, const SundayUploadApi * api)
{
  void * cursor = buffer;
  size_t remaining = length;

  if (bytes_read != NULL)
    *bytes_read = 0;

  while (remaining != 0)
  {
    ssize_t n;

    n = SUNDAY_TEMP_FAILURE_RETRY (api->read (fd, cursor, remaining));
    if (n <= 0)
      return false;

    if (bytes_read != NULL)
      *bytes_read += n;

    cursor += n;
    remaining -= n;
  }

  return true;
}

static bool
sunday_write_chunk (int fd, const void * buffer, size_t length, size_t * bytes_written, const SundayUploadApi * api)
{
  const void * cursor = buffer;
  size_t remaining = length;

  if (bytes_written != NULL)
    *bytes_written = 0;

  while (remaining != 0)
  {
    ssize_t n;

    n = SUNDAY_TEMP_FAILURE_RETRY (api->write (fd, cursor, remaining));
    if (n <= 0)
      return false;

    if (bytes_written != NULL)
      *bytes_written += n;

    cursor += n;
    remaining -= n;
  }

  return true;
}

#ifdef BUILDING_TEST_PROGRAM

#include <assert.h>
#include <pthread.h>
#include <stdio.h>

# undef BUILDING_TEST_PROGRAM
# include "upload-listener.c"
# define BUILDING_TEST_PROGRAM
# undef SUNDAY_WRITE_VALUE

typedef struct _SundayTestState SundayTestState;

struct _SundayTestState
{
  uint16_t port;

  uint64_t session_id_top;
  uint64_t session_id_bottom;

  uint8_t target_a[4];
  uint8_t target_b[2];

  const SundayUploadApi * api;
};

static void * sunday_emulate_client (void * user_data);

int
main (void)
{
  const SundayUploadApi api = SUNDAY_UPLOAD_API_INIT;
  uint64_t result;
  uint8_t error_code;
  uint32_t listener_fd;
  uint16_t port;
  pthread_t client_thread;
  SundayTestState state;
  const char * apple[] = { NULL };

  result = sunday_listen (SUNDAY_RX_BUFFER_SIZE, &api);

  error_code  = (result >> 56) & 0xff;
  listener_fd = (result >> 16) & 0xffffffff;
  port        =  result        & 0xffff;

  printf ("listen() => error_code=%u fd=%u port=%u\n", error_code, listener_fd, port);

  assert (error_code == 0);

  state.port = port;

  state.session_id_top = 1;
  state.session_id_bottom = 2;

  state.target_a[0] = 0;
  state.target_a[1] = 0;
  state.target_a[2] = 3;
  state.target_a[3] = 4;
  state.target_b[0] = 0;
  state.target_b[1] = 6;

  state.api = &api;

  pthread_create (&client_thread, NULL, sunday_emulate_client, &state);

  sunday_receive (listener_fd, 1, 2, apple, &api);

  pthread_join (client_thread, NULL);

  assert (state.target_a[0] == 1);
  assert (state.target_a[1] == 2);
  assert (state.target_a[2] == 3);
  assert (state.target_a[3] == 4);
  assert (state.target_b[0] == 5);
  assert (state.target_b[1] == 6);

  return 0;
}

static void *
sunday_emulate_client (void * user_data)
{
  SundayTestState * state = user_data;
  const SundayUploadApi * api = state->api;
  struct sockaddr_in addr;
  int fd;
  int res;
  bool success;
  const SundayUploadCommandType write_command_type = SUNDAY_UPLOAD_COMMAND_WRITE;
  uint64_t address;
  uint32_t size;
  uint8_t val_a[2], val_b;

  fd = api->socket (AF_INET, SOCK_STREAM, 0);
  assert (fd != -1);

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  addr.sin_port = htons (state->port);

  res = SUNDAY_TEMP_FAILURE_RETRY (connect (fd, (const struct sockaddr *) &addr, sizeof (addr)));
  assert (res != -1);

  #define SUNDAY_WRITE_VALUE(v) \
      success = sunday_write_chunk (fd, &(v), sizeof (v), NULL, api); \
      assert (success)

  SUNDAY_WRITE_VALUE (state->session_id_top);
  SUNDAY_WRITE_VALUE (state->session_id_bottom);

  SUNDAY_WRITE_VALUE (write_command_type);
  address = (uint64_t) &state->target_a;
  SUNDAY_WRITE_VALUE (address);
  size = 2;
  SUNDAY_WRITE_VALUE (size);
  val_a[0] = 1;
  val_a[1] = 2;
  SUNDAY_WRITE_VALUE (val_a);

  SUNDAY_WRITE_VALUE (write_command_type);
  address = (uint64_t) &state->target_b;
  SUNDAY_WRITE_VALUE (address);
  size = 1;
  SUNDAY_WRITE_VALUE (size);
  val_b = 5;
  SUNDAY_WRITE_VALUE (val_b);

  api->close (fd);

  return NULL;
}

#endif
