#ifndef _KBUPD_SGXSD_CALLBACKS_H
#define _KBUPD_SGXSD_CALLBACKS_H

#include <stdint.h>

typedef enum kbupd_request_type {
  KBUPD_REQUEST_TYPE_ANY     = 0,
  KBUPD_REQUEST_TYPE_BACKUP  = 1,
  KBUPD_REQUEST_TYPE_RESTORE = 2,
  KBUPD_REQUEST_TYPE_DELETE  = 3,
} kbupd_request_type_t;

typedef struct sgxsd_server_init_args {
} sgxsd_server_init_args_t;
_Static_assert(sizeof(sgxsd_server_init_args_t) == 0, "Enclave ABI compatibility");

typedef struct sgxsd_server_handle_call_args {
  uint8_t  backup_id[32];
  uint32_t request_type;
} sgxsd_server_handle_call_args_t;
_Static_assert(sizeof(sgxsd_server_handle_call_args_t) == 36, "Enclave ABI compatibility");

typedef struct sgxsd_server_terminate_args {
} sgxsd_server_terminate_args_t;
_Static_assert(sizeof(sgxsd_server_terminate_args_t) == 0, "Enclave ABI compatibility");

typedef struct sgxsd_ra_get_quote_args {
  const void *args;
} sgxsd_ra_get_quote_args_t;

#endif
