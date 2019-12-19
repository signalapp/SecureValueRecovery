#ifndef KBUPD_ENCLAVE_U_H__
#define KBUPD_ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "kbupd_sgxsd_callbacks.h"
#include "stdbool.h"
#include "sgx_quote.h"
#include "sgx_report.h"
#include "sgxsd.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef KBUPD_ENCLAVE_OCALL_RECV_ENCLAVE_MSG_DEFINED__
#define KBUPD_ENCLAVE_OCALL_RECV_ENCLAVE_MSG_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, kbupd_enclave_ocall_recv_enclave_msg, (const uint8_t* data, size_t data_size));
#endif
#ifndef KBUPD_ENCLAVE_OCALL_ALLOC_DEFINED__
#define KBUPD_ENCLAVE_OCALL_ALLOC_DEFINED__
void* SGX_UBRIDGE(SGX_NOCONVENTION, kbupd_enclave_ocall_alloc, (size_t* size));
#endif
#ifndef KBUPD_ENCLAVE_OCALL_PANIC_DEFINED__
#define KBUPD_ENCLAVE_OCALL_PANIC_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, kbupd_enclave_ocall_panic, (const uint8_t* msg, size_t msg_size));
#endif
#ifndef SGXSD_OCALL_REPLY_DEFINED__
#define SGXSD_OCALL_REPLY_DEFINED__
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, sgxsd_ocall_reply, (const sgxsd_msg_header_t* reply_header, const uint8_t* reply_data, size_t reply_data_size, sgxsd_msg_tag_t msg_tag));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif

sgx_status_t kbupd_enclave_recv_untrusted_msg(sgx_enclave_id_t eid, const uint8_t* data, size_t data_size);
sgx_status_t sgxsd_enclave_node_init(sgx_enclave_id_t eid, sgx_status_t* retval, const sgxsd_node_init_args_t* p_args);
sgx_status_t sgxsd_enclave_get_next_report(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_target_info_t qe_target_info, sgx_report_t* p_report);
sgx_status_t sgxsd_enclave_set_current_quote(sgx_enclave_id_t eid, sgx_status_t* retval);
sgx_status_t sgxsd_enclave_negotiate_request(sgx_enclave_id_t eid, sgx_status_t* retval, const sgxsd_request_negotiation_request_t* p_request, sgxsd_request_negotiation_response_t* p_response);
sgx_status_t sgxsd_enclave_server_start(sgx_enclave_id_t eid, sgx_status_t* retval, const sgxsd_server_init_args_t* p_args, sgxsd_server_state_handle_t state_handle);
sgx_status_t sgxsd_enclave_server_call(sgx_enclave_id_t eid, sgx_status_t* retval, const sgxsd_server_handle_call_args_t* p_args, const sgxsd_msg_header_t* msg_header, uint8_t* msg_data, size_t msg_size, sgxsd_msg_tag_t msg_tag, sgxsd_server_state_handle_t state_handle);
sgx_status_t sgxsd_enclave_server_stop(sgx_enclave_id_t eid, sgx_status_t* retval, const sgxsd_server_terminate_args_t* p_args, sgxsd_server_state_handle_t state_handle);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
