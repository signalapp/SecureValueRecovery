#include "kbupd_enclave_u.h"
#include <errno.h>

typedef struct ms_kbupd_enclave_recv_untrusted_msg_t {
	const uint8_t* ms_data;
	size_t ms_data_size;
} ms_kbupd_enclave_recv_untrusted_msg_t;

typedef struct ms_sgxsd_enclave_node_init_t {
	sgx_status_t ms_retval;
	const sgxsd_node_init_args_t* ms_p_args;
} ms_sgxsd_enclave_node_init_t;

typedef struct ms_sgxsd_enclave_get_next_report_t {
	sgx_status_t ms_retval;
	sgx_target_info_t ms_qe_target_info;
	sgx_report_t* ms_p_report;
} ms_sgxsd_enclave_get_next_report_t;

typedef struct ms_sgxsd_enclave_set_current_quote_t {
	sgx_status_t ms_retval;
} ms_sgxsd_enclave_set_current_quote_t;

typedef struct ms_sgxsd_enclave_negotiate_request_t {
	sgx_status_t ms_retval;
	const sgxsd_request_negotiation_request_t* ms_p_request;
	sgxsd_request_negotiation_response_t* ms_p_response;
} ms_sgxsd_enclave_negotiate_request_t;

typedef struct ms_sgxsd_enclave_server_start_t {
	sgx_status_t ms_retval;
	const sgxsd_server_init_args_t* ms_p_args;
	sgxsd_server_state_handle_t ms_state_handle;
} ms_sgxsd_enclave_server_start_t;

typedef struct ms_sgxsd_enclave_server_call_t {
	sgx_status_t ms_retval;
	const sgxsd_server_handle_call_args_t* ms_p_args;
	const sgxsd_msg_header_t* ms_msg_header;
	uint8_t* ms_msg_data;
	size_t ms_msg_size;
	sgxsd_msg_tag_t ms_msg_tag;
	sgxsd_server_state_handle_t ms_state_handle;
} ms_sgxsd_enclave_server_call_t;

typedef struct ms_sgxsd_enclave_server_stop_t {
	sgx_status_t ms_retval;
	const sgxsd_server_terminate_args_t* ms_p_args;
	sgxsd_server_state_handle_t ms_state_handle;
} ms_sgxsd_enclave_server_stop_t;

typedef struct ms_kbupd_enclave_ocall_recv_enclave_msg_t {
	const uint8_t* ms_data;
	size_t ms_data_size;
} ms_kbupd_enclave_ocall_recv_enclave_msg_t;

typedef struct ms_kbupd_enclave_ocall_alloc_t {
	void* ms_retval;
	size_t* ms_size;
} ms_kbupd_enclave_ocall_alloc_t;

typedef struct ms_kbupd_enclave_ocall_panic_t {
	const uint8_t* ms_msg;
	size_t ms_msg_size;
} ms_kbupd_enclave_ocall_panic_t;

typedef struct ms_sgxsd_ocall_reply_t {
	sgx_status_t ms_retval;
	const sgxsd_msg_header_t* ms_reply_header;
	const uint8_t* ms_reply_data;
	size_t ms_reply_data_size;
	sgxsd_msg_tag_t ms_msg_tag;
} ms_sgxsd_ocall_reply_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL kbupd_enclave_kbupd_enclave_ocall_recv_enclave_msg(void* pms)
{
	ms_kbupd_enclave_ocall_recv_enclave_msg_t* ms = SGX_CAST(ms_kbupd_enclave_ocall_recv_enclave_msg_t*, pms);
	kbupd_enclave_ocall_recv_enclave_msg(ms->ms_data, ms->ms_data_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL kbupd_enclave_kbupd_enclave_ocall_alloc(void* pms)
{
	ms_kbupd_enclave_ocall_alloc_t* ms = SGX_CAST(ms_kbupd_enclave_ocall_alloc_t*, pms);
	ms->ms_retval = kbupd_enclave_ocall_alloc(ms->ms_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL kbupd_enclave_kbupd_enclave_ocall_panic(void* pms)
{
	ms_kbupd_enclave_ocall_panic_t* ms = SGX_CAST(ms_kbupd_enclave_ocall_panic_t*, pms);
	kbupd_enclave_ocall_panic(ms->ms_msg, ms->ms_msg_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL kbupd_enclave_sgxsd_ocall_reply(void* pms)
{
	ms_sgxsd_ocall_reply_t* ms = SGX_CAST(ms_sgxsd_ocall_reply_t*, pms);
	ms->ms_retval = sgxsd_ocall_reply(ms->ms_reply_header, ms->ms_reply_data, ms->ms_reply_data_size, ms->ms_msg_tag);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL kbupd_enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL kbupd_enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL kbupd_enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL kbupd_enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL kbupd_enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[9];
} ocall_table_kbupd_enclave = {
	9,
	{
		(void*)kbupd_enclave_kbupd_enclave_ocall_recv_enclave_msg,
		(void*)kbupd_enclave_kbupd_enclave_ocall_alloc,
		(void*)kbupd_enclave_kbupd_enclave_ocall_panic,
		(void*)kbupd_enclave_sgxsd_ocall_reply,
		(void*)kbupd_enclave_sgx_oc_cpuidex,
		(void*)kbupd_enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)kbupd_enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)kbupd_enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)kbupd_enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t kbupd_enclave_recv_untrusted_msg(sgx_enclave_id_t eid, const uint8_t* data, size_t data_size)
{
	sgx_status_t status;
	ms_kbupd_enclave_recv_untrusted_msg_t ms;
	ms.ms_data = data;
	ms.ms_data_size = data_size;
	status = sgx_ecall(eid, 0, &ocall_table_kbupd_enclave, &ms);
	return status;
}

sgx_status_t sgxsd_enclave_node_init(sgx_enclave_id_t eid, sgx_status_t* retval, const sgxsd_node_init_args_t* p_args)
{
	sgx_status_t status;
	ms_sgxsd_enclave_node_init_t ms;
	ms.ms_p_args = p_args;
	status = sgx_ecall(eid, 1, &ocall_table_kbupd_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgxsd_enclave_get_next_report(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_target_info_t qe_target_info, sgx_report_t* p_report)
{
	sgx_status_t status;
	ms_sgxsd_enclave_get_next_report_t ms;
	ms.ms_qe_target_info = qe_target_info;
	ms.ms_p_report = p_report;
	status = sgx_ecall(eid, 2, &ocall_table_kbupd_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgxsd_enclave_set_current_quote(sgx_enclave_id_t eid, sgx_status_t* retval)
{
	sgx_status_t status;
	ms_sgxsd_enclave_set_current_quote_t ms;
	status = sgx_ecall(eid, 3, &ocall_table_kbupd_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgxsd_enclave_negotiate_request(sgx_enclave_id_t eid, sgx_status_t* retval, const sgxsd_request_negotiation_request_t* p_request, sgxsd_request_negotiation_response_t* p_response)
{
	sgx_status_t status;
	ms_sgxsd_enclave_negotiate_request_t ms;
	ms.ms_p_request = p_request;
	ms.ms_p_response = p_response;
	status = sgx_ecall(eid, 4, &ocall_table_kbupd_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgxsd_enclave_server_start(sgx_enclave_id_t eid, sgx_status_t* retval, const sgxsd_server_init_args_t* p_args, sgxsd_server_state_handle_t state_handle)
{
	sgx_status_t status;
	ms_sgxsd_enclave_server_start_t ms;
	ms.ms_p_args = p_args;
	ms.ms_state_handle = state_handle;
	status = sgx_ecall(eid, 5, &ocall_table_kbupd_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgxsd_enclave_server_call(sgx_enclave_id_t eid, sgx_status_t* retval, const sgxsd_server_handle_call_args_t* p_args, const sgxsd_msg_header_t* msg_header, uint8_t* msg_data, size_t msg_size, sgxsd_msg_tag_t msg_tag, sgxsd_server_state_handle_t state_handle)
{
	sgx_status_t status;
	ms_sgxsd_enclave_server_call_t ms;
	ms.ms_p_args = p_args;
	ms.ms_msg_header = msg_header;
	ms.ms_msg_data = msg_data;
	ms.ms_msg_size = msg_size;
	ms.ms_msg_tag = msg_tag;
	ms.ms_state_handle = state_handle;
	status = sgx_ecall(eid, 6, &ocall_table_kbupd_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgxsd_enclave_server_stop(sgx_enclave_id_t eid, sgx_status_t* retval, const sgxsd_server_terminate_args_t* p_args, sgxsd_server_state_handle_t state_handle)
{
	sgx_status_t status;
	ms_sgxsd_enclave_server_stop_t ms;
	ms.ms_p_args = p_args;
	ms.ms_state_handle = state_handle;
	status = sgx_ecall(eid, 7, &ocall_table_kbupd_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

