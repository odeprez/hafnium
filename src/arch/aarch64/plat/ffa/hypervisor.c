/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/ffa.h"
#include "hf/arch/other_world.h"
#include "hf/arch/plat/ffa.h"
#include "hf/arch/plat/ffa/indirect_messaging.h"
#include "hf/arch/plat/ffa/setup_and_discovery.h"
#include "hf/arch/plat/ffa/vm.h"

#include "hf/api.h"
#include "hf/dlog.h"
#include "hf/ffa.h"
#include "hf/ffa_internal.h"
#include "hf/vcpu.h"
#include "hf/vm.h"
#include "hf/vm_ids.h"

#include "smc.h"

static bool ffa_tee_enabled = false;

bool plat_ffa_is_tee_enabled(void)
{
	return ffa_tee_enabled;
}

void plat_ffa_set_tee_enabled(bool tee_enabled)
{
	ffa_tee_enabled = tee_enabled;
}

void plat_ffa_log_init(void)
{
	dlog_info("Initializing Hafnium (Hypervisor)\n");
}

void plat_ffa_init(struct mpool *ppool)
{
	struct vm *other_world_vm = vm_find(HF_OTHER_WORLD_ID);
	struct ffa_value ret;
	struct mm_stage1_locked mm_stage1_locked;

	/* This is a segment from TDRAM for the NS memory in the FVP platform.
	 *
	 * TODO: We ought to provide a better way to do this, if porting the
	 * hypervisor to other platforms. One option would be to provide this
	 * via DTS.
	 */
	const uint64_t start = 0x90000000;
	const uint64_t len = 0x60000000;
	const paddr_t send_addr = pa_init(start + len - PAGE_SIZE * 1);
	const paddr_t recv_addr = pa_init(start + len - PAGE_SIZE * 2);

	(void)ppool;

	if (!plat_ffa_is_tee_enabled()) {
		return;
	}

	CHECK(other_world_vm != NULL);

	arch_ffa_init();

	/*
	 * Call FFA_VERSION so the SPMC can store the hypervisor's
	 * version. This may be useful if there is a mismatch of
	 * versions.
	 */
	ret = arch_other_world_call((struct ffa_value){
		.func = FFA_VERSION_32, .arg1 = FFA_VERSION_COMPILED});
	if (ret.func == (uint32_t)FFA_NOT_SUPPORTED) {
		panic("Hypervisor and SPMC versions are not compatible.\n");
	}

	/*
	 * Setup TEE VM RX/TX buffers.
	 * Using the following hard-coded addresses, as they must be within the
	 * NS memory node in the SPMC manifest. From that region we should
	 * exclude the Hypervisor's address space to prevent SPs from using that
	 * memory in memory region nodes, or for the NWd to misuse that memory
	 * in runtime via memory sharing interfaces.
	 */

	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	other_world_vm->mailbox.send = (void *)pa_addr(send_addr);
	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	other_world_vm->mailbox.recv = (void *)pa_addr(recv_addr);

	/*
	 * Note that send and recv are swapped around, as the send buffer from
	 * Hafnium's perspective is the recv buffer from the EL3 dispatcher's
	 * perspective and vice-versa.
	 */
	dlog_verbose("Setting up buffers for TEE.\n");
	plat_ffa_rxtx_map_spmc(
		pa_from_va(va_from_ptr(other_world_vm->mailbox.recv)),
		pa_from_va(va_from_ptr(other_world_vm->mailbox.send)),
		HF_MAILBOX_SIZE / FFA_PAGE_SIZE);

	plat_ffa_set_tee_enabled(true);

	/*
	 * Hypervisor will write to secure world receive buffer, and will read
	 * from the secure world send buffer.
	 *
	 * Mapping operation is necessary because the ranges are outside of the
	 * hypervisor's binary.
	 */
	mm_stage1_locked = mm_lock_stage1();
	CHECK(mm_identity_map(mm_stage1_locked, send_addr,
			      pa_add(send_addr, PAGE_SIZE),
			      MM_MODE_R | MM_MODE_SHARED, ppool) != NULL);
	CHECK(mm_identity_map(
		      mm_stage1_locked, recv_addr, pa_add(recv_addr, PAGE_SIZE),
		      MM_MODE_R | MM_MODE_W | MM_MODE_SHARED, ppool) != NULL);
	mm_unlock_stage1(&mm_stage1_locked);

	dlog_verbose("TEE finished setting up buffers.\n");
}

bool plat_ffa_run_forward(ffa_id_t vm_id, ffa_vcpu_index_t vcpu_idx,
			  struct ffa_value *ret)
{
	/*
	 * VM's requests should be forwarded to the SPMC, if target is an SP.
	 */
	if (!vm_id_is_current_world(vm_id)) {
		*ret = arch_other_world_call_ext((struct ffa_value){
			.func = FFA_RUN_32, ffa_vm_vcpu(vm_id, vcpu_idx)});
		return true;
	}

	return false;
}

bool plat_ffa_intercept_call(struct vcpu_locked current_locked,
			     struct vcpu_locked next_locked,
			     struct ffa_value *signal_interrupt)
{
	(void)current_locked;
	(void)next_locked;
	(void)signal_interrupt;

	return false;
}

/**
 * Check if current VM can resume target VM/SP using FFA_RUN ABI.
 */
bool plat_ffa_run_checks(struct vcpu_locked current_locked,
			 ffa_id_t target_vm_id, ffa_vcpu_index_t vcpu_idx,
			 struct ffa_value *run_ret, struct vcpu **next)
{
	(void)next;
	(void)vcpu_idx;

	/* Only the primary VM can switch vCPUs. */
	if (!vm_is_primary(current_locked.vcpu->vm)) {
		run_ret->arg2 = FFA_DENIED;
		return false;
	}

	/* Only secondary VM vCPUs can be run. */
	if (target_vm_id == HF_PRIMARY_VM_ID) {
		return false;
	}

	return true;
}

void plat_ffa_handle_secure_interrupt(struct vcpu *current, struct vcpu **next)
{
	(void)current;
	(void)next;

	/*
	 * SPMD uses FFA_INTERRUPT ABI to convey secure interrupt to
	 * SPMC. Execution should not reach hypervisor with this ABI.
	 */
	CHECK(false);
}

bool plat_ffa_inject_notification_pending_interrupt(
	struct vcpu_locked target_locked, struct vcpu_locked current_locked,
	struct vm_locked receiver_locked)
{
	(void)target_locked;
	(void)current_locked;
	(void)receiver_locked;

	return false;
}

/**
 * Returns FFA_ERROR as FFA_SECONDARY_EP_REGISTER is not supported at the
 * non-secure FF-A instances.
 */
bool plat_ffa_is_secondary_ep_register_supported(void)
{
	return false;
}

/**
 * The invocation of FFA_MSG_WAIT at non-secure virtual FF-A instance is made
 * to be compliant with version v1.0 of the FF-A specification. It serves as
 * a blocking call.
 */
struct ffa_value plat_ffa_msg_wait_prepare(struct vcpu_locked current_locked,
					   struct vcpu **next)
{
	return plat_ffa_msg_recv(true, current_locked, next);
}

bool plat_ffa_check_runtime_state_transition(struct vcpu_locked current_locked,
					     ffa_id_t vm_id,
					     ffa_id_t receiver_vm_id,
					     struct vcpu_locked receiver_locked,
					     uint32_t func,
					     enum vcpu_state *next_state)
{
	(void)current_locked;
	(void)vm_id;
	(void)receiver_vm_id;
	(void)receiver_locked;

	switch (func) {
	case FFA_YIELD_32:
		/* Fall through. */
	case FFA_MSG_SEND_DIRECT_REQ_64:
	case FFA_MSG_SEND_DIRECT_REQ_32:
	case FFA_MSG_SEND_DIRECT_REQ2_64:
	case FFA_RUN_32:
		*next_state = VCPU_STATE_BLOCKED;
		return true;
	case FFA_MSG_WAIT_32:
		/* Fall through. */
	case FFA_MSG_SEND_DIRECT_RESP_64:
	case FFA_MSG_SEND_DIRECT_RESP_32:
	case FFA_MSG_SEND_DIRECT_RESP2_64:
		*next_state = VCPU_STATE_WAITING;
		return true;
	default:
		return false;
	}
}

void plat_ffa_init_schedule_mode_ffa_run(struct vcpu_locked current_locked,
					 struct vcpu_locked target_locked)
{
	/* Scheduling mode not supported in the Hypervisor/VMs. */
	(void)current_locked;
	(void)target_locked;
}

bool plat_ffa_is_spmd_lp_id(ffa_id_t vm_id)
{
	(void)vm_id;
	return false;
}

/**
 * Enable relevant virtual interrupts for VMs.
 */
void plat_ffa_enable_virtual_interrupts(struct vcpu_locked current_locked,
					struct vm_locked vm_locked)
{
	struct vcpu *current;
	struct interrupts *interrupts;

	current = current_locked.vcpu;
	interrupts = &current->interrupts;

	if (vm_locked.vm->notifications.enabled) {
		vcpu_virt_interrupt_set_enabled(interrupts,
						HF_NOTIFICATION_PENDING_INTID);
	}
}

/**
 * Notifies the `to` VM about the message currently in its mailbox, possibly
 * with the help of the primary VM.
 */
static struct ffa_value deliver_msg(struct vm_locked to, ffa_id_t from_id,
				    struct vcpu_locked current_locked,
				    struct vcpu **next)
{
	struct ffa_value ret = (struct ffa_value){.func = FFA_SUCCESS_32};
	struct ffa_value primary_ret = {
		.func = FFA_MSG_SEND_32,
		.arg1 = ((uint32_t)from_id << 16) | to.vm->id,
	};

	/* Messages for the primary VM are delivered directly. */
	if (vm_is_primary(to.vm)) {
		/*
		 * Only tell the primary VM the size and other details if the
		 * message is for it, to avoid leaking data about messages for
		 * other VMs.
		 */
		primary_ret = ffa_msg_recv_return(to.vm);

		*next = api_switch_to_primary(current_locked, primary_ret,
					      VCPU_STATE_BLOCKED);
		return ret;
	}

	to.vm->mailbox.state = MAILBOX_STATE_FULL;

	/* Messages for the TEE are sent on via the dispatcher. */
	if (to.vm->id == HF_TEE_VM_ID) {
		struct ffa_value call = ffa_msg_recv_return(to.vm);

		ret = arch_other_world_call(call);
		/*
		 * After the call to the TEE completes it must have finished
		 * reading its RX buffer, so it is ready for another message.
		 */
		to.vm->mailbox.state = MAILBOX_STATE_EMPTY;
		/*
		 * Don't return to the primary VM in this case, as the TEE is
		 * not (yet) scheduled via FF-A.
		 */
		return ret;
	}

	/* Return to the primary VM directly or with a switch. */
	if (from_id != HF_PRIMARY_VM_ID) {
		*next = api_switch_to_primary(current_locked, primary_ret,
					      VCPU_STATE_BLOCKED);
	}

	return ret;
}

/*
 * Copies data from the sender's send buffer to the recipient's receive buffer
 * and notifies the recipient.
 *
 * If the recipient's receive buffer is busy, it can optionally register the
 * caller to be notified when the recipient's receive buffer becomes available.
 */
struct ffa_value plat_ffa_msg_send(ffa_id_t sender_vm_id,
				   ffa_id_t receiver_vm_id, uint32_t size,
				   struct vcpu *current, struct vcpu **next)
{
	struct vm *from = current->vm;
	struct vm *to;
	struct vm_locked to_locked;
	const void *from_msg;
	struct ffa_value ret;
	struct vcpu_locked current_locked;
	bool is_direct_request_ongoing;

	/* Ensure sender VM ID corresponds to the current VM. */
	if (sender_vm_id != from->id) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/* Disallow reflexive requests as this suggests an error in the VM. */
	if (receiver_vm_id == from->id) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/* Limit the size of transfer. */
	if (size > FFA_MSG_PAYLOAD_MAX) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/* Ensure the receiver VM exists. */
	to = vm_find(receiver_vm_id);
	if (to == NULL) {
		return ffa_error(FFA_INVALID_PARAMETERS);
	}

	/*
	 * Deny if vCPU is executing in context of an FFA_MSG_SEND_DIRECT_REQ
	 * invocation.
	 */
	current_locked = vcpu_lock(current);
	is_direct_request_ongoing =
		is_ffa_direct_msg_request_ongoing(current_locked);

	if (is_direct_request_ongoing) {
		ret = ffa_error(FFA_DENIED);
		goto out_current;
	}

	/*
	 * Check that the sender has configured its send buffer. If the tx
	 * mailbox at from_msg is configured (i.e. from_msg != NULL) then it can
	 * be safely accessed after releasing the lock since the tx mailbox
	 * address can only be configured once.
	 * A VM's lock must be acquired before any of its vCPU's lock. Hence,
	 * unlock current vCPU and acquire it immediately after its VM's lock.
	 */
	vcpu_unlock(&current_locked);
	sl_lock(&from->lock);
	current_locked = vcpu_lock(current);
	from_msg = from->mailbox.send;
	sl_unlock(&from->lock);

	if (from_msg == NULL) {
		ret = ffa_error(FFA_INVALID_PARAMETERS);
		goto out_current;
	}

	to_locked = vm_lock(to);

	if (vm_is_mailbox_busy(to_locked)) {
		ret = ffa_error(FFA_BUSY);
		goto out;
	}

	/* Copy data. */
	memcpy_s(to->mailbox.recv, FFA_MSG_PAYLOAD_MAX, from_msg, size);
	to->mailbox.recv_size = size;
	to->mailbox.recv_sender = sender_vm_id;
	to->mailbox.recv_func = FFA_MSG_SEND_32;
	to->mailbox.state = MAILBOX_STATE_FULL;
	ret = deliver_msg(to_locked, sender_vm_id, current_locked, next);

out:
	vm_unlock(&to_locked);

out_current:
	vcpu_unlock(&current_locked);

	return ret;
}

/*
 * Prepare to yield execution back to the VM that allocated cpu cycles and move
 * to BLOCKED state.
 */
struct ffa_value plat_ffa_yield_prepare(struct vcpu_locked current_locked,
					struct vcpu **next,
					uint32_t timeout_low,
					uint32_t timeout_high)
{
	struct vcpu *current = current_locked.vcpu;
	struct ffa_value ret = {
		.func = FFA_YIELD_32,
		.arg1 = ffa_vm_vcpu(current->vm->id, vcpu_index(current)),
		.arg2 = timeout_low,
		.arg3 = timeout_high,
	};

	/*
	 * Return execution to primary VM.
	 */
	*next = api_switch_to_primary(current_locked, ret, VCPU_STATE_BLOCKED);

	return (struct ffa_value){.func = FFA_SUCCESS_32};
}

struct ffa_value plat_ffa_error_32(struct vcpu *current, struct vcpu **next,
				   enum ffa_error error_code)
{
	(void)current;
	(void)next;
	(void)error_code;
	/* TODO: Interface not handled in hypervisor. */
	return ffa_error(FFA_NOT_SUPPORTED);
}

uint32_t plat_ffa_interrupt_get(struct vcpu_locked current_locked)
{
	return api_interrupt_get(current_locked);
}

bool plat_ffa_handle_framework_msg(struct ffa_value args, struct ffa_value *ret)
{
	(void)args;
	(void)ret;

	return false;
}
