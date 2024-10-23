/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/irq.h"
#include "hf/arch/vm/delay.h"
#include "hf/arch/vm/interrupts_gicv3.h"
#include "hf/arch/vm/power_mgmt.h"
#include "hf/arch/vm/timer.h"

#include "ffa_secure_partitions.h"
#include "gicv3.h"
#include "partition_services.h"
#include "sp805.h"
#include "sp_helpers.h"
#include "wdog.h"

#define SP_SKIP_SLEEP 0U
#define SP_SLEEP_TIME 100U
#define SP_SHORT_SLEEP 10U
#define TIMER_DEADLINE 50U
#define NS_SLEEP_TIME 200U

#define FORWARD_TIMER_CMD 1

#define LAST_SECONDARY_VCPU_ID (MAX_CPUS - 1)

struct secondary_cpu_entry_args {
	ffa_id_t receiver_id;
	ffa_vcpu_index_t vcpu_id;
	struct spinlock lock;
};

/**
 * This test requests SP to start the timer with short deadline and wait for
 * few milliseconds for the deadline to expire. SPMC tracks the timer deadline
 * and signals the virtual timer interrupt which shall be handled by the SP.
 * Further, the test queries the SP for the last serviced virtual interrupt to
 * ensure virtual timer interrupt was handled.
 */
TEST(arch_timer, short_deadline)
{
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service2_info = service2(mb.recv);
	const ffa_id_t receiver_id = service2_info->vm_id;

	res = sp_virtual_interrupt_cmd_send(own_id, receiver_id,
					    HF_VIRTUAL_TIMER_INTID, true, 0);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	res = sp_program_arch_timer_sleep_cmd_send(own_id, receiver_id, 5,
						   SP_SLEEP_TIME, 0);
	/*
	 * Timer deadline would have expired during this time. SP will handle
	 * the virtual timer interrupt.
	 */
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/* Make sure elapsed time not less than sleep time. */
	EXPECT_GE(sp_resp_value(res), SP_SLEEP_TIME);

	/* Check for the last serviced secure virtual interrupt. */
	res = sp_get_last_interrupt_cmd_send(own_id, receiver_id);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/* Make sure virtual timer interrupt was serviced. */
	EXPECT_EQ(sp_resp_value(res), HF_VIRTUAL_TIMER_INTID);
}

/**
 * This test requests SP to program the timer with a long deadline and then
 * requests again to program with a short deadline. SPMC shall honor the most
 * recent configuration of the arch timer by the SP.
 */
TEST(arch_timer, reprogram_deadline)
{
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service2_info = service2(mb.recv);
	const ffa_id_t receiver_id = service2_info->vm_id;

	res = sp_virtual_interrupt_cmd_send(own_id, receiver_id,
					    HF_VIRTUAL_TIMER_INTID, true, 0);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	res = sp_program_arch_timer_sleep_cmd_send(own_id, receiver_id, 100,
						   SP_SHORT_SLEEP, 0);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	res = sp_program_arch_timer_sleep_cmd_send(own_id, receiver_id, 5,
						   SP_SHORT_SLEEP, 0);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/*
	 * Timer deadline would have expired during this time. SP will handle
	 * the virtual timer interrupt.
	 */
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/* Make sure elapsed time not less than sleep time. */
	EXPECT_GE(sp_resp_value(res), SP_SHORT_SLEEP);

	/* Check for the last serviced secure virtual interrupt. */
	res = sp_get_last_interrupt_cmd_send(own_id, receiver_id);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/* Make sure virtual timer interrupt was serviced. */
	EXPECT_EQ(sp_resp_value(res), HF_VIRTUAL_TIMER_INTID);
}

static void enable_arch_timer_virtual_interrupt_all_sp(ffa_id_t own_id,
						       ffa_id_t receiver1_id,
						       ffa_id_t receiver2_id,
						       ffa_id_t receiver3_id)
{
	struct ffa_value res;

	res = sp_virtual_interrupt_cmd_send(own_id, receiver1_id,
					    HF_VIRTUAL_TIMER_INTID, true, 0);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	res = sp_virtual_interrupt_cmd_send(own_id, receiver2_id,
					    HF_VIRTUAL_TIMER_INTID, true, 0);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	res = sp_virtual_interrupt_cmd_send(own_id, receiver3_id,
					    HF_VIRTUAL_TIMER_INTID, true, 0);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);
}

static void check_arch_timer_virtual_interrupt_serviced_all_sp(
	ffa_id_t own_id, ffa_id_t receiver1_id, ffa_id_t receiver2_id,
	ffa_id_t receiver3_id)
{
	struct ffa_value res;

	/* Check for the last serviced secure virtual interrupt. */
	res = sp_get_last_interrupt_cmd_send(own_id, receiver1_id);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/* Make sure virtual timer interrupt was serviced. */
	EXPECT_EQ(sp_resp_value(res), HF_VIRTUAL_TIMER_INTID);

	res = sp_get_last_interrupt_cmd_send(own_id, receiver2_id);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/* Make sure virtual timer interrupt was serviced. */
	EXPECT_EQ(sp_resp_value(res), HF_VIRTUAL_TIMER_INTID);

	res = sp_get_last_interrupt_cmd_send(own_id, receiver3_id);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/* Make sure virtual timer interrupt was serviced. */
	EXPECT_EQ(sp_resp_value(res), HF_VIRTUAL_TIMER_INTID);
}

/**
 * This test initiates a request to form a long normal world call chain with all
 * three SPs. Each SP programs a short deadline followed by a short sleep. The
 * choice of deadline and sleep delay are such that the first SP's deadline
 * expires while execution is in SWd and the third SP's deadline expires while
 * execution is in NWd.
 */
TEST(arch_timer, cascaded_timer_deadlines_long_callchain)
{
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	struct ffa_partition_info *service3_info = service3(mb.recv);
	const ffa_id_t receiver1_id = service1_info->vm_id;
	const ffa_id_t receiver2_id = service2_info->vm_id;
	const ffa_id_t receiver3_id = service3_info->vm_id;

	enable_arch_timer_virtual_interrupt_all_sp(own_id, receiver1_id,
						   receiver2_id, receiver3_id);

	res = sp_program_arch_timer_sleep_cmd_send(own_id, receiver1_id, 10, 5,
						   FORWARD_TIMER_CMD);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/*
	 * Any pending timer's deadline should expire during this time, SP will
	 * handle the virtual timer interrupt.
	 */
	waitms(10);

	check_arch_timer_virtual_interrupt_serviced_all_sp(
		own_id, receiver1_id, receiver2_id, receiver3_id);
}

/**
 * This test is very similar to above test except that the NWd test driver
 * requests each SP to program a deadline followed by a short sleep.
 */
TEST(arch_timer, multiple_sp_deadline)
{
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	struct ffa_partition_info *service3_info = service3(mb.recv);
	const ffa_id_t receiver1_id = service1_info->vm_id;
	const ffa_id_t receiver2_id = service2_info->vm_id;
	const ffa_id_t receiver3_id = service3_info->vm_id;

	enable_arch_timer_virtual_interrupt_all_sp(own_id, receiver1_id,
						   receiver2_id, receiver3_id);

	res = sp_program_arch_timer_sleep_cmd_send(own_id, receiver1_id, 10, 5,
						   0);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	res = sp_program_arch_timer_sleep_cmd_send(own_id, receiver2_id, 10, 5,
						   0);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	res = sp_program_arch_timer_sleep_cmd_send(own_id, receiver3_id, 10, 5,
						   0);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/*
	 * Any pending timer's deadline should expire during this time, SP will
	 * handle the virtual timer interrupt.
	 */
	waitms(10);

	check_arch_timer_virtual_interrupt_serviced_all_sp(
		own_id, receiver1_id, receiver2_id, receiver3_id);
}

static void migrate_up_sp_pending_timer(uintptr_t arg)
{
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_value res;

	struct secondary_cpu_entry_args *args =
		// NOLINTNEXTLINE(performance-no-int-to-ptr)
		(struct secondary_cpu_entry_args *)arg;

	if (args->vcpu_id == LAST_SECONDARY_VCPU_ID) {
		/* Migrate the vCPU of SP with pending timer to CPU7. */
		res = sp_sleep_cmd_send(own_id, args->receiver_id,
					SP_SLEEP_TIME, 0);

		/*
		 * Timer deadline would have expired during this time. SP will
		 * handle the virtual timer interrupt.
		 */
		EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);

		/* Make sure elapsed time not less than sleep time. */
		EXPECT_GE(sp_resp_value(res), SP_SLEEP_TIME);

		/* Check for the last serviced secure virtual interrupt. */
		res = sp_get_last_interrupt_cmd_send(own_id, args->receiver_id);

		EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
		EXPECT_EQ(sp_resp(res), SP_SUCCESS);

		/* Make sure virtual timer interrupt was serviced. */
		EXPECT_EQ(sp_resp_value(res), HF_VIRTUAL_TIMER_INTID);
	}

	/* Releases the lock passed in. */
	sl_unlock(&args->lock);
	arch_cpu_stop();
}

/**
 * This test causes the vCPU of an SP with pending timer to be migrated to a
 * different CPU.
 */
TEST_PRECONDITION_LONG_RUNNING(arch_timer, migrate_with_deadline,
			       service2_is_up_sp)
{
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();
	struct secondary_cpu_entry_args args;
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *up_receiver_info = service2(mb.recv);
	ffa_id_t up_receiver_id = up_receiver_info->vm_id;
	struct ffa_partition_info *companion_info = service3(mb.recv);
	ffa_id_t companion_id = companion_info->vm_id;

	ASSERT_EQ(up_receiver_info->vcpu_count, 1);

	args.receiver_id = up_receiver_id;
	res = sp_virtual_interrupt_cmd_send(own_id, up_receiver_id,
					    HF_VIRTUAL_TIMER_INTID, true, 0);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	res = sp_virtual_interrupt_cmd_send(own_id, companion_id,
					    HF_VIRTUAL_TIMER_INTID, true, 0);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	res = sp_program_arch_timer_sleep_cmd_send(own_id, companion_id, 30,
						   SP_SKIP_SLEEP, 0);
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	res = sp_program_arch_timer_sleep_cmd_send(
		own_id, up_receiver_id, TIMER_DEADLINE, SP_SKIP_SLEEP, 0);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/* Start secondary EC while holding lock. */
	sl_lock(&args.lock);

	for (size_t i = 1; i < MAX_CPUS; i++) {
		uintptr_t id;

		id = hftest_get_cpu_id(i);
		args.vcpu_id = i;
		HFTEST_LOG("Booting CPU %zu - %lx", i, id);

		EXPECT_EQ(hftest_cpu_start(id, hftest_get_secondary_ec_stack(i),
					   migrate_up_sp_pending_timer,
					   (uintptr_t)&args),
			  true);

		/* Wait for CPU to release the lock. */
		sl_lock(&args.lock);

		HFTEST_LOG("Done with CPU %zu", i);
	}

	/* Check for the last serviced secure virtual interrupt. */
	res = sp_get_last_interrupt_cmd_send(own_id, companion_id);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/* Make sure virtual timer interrupt was serviced. */
	EXPECT_EQ(sp_resp_value(res), HF_VIRTUAL_TIMER_INTID);
}

TEST(arch_timer, preempted_state)
{
	struct ffa_value res;
	ffa_id_t own_id = hf_vm_get_id();
	struct mailbox_buffers mb = set_up_mailbox();
	struct ffa_partition_info *service2_info = service2(mb.recv);
	const ffa_id_t receiver_id = service2_info->vm_id;

	gicv3_system_setup();

	/* Source of non-secure interrupt. */
	setup_wdog_timer_interrupt();

	/* Set watchdog timer for 20 ms. */
	start_wdog_timer(20);

	res = sp_virtual_interrupt_cmd_send(own_id, receiver_id,
					    HF_VIRTUAL_TIMER_INTID, true, 0);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	res = sp_program_arch_timer_sleep_cmd_send(own_id, receiver_id, 200, 50,
						   0);

	/* SP is pre-empted by the non-secure watchdog interrupt. */
	EXPECT_EQ(res.func, FFA_INTERRUPT_32);

	/* VM id/vCPU index are passed through arg1. */
	EXPECT_EQ(res.arg1, ffa_vm_vcpu(receiver_id, 0));

	/* Waiting for interrupt to be serviced in normal world. */
	while (last_interrupt_id == 0) {
		EXPECT_EQ(io_read32_array(GICD_ISPENDR, 0), 0);
		EXPECT_EQ(io_read32(GICR_ISPENDR0), 0);
		EXPECT_EQ(io_read32_array(GICD_ISACTIVER, 0), 0);
		EXPECT_EQ(io_read32(GICR_ISACTIVER0), 0);
	}

	/* Check that we got the non-secure watchdog interrupt. */
	EXPECT_EQ(last_interrupt_id, IRQ_WDOG_INTID);

	/* Stop the watchdog timer. */
	wdog_stop();

	/*
	 * NS Interrupt has been serviced and receiver SP is now in PREEMPTED
	 * state. Wait for arch timer of SP to be fired. SPMC queues the secure
	 * virtual interrupt.
	 */
	waitms(NS_SLEEP_TIME);

	/*
	 * Resume the SP to complete the busy loop, handle the secure virtual
	 * interrupt and return with success.
	 */
	res = ffa_run(ffa_vm_id(res), ffa_vcpu_index(res));
	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(res.arg3, SP_SUCCESS);

	/* Check for the last serviced secure virtual interrupt. */
	res = sp_get_last_interrupt_cmd_send(own_id, receiver_id);

	EXPECT_EQ(res.func, FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_EQ(sp_resp(res), SP_SUCCESS);

	/* Make sure virtual timer interrupt was serviced. */
	EXPECT_EQ(sp_resp_value(res), HF_VIRTUAL_TIMER_INTID);
}
