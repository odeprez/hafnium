/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdalign.h>

#include "hf/arch/vm/power_mgmt.h"

#include "hf/spinlock.h"

#include "vmapi/hf/call.h"

#include "test/hftest.h"
#include "test/vmapi/ffa.h"

/*
 * TODO: Some of these tests are duplicated between 'primary_only' and
 * 'primary_with_secondaries'. Move them to a common place consider running
 * them inside secondary VMs too.
 */

/**
 * Confirms the primary VM has the primary ID.
 */
TEST(hf_vm_get_id, primary_has_primary_id)
{
	EXPECT_EQ(hf_vm_get_id(), HF_PRIMARY_VM_ID);
}

/**
 * Confirm there is only the primary VM.
 */
TEST(hf_vm_get_count, no_secondary_vms)
{
	EXPECT_EQ(hf_vm_get_count(), 1);
}

/**
 * Confirm the primary has at least one vCPU.
 */
TEST(hf_vcpu_get_count, primary_has_at_least_one)
{
	EXPECT_GE(hf_vcpu_get_count(HF_PRIMARY_VM_ID), 0);
}

/**
 * Confirm an error is returned when getting the vCPU count of a non-existent
 * VM.
 */
TEST(hf_vcpu_get_count, no_secondary_vms)
{
	EXPECT_EQ(hf_vcpu_get_count(HF_VM_ID_OFFSET + 1), 0);
}

/**
 * Confirm an error is returned when getting the vCPU count for a reserved ID.
 */
TEST(hf_vcpu_get_count, reserved_vm_id)
{
	ffa_vm_id_t id;

	for (id = 0; id < HF_VM_ID_OFFSET; ++id) {
		EXPECT_EQ(hf_vcpu_get_count(id), 0);
	}
}

/**
 * Confirm an error is returned when getting the vCPU count of a VM with an ID
 * that is likely to be far outside the resource limit.
 */
TEST(hf_vcpu_get_count, large_invalid_vm_id)
{
	EXPECT_EQ(hf_vcpu_get_count(0xffff), 0);
}

/**
 * Confirm it is an error when running a vCPU from the primary VM.
 */
TEST(ffa_run, cannot_run_primary)
{
	struct ffa_value res = ffa_run(HF_PRIMARY_VM_ID, 0);
	EXPECT_FFA_ERROR(res, FFA_INVALID_PARAMETERS);
}

/**
 * Confirm it is an error when running a vCPU from a non-existent secondary VM.
 */
TEST(ffa_run, cannot_run_absent_secondary)
{
	struct ffa_value res = ffa_run(1, 0);
	EXPECT_FFA_ERROR(res, FFA_INVALID_PARAMETERS);
}

/**
 * Yielding from the primary is a noop.
 */
TEST(ffa_yield, yield_is_noop_for_primary)
{
	EXPECT_EQ(ffa_yield().func, FFA_SUCCESS_32);
}

/**
 * Releases the lock passed in.
 */
static void vm_cpu_entry(uintptr_t arg)
{
	struct spinlock *lock = (struct spinlock *)arg;

	dlog("Second CPU started.\n");
	sl_unlock(lock);
}

/**
 * Confirm a new CPU can be started to execute in parallel.
 */
TEST(cpus, start)
{
	struct spinlock lock = SPINLOCK_INIT;
	alignas(4096) static uint8_t other_stack[4096];

	/* Start secondary while holding lock. */
	sl_lock(&lock);
	EXPECT_EQ(hftest_cpu_start(hftest_get_cpu_id(1), other_stack,
				   sizeof(other_stack), vm_cpu_entry,
				   (uintptr_t)&lock),
		  true);

	/* Wait for CPU to release the lock. */
	sl_lock(&lock);
}

/**
 * Releases the lock passed in and then stops the CPU.
 */
static void vm_cpu_entry_stop(uintptr_t arg)
{
	struct spinlock *lock = (struct spinlock *)arg;

	dlog("Second CPU started.\n");
	sl_unlock(lock);

	dlog("Second CPU stopping.\n");
	arch_cpu_stop();

	FAIL("arch_cpu_stop() returned.");
}

/**
 * Confirm a secondary CPU can be stopped again.
 */
TEST(cpus, stop)
{
	struct spinlock lock = SPINLOCK_INIT;
	alignas(4096) static uint8_t other_stack[4096];

	/* Start secondary while holding lock. */
	sl_lock(&lock);
	dlog("Starting second CPU.\n");
	EXPECT_EQ(hftest_cpu_start(hftest_get_cpu_id(1), other_stack,
				   sizeof(other_stack), vm_cpu_entry_stop,
				   (uintptr_t)&lock),
		  true);

	/* Wait for CPU to release the lock after starting. */
	sl_lock(&lock);

	dlog("Waiting for second CPU to stop.\n");
	/* Wait a while for CPU to stop. */
	while (arch_cpu_status(hftest_get_cpu_id(1)) != POWER_STATUS_OFF) {
	}
	dlog("Second CPU stopped.\n");

	dlog("Starting second CPU again.\n");
	EXPECT_EQ(hftest_cpu_start(hftest_get_cpu_id(1), other_stack,
				   sizeof(other_stack), vm_cpu_entry_stop,
				   (uintptr_t)&lock),
		  true);

	/* Wait for CPU to release the lock after starting. */
	sl_lock(&lock);

	dlog("Waiting for second CPU to stop.\n");
	/* Wait a while for CPU to stop. */
	while (arch_cpu_status(hftest_get_cpu_id(1)) != POWER_STATUS_OFF) {
	}
	dlog("Second CPU stopped.\n");
}

/** Ensures that the Hafnium FF-A version is reported as expected. */
TEST(ffa, ffa_version)
{
	const int32_t major_revision = 1;
	const int32_t major_revision_offset = 16;
	const int32_t minor_revision = 0;
	const int32_t current_version =
		(major_revision << major_revision_offset) | minor_revision;

	EXPECT_EQ(ffa_version(current_version), current_version);
	EXPECT_EQ(ffa_version(0x0), current_version);
	EXPECT_EQ(ffa_version(0x1), current_version);
	EXPECT_EQ(ffa_version(0x10003), current_version);
	EXPECT_EQ(ffa_version(0xffff), current_version);
	EXPECT_EQ(ffa_version(0xfffffff), current_version);
}

/** Ensures that an invalid call to FFA_VERSION gets an error back. */
TEST(ffa, ffa_version_invalid)
{
	int32_t ret = ffa_version(0x80000000);

	EXPECT_EQ(ret, FFA_NOT_SUPPORTED);
}

/** Ensures that FFA_FEATURES is reporting the expected interfaces. */
TEST(ffa, ffa_features)
{
	struct ffa_value ret;

	ret = ffa_features(FFA_ERROR_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_SUCCESS_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_INTERRUPT_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_VERSION_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_FEATURES_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_RX_RELEASE_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_RXTX_MAP_64);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_ID_GET_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MSG_POLL_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MSG_WAIT_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_YIELD_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_RUN_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MSG_SEND_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MEM_DONATE_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MEM_LEND_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MEM_SHARE_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MEM_RETRIEVE_REQ_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MEM_RETRIEVE_RESP_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MEM_RELINQUISH_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);

	ret = ffa_features(FFA_MEM_RECLAIM_32);
	EXPECT_EQ(ret.func, FFA_SUCCESS_32);
}

/**
 * Ensures that FFA_FEATURES returns not supported for a bogus FID or
 * currently non-implemented interfaces.
 */
TEST(ffa, ffa_features_not_supported)
{
	struct ffa_value ret;

	ret = ffa_features(0);
	EXPECT_FFA_ERROR(ret, FFA_NOT_SUPPORTED);

	ret = ffa_features(0x84000000);
	EXPECT_FFA_ERROR(ret, FFA_NOT_SUPPORTED);

	ret = ffa_features(FFA_RXTX_UNMAP_32);
	EXPECT_FFA_ERROR(ret, FFA_NOT_SUPPORTED);

	ret = ffa_features(FFA_PARTITION_INFO_GET_32);
	EXPECT_FFA_ERROR(ret, FFA_NOT_SUPPORTED);

	ret = ffa_features(FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_FFA_ERROR(ret, FFA_NOT_SUPPORTED);

	ret = ffa_features(FFA_MSG_SEND_DIRECT_REQ_32);
	EXPECT_FFA_ERROR(ret, FFA_NOT_SUPPORTED);

	ret = ffa_features(FFA_MSG_SEND_DIRECT_REQ_32);
	EXPECT_FFA_ERROR(ret, FFA_NOT_SUPPORTED);

	ret = ffa_features(FFA_MSG_SEND_DIRECT_RESP_32);
	EXPECT_FFA_ERROR(ret, FFA_NOT_SUPPORTED);
}

/**
 * Test that floating-point operations work in the primary VM.
 */
TEST(fp, fp)
{
	/*
	 * Get some numbers that the compiler can't tell are constants, so it
	 * can't optimise them away.
	 */
	double a = hf_vm_get_count();
	double b = hf_vcpu_get_count(HF_PRIMARY_VM_ID);
	double result = a * b;
	dlog("VM count: %d\n", hf_vm_get_count());
	dlog("vCPU count: %d\n", hf_vcpu_get_count(HF_PRIMARY_VM_ID));
	dlog("result: %d\n", (int)result);
	EXPECT_TRUE(a == 1.0);
	EXPECT_TRUE(b == 8.0);
	EXPECT_TRUE(result == 8.0);
}
