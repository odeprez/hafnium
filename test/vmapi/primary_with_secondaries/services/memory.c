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

#include "hf/mm.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "hftest.h"
#include "primary_with_secondary.h"
#include "util.h"

alignas(PAGE_SIZE) static uint8_t page[PAGE_SIZE];

TEST_SERVICE(memory_increment)
{
	/* Loop, writing message to the shared memory. */
	for (;;) {
		struct spci_value ret = spci_msg_wait();
		uint8_t *ptr;
		size_t i;
		void *recv_buf = SERVICE_RECV_BUFFER();
		struct spci_memory_region *memory_region =
			(struct spci_memory_region *)recv_buf;
		struct spci_memory_region_constituent *constituents =
			spci_memory_region_get_constituents(memory_region);

		EXPECT_EQ(ret.func, SPCI_MSG_SEND_32);
		EXPECT_EQ(spci_msg_send_attributes(ret),
			  SPCI_MSG_SEND_LEGACY_MEMORY_SHARE);

		ptr = (uint8_t *)constituents[0].address;

		/* Check the memory was cleared. */
		for (i = 0; i < PAGE_SIZE; ++i) {
			ASSERT_EQ(ptr[i], 0);
		}

		/* Allow the memory to be populated. */
		EXPECT_EQ(spci_yield().func, SPCI_SUCCESS_32);

		/* Increment each byte of memory. */
		for (i = 0; i < PAGE_SIZE; ++i) {
			++ptr[i];
		}

		/* Signal completion and reset. */
		spci_rx_release();
		spci_msg_send(hf_vm_get_id(), spci_msg_send_sender(ret),
			      sizeof(ptr), 0);
	}
}

TEST_SERVICE(give_memory_and_fault)
{
	void *send_buf = SERVICE_SEND_BUFFER();

	/* Give memory to the primary. */
	struct spci_memory_region_constituent constituents[] = {
		{.address = (uint64_t)&page, .page_count = 1},
	};
	uint32_t msg_size = spci_memory_region_init(
		send_buf, HF_PRIMARY_VM_ID, constituents,
		ARRAY_SIZE(constituents), 0, SPCI_MEMORY_REGION_FLAG_CLEAR,
		SPCI_MEMORY_RW_X, SPCI_MEMORY_NORMAL_MEM,
		SPCI_MEMORY_CACHE_WRITE_BACK, SPCI_MEMORY_OUTER_SHAREABLE);
	EXPECT_EQ(spci_msg_send(hf_vm_get_id(), HF_PRIMARY_VM_ID, msg_size,
				SPCI_MSG_SEND_LEGACY_MEMORY_DONATE)
			  .func,
		  SPCI_SUCCESS_32);

	/* Try using the memory that isn't valid unless it's been returned. */
	page[16] = 123;
}

TEST_SERVICE(lend_memory_and_fault)
{
	void *send_buf = SERVICE_SEND_BUFFER();

	/* Lend memory to the primary. */
	struct spci_memory_region_constituent constituents[] = {
		{.address = (uint64_t)&page, .page_count = 1},
	};
	uint32_t msg_size = spci_memory_region_init(
		send_buf, HF_PRIMARY_VM_ID, constituents,
		ARRAY_SIZE(constituents), 0, SPCI_MEMORY_REGION_FLAG_CLEAR,
		SPCI_MEMORY_RW_X, SPCI_MEMORY_NORMAL_MEM,
		SPCI_MEMORY_CACHE_WRITE_BACK, SPCI_MEMORY_OUTER_SHAREABLE);
	EXPECT_EQ(spci_msg_send(hf_vm_get_id(), HF_PRIMARY_VM_ID, msg_size,
				SPCI_MSG_SEND_LEGACY_MEMORY_LEND)
			  .func,
		  SPCI_SUCCESS_32);

	/* Try using the memory that isn't valid unless it's been returned. */
	page[633] = 180;
}

TEST_SERVICE(spci_memory_return)
{
	/* Loop, giving memory back to the sender. */
	for (;;) {
		struct spci_value ret = spci_msg_wait();
		uint8_t *ptr;
		uint32_t msg_size;
		size_t i;
		void *recv_buf = SERVICE_RECV_BUFFER();
		void *send_buf = SERVICE_SEND_BUFFER();
		struct spci_memory_region *memory_region;
		struct spci_memory_region_constituent *constituents;

		EXPECT_EQ(ret.func, SPCI_MSG_SEND_32);
		/*
		 * The memory may have been sent in one of several different
		 * ways, but there shouldn't be any other attributes to the
		 * message.
		 */
		EXPECT_NE(spci_msg_send_attributes(ret) &
				  SPCI_MSG_SEND_LEGACY_MEMORY_MASK,
			  0);
		EXPECT_EQ(spci_msg_send_attributes(ret) &
				  ~SPCI_MSG_SEND_LEGACY_MEMORY_MASK,
			  0);

		memory_region = (struct spci_memory_region *)recv_buf;
		constituents =
			spci_memory_region_get_constituents(memory_region);
		ptr = (uint8_t *)constituents[0].address;

		/* Check that one has access to the shared region. */
		for (i = 0; i < PAGE_SIZE; ++i) {
			ptr[i]++;
		}

		/* Give the memory back and notify the sender. */
		msg_size = spci_memory_region_init(
			send_buf, HF_PRIMARY_VM_ID, constituents,
			memory_region->constituent_count, 0, 0,
			SPCI_MEMORY_RW_X, SPCI_MEMORY_NORMAL_MEM,
			SPCI_MEMORY_CACHE_WRITE_BACK,
			SPCI_MEMORY_OUTER_SHAREABLE);
		spci_rx_release();
		EXPECT_EQ(spci_msg_send(spci_msg_send_receiver(ret),
					spci_msg_send_sender(ret), msg_size,
					SPCI_MSG_SEND_LEGACY_MEMORY_DONATE)
				  .func,
			  SPCI_SUCCESS_32);

		/*
		 * Try and access the memory which will cause a fault unless the
		 * memory has been shared back again.
		 */
		ptr[0] = 123;
	}
}

TEST_SERVICE(spci_donate_check_upper_bound)
{
	struct spci_value ret = spci_msg_wait();
	uint8_t *ptr;
	uint8_t index;
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct spci_memory_region *memory_region;
	struct spci_memory_region_constituent *constituents;

	EXPECT_EQ(ret.func, SPCI_MSG_SEND_32);
	EXPECT_EQ(spci_msg_send_attributes(ret),
		  SPCI_MSG_SEND_LEGACY_MEMORY_DONATE);
	memory_region = (struct spci_memory_region *)recv_buf;
	constituents = spci_memory_region_get_constituents(memory_region);

	/* Choose which constituent we want to test. */
	index = *(uint8_t *)constituents[0].address;
	ptr = (uint8_t *)constituents[index].address;

	spci_rx_release();

	/* Check that one cannot access out of bounds after donated region. */
	ptr[PAGE_SIZE]++;
}

TEST_SERVICE(spci_donate_check_lower_bound)
{
	struct spci_value ret = spci_msg_wait();
	uint8_t *ptr;
	uint8_t index;
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct spci_memory_region *memory_region =
		(struct spci_memory_region *)recv_buf;
	struct spci_memory_region_constituent *constituents =
		spci_memory_region_get_constituents(memory_region);

	EXPECT_EQ(ret.func, SPCI_MSG_SEND_32);
	EXPECT_EQ(spci_msg_send_attributes(ret),
		  SPCI_MSG_SEND_LEGACY_MEMORY_DONATE);

	/* Choose which constituent we want to test. */
	index = *(uint8_t *)constituents[0].address;
	ptr = (uint8_t *)constituents[index].address;
	spci_rx_release();

	/* Check that one cannot access out of bounds before donated region. */
	ptr[-1]++;
}

/**
 * Attempt to donate memory and then modify.
 */
TEST_SERVICE(spci_donate_secondary_and_fault)
{
	struct spci_value ret = spci_msg_wait();
	uint8_t *ptr;
	uint32_t msg_size;
	void *recv_buf = SERVICE_RECV_BUFFER();
	void *send_buf = SERVICE_SEND_BUFFER();
	struct spci_memory_region *memory_region =
		(struct spci_memory_region *)recv_buf;
	struct spci_memory_region_constituent *constituents =
		spci_memory_region_get_constituents(memory_region);

	EXPECT_EQ(ret.func, SPCI_MSG_SEND_32);
	EXPECT_EQ(spci_msg_send_attributes(ret),
		  SPCI_MSG_SEND_LEGACY_MEMORY_DONATE);

	ptr = (uint8_t *)constituents[0].address;

	/* Donate memory to next VM. */
	msg_size = spci_memory_region_init(
		send_buf, SERVICE_VM2, constituents,
		memory_region->constituent_count, 0, 0, SPCI_MEMORY_RW_X,
		SPCI_MEMORY_NORMAL_MEM, SPCI_MEMORY_CACHE_WRITE_BACK,
		SPCI_MEMORY_OUTER_SHAREABLE);
	spci_rx_release();
	EXPECT_EQ(spci_msg_send(spci_msg_send_receiver(ret), SERVICE_VM2,
				msg_size, SPCI_MSG_SEND_LEGACY_MEMORY_DONATE)
			  .func,
		  SPCI_SUCCESS_32);

	/* Ensure that we are unable to modify memory any more. */
	ptr[0] = 'c';
	EXPECT_EQ(ptr[0], 'c');
	spci_yield();
}

/**
 * Attempt to donate memory twice from VM.
 */
TEST_SERVICE(spci_donate_twice)
{
	uint32_t msg_size;
	struct spci_value ret = spci_msg_wait();
	void *recv_buf = SERVICE_RECV_BUFFER();
	void *send_buf = SERVICE_SEND_BUFFER();
	struct spci_memory_region *memory_region =
		(struct spci_memory_region *)recv_buf;
	struct spci_memory_region_constituent constituent =
		spci_memory_region_get_constituents(memory_region)[0];

	EXPECT_EQ(ret.func, SPCI_MSG_SEND_32);
	EXPECT_EQ(spci_msg_send_attributes(ret),
		  SPCI_MSG_SEND_LEGACY_MEMORY_DONATE);
	spci_rx_release();

	/* Yield to allow attempt to re donate from primary. */
	spci_yield();

	/* Give the memory back and notify the sender. */
	msg_size = spci_memory_region_init(
		send_buf, HF_PRIMARY_VM_ID, &constituent, 1, 0, 0,
		SPCI_MEMORY_RW_X, SPCI_MEMORY_NORMAL_MEM,
		SPCI_MEMORY_CACHE_WRITE_BACK, SPCI_MEMORY_OUTER_SHAREABLE);
	EXPECT_EQ(spci_msg_send(SERVICE_VM1, HF_PRIMARY_VM_ID, msg_size,
				SPCI_MSG_SEND_LEGACY_MEMORY_DONATE)
			  .func,
		  SPCI_SUCCESS_32);

	/* Attempt to donate the memory to another VM. */
	msg_size = spci_memory_region_init(
		send_buf, SERVICE_VM2, &constituent, 1, 0, 0, SPCI_MEMORY_RW_X,
		SPCI_MEMORY_NORMAL_MEM, SPCI_MEMORY_CACHE_WRITE_BACK,
		SPCI_MEMORY_OUTER_SHAREABLE);
	EXPECT_SPCI_ERROR(
		spci_msg_send(spci_msg_send_receiver(ret), SERVICE_VM2,
			      msg_size, SPCI_MSG_SEND_LEGACY_MEMORY_DONATE),
		SPCI_INVALID_PARAMETERS);

	spci_yield();
}

/**
 * Continually receive memory, check if we have access and ensure it is not
 * changed by a third party.
 */
TEST_SERVICE(spci_memory_receive)
{
	for (;;) {
		struct spci_value ret = spci_msg_wait();
		uint8_t *ptr;
		void *recv_buf = SERVICE_RECV_BUFFER();
		struct spci_memory_region *memory_region =
			(struct spci_memory_region *)recv_buf;
		struct spci_memory_region_constituent *constituents =
			spci_memory_region_get_constituents(memory_region);

		EXPECT_EQ(ret.func, SPCI_MSG_SEND_32);
		EXPECT_EQ(spci_msg_send_attributes(ret),
			  SPCI_MSG_SEND_LEGACY_MEMORY_DONATE);

		ptr = (uint8_t *)constituents[0].address;
		spci_rx_release();
		ptr[0] = 'd';
		spci_yield();

		/* Ensure memory has not changed. */
		EXPECT_EQ(ptr[0], 'd');
		spci_yield();
	}
}

/**
 * Receive memory and attempt to donate from primary VM.
 */
TEST_SERVICE(spci_donate_invalid_source)
{
	uint32_t msg_size;
	struct spci_value ret = spci_msg_wait();
	void *recv_buf = SERVICE_RECV_BUFFER();
	void *send_buf = SERVICE_SEND_BUFFER();
	struct spci_memory_region *memory_region =
		(struct spci_memory_region *)recv_buf;
	struct spci_memory_region_constituent *constituents =
		spci_memory_region_get_constituents(memory_region);

	EXPECT_EQ(ret.func, SPCI_MSG_SEND_32);
	EXPECT_EQ(spci_msg_send_attributes(ret),
		  SPCI_MSG_SEND_LEGACY_MEMORY_DONATE);

	/* Give the memory back and notify the sender. */
	msg_size = spci_memory_region_init(
		send_buf, HF_PRIMARY_VM_ID, constituents,
		memory_region->constituent_count, 0, 0, SPCI_MEMORY_RW_X,
		SPCI_MEMORY_NORMAL_MEM, SPCI_MEMORY_CACHE_WRITE_BACK,
		SPCI_MEMORY_OUTER_SHAREABLE);
	EXPECT_EQ(spci_msg_send(spci_msg_send_receiver(ret), HF_PRIMARY_VM_ID,
				msg_size, SPCI_MSG_SEND_LEGACY_MEMORY_DONATE)
			  .func,
		  SPCI_SUCCESS_32);

	/* Fail to donate the memory from the primary to VM2. */
	msg_size = spci_memory_region_init(
		send_buf, SERVICE_VM2, constituents,
		memory_region->constituent_count, 0, 0, SPCI_MEMORY_RW_X,
		SPCI_MEMORY_NORMAL_MEM, SPCI_MEMORY_CACHE_WRITE_BACK,
		SPCI_MEMORY_OUTER_SHAREABLE);
	spci_rx_release();
	EXPECT_SPCI_ERROR(spci_msg_send(HF_PRIMARY_VM_ID, SERVICE_VM2, msg_size,
					SPCI_MSG_SEND_LEGACY_MEMORY_DONATE),
			  SPCI_INVALID_PARAMETERS);
	spci_yield();
}

TEST_SERVICE(spci_memory_lend_relinquish)
{
	/* Loop, giving memory back to the sender. */
	for (;;) {
		struct spci_value ret = spci_msg_wait();
		uint8_t *ptr;
		uint8_t *ptr2;
		uint32_t count;
		uint32_t count2;
		uint32_t msg_size;
		size_t i;

		void *recv_buf = SERVICE_RECV_BUFFER();
		void *send_buf = SERVICE_SEND_BUFFER();
		struct spci_memory_region *memory_region =
			(struct spci_memory_region *)recv_buf;
		struct spci_memory_region_constituent *constituents =
			spci_memory_region_get_constituents(memory_region);

		EXPECT_EQ(ret.func, SPCI_MSG_SEND_32);
		/*
		 * The memory may have been sent in one of several different
		 * ways, but there shouldn't be any other attributes to the
		 * message.
		 */
		EXPECT_NE(spci_msg_send_attributes(ret) &
				  SPCI_MSG_SEND_LEGACY_MEMORY_MASK,
			  0);
		EXPECT_EQ(spci_msg_send_attributes(ret) &
				  ~SPCI_MSG_SEND_LEGACY_MEMORY_MASK,
			  0);

		ptr = (uint8_t *)constituents[0].address;
		count = constituents[0].page_count;
		ptr2 = (uint8_t *)constituents[1].address;
		count2 = constituents[1].page_count;

		/* Check that one has access to the shared region. */
		for (i = 0; i < PAGE_SIZE * count; ++i) {
			ptr[i]++;
		}
		for (i = 0; i < PAGE_SIZE * count2; ++i) {
			ptr2[i]++;
		}

		/* Give the memory back and notify the sender. */
		msg_size = spci_memory_region_init(
			send_buf, HF_PRIMARY_VM_ID, constituents,
			memory_region->constituent_count, 0, 0,
			SPCI_MEMORY_RW_X, SPCI_MEMORY_NORMAL_MEM,
			SPCI_MEMORY_CACHE_WRITE_BACK,
			SPCI_MEMORY_OUTER_SHAREABLE);
		/* Relevant information read, mailbox can be cleared. */
		spci_rx_release();
		EXPECT_EQ(spci_msg_send(spci_msg_send_receiver(ret),
					spci_msg_send_sender(ret), msg_size,
					SPCI_MSG_SEND_LEGACY_MEMORY_RELINQUISH)
				  .func,
			  SPCI_SUCCESS_32);

		/*
		 * Try and access the memory which will cause a fault unless the
		 * memory has been shared back again.
		 */
		ptr[0] = 123;
	}
}

/**
 * Ensure that we can't relinquish donated memory.
 */
TEST_SERVICE(spci_memory_donate_relinquish)
{
	for (;;) {
		struct spci_value ret = spci_msg_wait();
		uint8_t *ptr;
		uint32_t msg_size;
		size_t i;

		void *recv_buf = SERVICE_RECV_BUFFER();
		void *send_buf = SERVICE_SEND_BUFFER();
		struct spci_memory_region *memory_region =
			(struct spci_memory_region *)recv_buf;
		struct spci_memory_region_constituent *constituents =
			spci_memory_region_get_constituents(memory_region);

		EXPECT_EQ(ret.func, SPCI_MSG_SEND_32);
		EXPECT_EQ(spci_msg_send_attributes(ret),
			  SPCI_MSG_SEND_LEGACY_MEMORY_DONATE);

		ptr = (uint8_t *)constituents[0].address;

		/* Check that one has access to the shared region. */
		for (i = 0; i < PAGE_SIZE; ++i) {
			ptr[i]++;
		}
		/* Give the memory back and notify the sender. */
		msg_size = spci_memory_region_init(
			send_buf, HF_PRIMARY_VM_ID, constituents,
			memory_region->constituent_count, 0, 0,
			SPCI_MEMORY_RW_X, SPCI_MEMORY_NORMAL_MEM,
			SPCI_MEMORY_CACHE_WRITE_BACK,
			SPCI_MEMORY_OUTER_SHAREABLE);
		spci_rx_release();
		EXPECT_SPCI_ERROR(
			spci_msg_send(spci_msg_send_receiver(ret),
				      HF_PRIMARY_VM_ID, msg_size,
				      SPCI_MSG_SEND_LEGACY_MEMORY_RELINQUISH),
			SPCI_INVALID_PARAMETERS);

		/* Ensure we still have access to the memory. */
		ptr[0] = 123;

		spci_yield();
	}
}

/**
 * Receive memory and attempt to donate from primary VM.
 */
TEST_SERVICE(spci_lend_invalid_source)
{
	uint32_t msg_size;
	struct spci_value ret = spci_msg_wait();

	void *recv_buf = SERVICE_RECV_BUFFER();
	void *send_buf = SERVICE_SEND_BUFFER();
	struct spci_memory_region *memory_region =
		(struct spci_memory_region *)recv_buf;
	struct spci_memory_region_constituent *constituents =
		spci_memory_region_get_constituents(memory_region);

	EXPECT_EQ(ret.func, SPCI_MSG_SEND_32);
	EXPECT_EQ(spci_msg_send_attributes(ret),
		  SPCI_MSG_SEND_LEGACY_MEMORY_LEND);

	/* Attempt to relinquish from primary VM. */
	msg_size = spci_memory_region_init(
		send_buf, spci_msg_send_receiver(ret), constituents,
		memory_region->constituent_count, 0, 0, SPCI_MEMORY_RW_X,
		SPCI_MEMORY_NORMAL_MEM, SPCI_MEMORY_CACHE_WRITE_BACK,
		SPCI_MEMORY_OUTER_SHAREABLE);
	EXPECT_SPCI_ERROR(
		spci_msg_send(HF_PRIMARY_VM_ID, spci_msg_send_receiver(ret),
			      msg_size, SPCI_MSG_SEND_LEGACY_MEMORY_RELINQUISH),
		SPCI_INVALID_PARAMETERS);

	/* Give the memory back and notify the sender. */
	msg_size = spci_memory_region_init(
		send_buf, HF_PRIMARY_VM_ID, constituents,
		memory_region->constituent_count, 0, 0, SPCI_MEMORY_RW_X,
		SPCI_MEMORY_NORMAL_MEM, SPCI_MEMORY_CACHE_WRITE_BACK,
		SPCI_MEMORY_OUTER_SHAREABLE);
	EXPECT_EQ(
		spci_msg_send(spci_msg_send_receiver(ret), HF_PRIMARY_VM_ID,
			      msg_size, SPCI_MSG_SEND_LEGACY_MEMORY_RELINQUISH)
			.func,
		SPCI_SUCCESS_32);

	/* Ensure we cannot lend from the primary to another secondary. */
	msg_size = spci_memory_region_init(
		send_buf, SERVICE_VM2, constituents,
		memory_region->constituent_count, 0, 0, SPCI_MEMORY_RW_X,
		SPCI_MEMORY_NORMAL_MEM, SPCI_MEMORY_CACHE_WRITE_BACK,
		SPCI_MEMORY_OUTER_SHAREABLE);
	EXPECT_SPCI_ERROR(spci_msg_send(HF_PRIMARY_VM_ID, SERVICE_VM2, msg_size,
					SPCI_MSG_SEND_LEGACY_MEMORY_LEND),
			  SPCI_INVALID_PARAMETERS);

	/* Ensure we cannot share from the primary to another secondary. */
	msg_size = spci_memory_region_init(
		send_buf, SERVICE_VM2, constituents,
		memory_region->constituent_count, 0, 0, SPCI_MEMORY_RW_X,
		SPCI_MEMORY_NORMAL_MEM, SPCI_MEMORY_CACHE_WRITE_BACK,
		SPCI_MEMORY_OUTER_SHAREABLE);
	spci_rx_release();
	EXPECT_SPCI_ERROR(spci_msg_send(HF_PRIMARY_VM_ID, SERVICE_VM2, msg_size,
					SPCI_MSG_SEND_LEGACY_MEMORY_SHARE),
			  SPCI_INVALID_PARAMETERS);

	spci_yield();
}

/**
 * Attempt to execute an instruction from the lent memory.
 */
TEST_SERVICE(spci_memory_lend_relinquish_X)
{
	for (;;) {
		struct spci_value ret = spci_msg_wait();
		uint64_t *ptr;
		uint32_t msg_size;

		void *recv_buf = SERVICE_RECV_BUFFER();
		void *send_buf = SERVICE_SEND_BUFFER();
		struct spci_memory_region *memory_region =
			(struct spci_memory_region *)recv_buf;
		struct spci_memory_region_constituent *constituents =
			spci_memory_region_get_constituents(memory_region);

		EXPECT_EQ(ret.func, SPCI_MSG_SEND_32);
		EXPECT_EQ(spci_msg_send_attributes(ret),
			  SPCI_MSG_SEND_LEGACY_MEMORY_LEND);

		ptr = (uint64_t *)constituents[0].address;
		/*
		 * Verify that the instruction in memory is the encoded RET
		 * instruction.
		 */
		EXPECT_EQ(*ptr, 0xD65F03C0);
		/* Try to execute instruction from the shared memory region. */
		__asm__ volatile("blr %0" ::"r"(ptr));

		/* Release the memory again. */
		msg_size = spci_memory_region_init(
			send_buf, HF_PRIMARY_VM_ID, constituents,
			memory_region->constituent_count, 0, 0,
			SPCI_MEMORY_RW_X, SPCI_MEMORY_NORMAL_MEM,
			SPCI_MEMORY_CACHE_WRITE_BACK,
			SPCI_MEMORY_OUTER_SHAREABLE);
		spci_rx_release();
		EXPECT_EQ(spci_msg_send(spci_msg_send_receiver(ret),
					HF_PRIMARY_VM_ID, msg_size,
					SPCI_MSG_SEND_LEGACY_MEMORY_RELINQUISH)
				  .func,
			  SPCI_SUCCESS_32);
	}
}

/**
 * Attempt to read and write to a shared page.
 */
TEST_SERVICE(spci_memory_lend_relinquish_RW)
{
	for (;;) {
		struct spci_value ret = spci_msg_wait();
		uint8_t *ptr;
		uint32_t msg_size;
		size_t i;

		void *recv_buf = SERVICE_RECV_BUFFER();
		void *send_buf = SERVICE_SEND_BUFFER();
		struct spci_memory_region *memory_region =
			(struct spci_memory_region *)recv_buf;
		struct spci_memory_region_constituent *constituents =
			spci_memory_region_get_constituents(memory_region);
		struct spci_memory_region_constituent constituent_copy =
			constituents[0];

		EXPECT_EQ(ret.func, SPCI_MSG_SEND_32);
		/*
		 * The memory may have been sent in one of several different
		 * ways, but there shouldn't be any other attributes to the
		 * message.
		 */
		EXPECT_NE(spci_msg_send_attributes(ret) &
				  SPCI_MSG_SEND_LEGACY_MEMORY_MASK,
			  0);
		EXPECT_EQ(spci_msg_send_attributes(ret) &
				  ~SPCI_MSG_SEND_LEGACY_MEMORY_MASK,
			  0);

		spci_rx_release();

		ptr = (uint8_t *)constituent_copy.address;

		/* Check that we have read access. */
		for (i = 0; i < PAGE_SIZE; ++i) {
			EXPECT_EQ(ptr[i], 'b');
		}

		/* Return control to primary, to verify shared access. */
		spci_yield();

		/* Attempt to modify the memory. */
		for (i = 0; i < PAGE_SIZE; ++i) {
			ptr[i]++;
		}

		msg_size = spci_memory_region_init(
			send_buf, HF_PRIMARY_VM_ID, &constituent_copy, 1, 0, 0,
			SPCI_MEMORY_RW_X, SPCI_MEMORY_NORMAL_MEM,
			SPCI_MEMORY_CACHE_WRITE_BACK,
			SPCI_MEMORY_OUTER_SHAREABLE);
		EXPECT_EQ(spci_msg_send(spci_msg_send_receiver(ret),
					HF_PRIMARY_VM_ID, msg_size,
					SPCI_MSG_SEND_LEGACY_MEMORY_RELINQUISH)
				  .func,
			  SPCI_SUCCESS_32);
	}
}

/**
 * Attempt to modify above the upper bound for the lent memory.
 */
TEST_SERVICE(spci_lend_check_upper_bound)
{
	struct spci_value ret = spci_msg_wait();
	uint8_t *ptr;
	uint8_t index;

	void *recv_buf = SERVICE_RECV_BUFFER();
	struct spci_memory_region *memory_region =
		(struct spci_memory_region *)recv_buf;
	struct spci_memory_region_constituent *constituents =
		spci_memory_region_get_constituents(memory_region);

	EXPECT_EQ(ret.func, SPCI_MSG_SEND_32);
	EXPECT_EQ(spci_msg_send_attributes(ret),
		  SPCI_MSG_SEND_LEGACY_MEMORY_LEND);

	/* Choose which constituent we want to test. */
	index = *(uint8_t *)constituents[0].address;
	ptr = (uint8_t *)constituents[index].address;
	spci_rx_release();

	/* Check that one cannot access after lent region. */
	ASSERT_EQ(ptr[PAGE_SIZE], 0);
}

/**
 * Attempt to modify below the lower bound for the lent memory.
 */
TEST_SERVICE(spci_lend_check_lower_bound)
{
	struct spci_value ret = spci_msg_wait();
	uint8_t *ptr;
	uint8_t index;

	void *recv_buf = SERVICE_RECV_BUFFER();
	struct spci_memory_region *memory_region =
		(struct spci_memory_region *)recv_buf;
	struct spci_memory_region_constituent *constituents =
		spci_memory_region_get_constituents(memory_region);

	EXPECT_EQ(ret.func, SPCI_MSG_SEND_32);
	EXPECT_EQ(spci_msg_send_attributes(ret),
		  SPCI_MSG_SEND_LEGACY_MEMORY_LEND);

	/* Choose which constituent we want to test. */
	index = *(uint8_t *)constituents[0].address;
	ptr = (uint8_t *)constituents[index].address;
	spci_rx_release();

	/* Check that one cannot access after lent region. */
	ptr[-1]++;
	spci_yield();
}

TEST_SERVICE(spci_memory_lend_twice)
{
	struct spci_value ret = spci_msg_wait();
	uint8_t *ptr;
	uint32_t msg_size;
	size_t i;

	void *recv_buf = SERVICE_RECV_BUFFER();
	void *send_buf = SERVICE_SEND_BUFFER();
	struct spci_memory_region *memory_region =
		(struct spci_memory_region *)recv_buf;
	struct spci_memory_region_constituent *constituents =
		spci_memory_region_get_constituents(memory_region);
	struct spci_memory_region_constituent constituent_copy =
		constituents[0];

	EXPECT_EQ(ret.func, SPCI_MSG_SEND_32);
	/*
	 * The memory may have been sent in one of several different ways, but
	 * there shouldn't be any other attributes to the message.
	 */
	EXPECT_NE(spci_msg_send_attributes(ret) &
			  SPCI_MSG_SEND_LEGACY_MEMORY_MASK,
		  0);
	EXPECT_EQ(spci_msg_send_attributes(ret) &
			  ~SPCI_MSG_SEND_LEGACY_MEMORY_MASK,
		  0);

	spci_rx_release();

	ptr = (uint8_t *)constituent_copy.address;

	/* Check that we have read access. */
	for (i = 0; i < PAGE_SIZE; ++i) {
		EXPECT_EQ(ptr[i], 'b');
	}

	/* Attempt to modify the memory. */
	for (i = 0; i < PAGE_SIZE; ++i) {
		ptr[i]++;
	}

	for (i = 1; i < PAGE_SIZE * 2; i++) {
		constituent_copy.address = (uint64_t)ptr + i;

		/* Fail to lend or share the memory back to the primary. */
		msg_size = spci_memory_region_init(
			send_buf, SERVICE_VM2, &constituent_copy, 1, 0, 0,
			SPCI_MEMORY_RW_X, SPCI_MEMORY_NORMAL_MEM,
			SPCI_MEMORY_CACHE_WRITE_BACK,
			SPCI_MEMORY_OUTER_SHAREABLE);
		EXPECT_SPCI_ERROR(
			spci_msg_send(HF_PRIMARY_VM_ID, SERVICE_VM2, msg_size,
				      SPCI_MSG_SEND_LEGACY_MEMORY_LEND),
			SPCI_INVALID_PARAMETERS);
		msg_size = spci_memory_region_init(
			send_buf, SERVICE_VM2, &constituent_copy, 1, 0, 0,
			SPCI_MEMORY_RW_X, SPCI_MEMORY_NORMAL_MEM,
			SPCI_MEMORY_CACHE_WRITE_BACK,
			SPCI_MEMORY_OUTER_SHAREABLE);
		EXPECT_SPCI_ERROR(
			spci_msg_send(HF_PRIMARY_VM_ID, SERVICE_VM2, msg_size,
				      SPCI_MSG_SEND_LEGACY_MEMORY_SHARE),
			SPCI_INVALID_PARAMETERS);
	}

	/* Return control to primary. */
	spci_yield();
}
