/*
 * Copyright 2019 The Hafnium Authors.
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

#pragma once

#include "hf/types.h"

/* clang-format off */

#define SPCI_LOW_32_ID  0x84000060
#define SPCI_HIGH_32_ID 0x8400007F
#define SPCI_LOW_64_ID  0xC4000060
#define SPCI_HIGH_32_ID 0x8400007F

/* SPCI function identifiers. */
#define SPCI_ERROR_32                 0x84000060
#define SPCI_SUCCESS_32               0x84000061
#define SPCI_INTERRUPT_32             0x84000062
#define SPCI_VERSION_32               0x84000063
#define SPCI_FEATURES_32              0x84000064
#define SPCI_RX_RELEASE_32            0x84000065
#define SPCI_RXTX_MAP_32              0x84000066
#define SPCI_RXTX_MAP_64              0xC4000066
#define SPCI_RXTX_UNMAP_32            0x84000067
#define SPCI_PARTITION_INFO_GET_32    0x84000068
#define SPCI_ID_GET_32                0x84000069
#define SPCI_MSG_POLL_32              0x8400006A
#define SPCI_MSG_WAIT_32              0x8400006B
#define SPCI_YIELD_32                 0x8400006C
#define SPCI_RUN_32                   0x8400006D
#define SPCI_MSG_SEND_32              0x8400006E
#define SPCI_MSG_SEND_DIRECT_REQ_32   0x8400006F
#define SPCI_MSG_SEND_DIRECT_RESP_32  0x84000070
#define SPCI_MEM_DONATE_32            0x84000071
#define SPCI_MEM_LEND_32              0x84000072
#define SPCI_MEM_SHARE_32             0x84000073
#define SPCI_MEM_RETRIEVE_REQ_32      0x84000074
#define SPCI_MEM_RETRIEVE_RESP_32     0x84000075
#define SPCI_MEM_RELINQUISH_32        0x84000076
#define SPCI_MEM_RECLAIM_32           0x84000077

/* SPCI error codes. */
#define SPCI_NOT_SUPPORTED      INT32_C(-1)
#define SPCI_INVALID_PARAMETERS INT32_C(-2)
#define SPCI_NO_MEMORY          INT32_C(-3)
#define SPCI_BUSY               INT32_C(-4)
#define SPCI_INTERRUPTED        INT32_C(-5)
#define SPCI_DENIED             INT32_C(-6)
#define SPCI_RETRY              INT32_C(-7)
#define SPCI_ABORTED            INT32_C(-8)

/* SPCI function specific constants. */
#define SPCI_MSG_RECV_BLOCK  0x1
#define SPCI_MSG_RECV_BLOCK_MASK  0x1

#define SPCI_MSG_SEND_NOTIFY 0x1
#define SPCI_MSG_SEND_NOTIFY_MASK 0x1

#define SPCI_MEM_RECLAIM_CLEAR 0x1

#define SPCI_SLEEP_INDEFINITE 0

/**
 * For use where the SPCI specification refers explicitly to '4K pages'. Not to
 * be confused with PAGE_SIZE, which is the translation granule Hafnium is
 * configured to use.
 */
#define SPCI_PAGE_SIZE 4096

/* The maximum length possible for a single message. */
#define SPCI_MSG_PAYLOAD_MAX HF_MAILBOX_SIZE

enum spci_memory_access {
	SPCI_MEMORY_RO_NX,
	SPCI_MEMORY_RO_X,
	SPCI_MEMORY_RW_NX,
	SPCI_MEMORY_RW_X,
};

enum spci_memory_type {
	SPCI_MEMORY_DEVICE_MEM,
	SPCI_MEMORY_NORMAL_MEM,
};

enum spci_memory_cacheability {
	SPCI_MEMORY_CACHE_RESERVED = 0x0,
	SPCI_MEMORY_CACHE_NON_CACHEABLE = 0x1,
	SPCI_MEMORY_CACHE_WRITE_THROUGH = 0x2,
	SPCI_MEMORY_CACHE_WRITE_BACK = 0x4,
	SPCI_MEMORY_DEV_NGNRNE = 0x0,
	SPCI_MEMORY_DEV_NGNRE = 0x1,
	SPCI_MEMORY_DEV_NGRE = 0x2,
	SPCI_MEMORY_DEV_GRE = 0x3,
};

enum spci_memory_shareability {
	SPCI_MEMORY_SHARE_NON_SHAREABLE,
	SPCI_MEMORY_RESERVED,
	SPCI_MEMORY_OUTER_SHAREABLE,
	SPCI_MEMORY_INNER_SHAREABLE,
};

#define SPCI_MEMORY_ACCESS_OFFSET (0x5U)
#define SPCI_MEMORY_ACCESS_MASK ((0x3U) << SPCI_MEMORY_ACCESS_OFFSET)

#define SPCI_MEMORY_TYPE_OFFSET (0x4U)
#define SPCI_MEMORY_TYPE_MASK ((0x1U) << SPCI_MEMORY_TYPE_OFFSET)

#define SPCI_MEMORY_CACHEABILITY_OFFSET (0x2U)
#define SPCI_MEMORY_CACHEABILITY_MASK ((0x3U) <<\
	SPCI_MEMORY_CACHEABILITY_OFFSET)

#define SPCI_MEMORY_SHAREABILITY_OFFSET (0x0U)
#define SPCI_MEMORY_SHAREABILITY_MASK ((0x3U) <<\
	SPCI_MEMORY_SHAREABILITY_OFFSET)

#define LEND_ATTR_FUNCTION_SET(name, offset, mask) \
static inline void spci_set_memory_##name##_attr(uint16_t *attr,\
	const enum spci_memory_##name perm)\
{\
	*attr = (*attr & ~(mask)) | ((perm  << offset) & mask);\
}

#define LEND_ATTR_FUNCTION_GET(name, offset, mask) \
static inline enum spci_memory_##name spci_get_memory_##name##_attr(\
	uint16_t attr)\
{\
	return (enum spci_memory_##name)((attr & mask) >> offset);\
}

LEND_ATTR_FUNCTION_SET(access, SPCI_MEMORY_ACCESS_OFFSET,
	SPCI_MEMORY_ACCESS_MASK)
LEND_ATTR_FUNCTION_GET(access, SPCI_MEMORY_ACCESS_OFFSET,
	SPCI_MEMORY_ACCESS_MASK)

LEND_ATTR_FUNCTION_SET(type, SPCI_MEMORY_TYPE_OFFSET, SPCI_MEMORY_TYPE_MASK)
LEND_ATTR_FUNCTION_GET(type, SPCI_MEMORY_TYPE_OFFSET, SPCI_MEMORY_TYPE_MASK)

LEND_ATTR_FUNCTION_SET(cacheability, SPCI_MEMORY_CACHEABILITY_OFFSET,
	SPCI_MEMORY_CACHEABILITY_MASK)

LEND_ATTR_FUNCTION_GET(cacheability, SPCI_MEMORY_CACHEABILITY_OFFSET,
	SPCI_MEMORY_CACHEABILITY_MASK)

LEND_ATTR_FUNCTION_SET(shareability, SPCI_MEMORY_SHAREABILITY_OFFSET,
	SPCI_MEMORY_SHAREABILITY_MASK)

LEND_ATTR_FUNCTION_GET(shareability, SPCI_MEMORY_SHAREABILITY_OFFSET,
	SPCI_MEMORY_SHAREABILITY_MASK)

/* clang-format on */

#define SPCI_MEMORY_HANDLE_ALLOCATOR_MASK ((spci_memory_handle_t)(1U << 31))
#define SPCI_MEMORY_HANDLE_ALLOCATOR_HYPERVISOR \
	((spci_memory_handle_t)(1U << 31))

/** The ID of a VM. These are assigned sequentially starting with an offset. */
typedef uint16_t spci_vm_id_t;

/**
 * A globally-unique ID assigned by the hypervisor for a region of memory being
 * sent between VMs.
 */
typedef uint32_t spci_memory_handle_t;

/**
 * A unique-per-VM ID used to associate fragments of a memory sharing message,
 * assigned by the sender of the message.
 */
typedef uint32_t spci_cookie_t;

/**
 * A count of VMs. This has the same range as the VM IDs but we give it a
 * different name to make the different semantics clear.
 */
typedef spci_vm_id_t spci_vm_count_t;

/** The index of a vCPU within a particular VM. */
typedef uint16_t spci_vcpu_index_t;

/**
 * A count of vCPUs. This has the same range as the vCPU indices but we give it
 * a different name to make the different semantics clear.
 */
typedef spci_vcpu_index_t spci_vcpu_count_t;

/** Parameter and return type of SPCI functions. */
struct spci_value {
	uint64_t func;
	uint64_t arg1;
	uint64_t arg2;
	uint64_t arg3;
	uint64_t arg4;
	uint64_t arg5;
	uint64_t arg6;
	uint64_t arg7;
};

static inline spci_vm_id_t spci_msg_send_sender(struct spci_value args)
{
	return (args.arg1 >> 16) & 0xffff;
}

static inline spci_vm_id_t spci_msg_send_receiver(struct spci_value args)
{
	return args.arg1 & 0xffff;
}

static inline uint32_t spci_msg_send_size(struct spci_value args)
{
	return args.arg3;
}

static inline uint32_t spci_msg_send_attributes(struct spci_value args)
{
	return args.arg4;
}

static inline spci_memory_handle_t spci_mem_success_handle(
	struct spci_value args)
{
	return args.arg2;
}

static inline spci_vm_id_t spci_vm_id(struct spci_value args)
{
	return (args.arg1 >> 16) & 0xffff;
}

static inline spci_vcpu_index_t spci_vcpu_index(struct spci_value args)
{
	return args.arg1 & 0xffff;
}

static inline uint64_t spci_vm_vcpu(spci_vm_id_t vm_id,
				    spci_vcpu_index_t vcpu_index)
{
	return ((uint32_t)vm_id << 16) | vcpu_index;
}

struct spci_memory_region_constituent {
	/**
	 * The base IPA of the constituent memory region, aligned to 4 kiB page
	 * size granularity.
	 */
	uint32_t address_low;
	uint32_t address_high;
	/** The number of 4 kiB pages in the constituent memory region. */
	uint32_t page_count;
	/** Reserved field, must be 0. */
	uint32_t reserved;
};

struct spci_memory_region_attributes {
	/** The ID of the VM to which the memory is being given or shared. */
	spci_vm_id_t receiver;
	/**
	 * The attributes with which the memory region should be mapped in the
	 * receiver's page table.
	 */
	uint16_t memory_attributes;
	/** Reserved field, must be 0. */
	uint32_t reserved_0;
	/** Reserved field, must be 0. */
	uint64_t reserved_1;
};

/** Flags to control the behaviour of a memory sharing transaction. */
typedef uint32_t spci_memory_region_flags_t;

/**
 * Clear memory region contents after unmapping it from the sender and before
 * mapping it for any receiver.
 */
#define SPCI_MEMORY_REGION_FLAG_CLEAR 0x1

struct spci_memory_region {
	/**
	 * An implementation defined value associated with the receiver and the
	 * memory region.
	 */
	uint32_t tag;
	/** Flags to control behaviour of the transaction. */
	spci_memory_region_flags_t flags;
	/** Sender VM ID. */
	spci_vm_id_t sender;
	/** Reserved field, must be 0. */
	uint16_t reserved_0;
	/**
	 * The total number of 4 kiB pages included in this memory region. This
	 * must be equal to the sum of page counts specified in each
	 * `spci_memory_region_constituent`.
	 */
	uint32_t page_count;
	/**
	 * The number of constituents (`spci_memory_region_constituent`)
	 * included in this memory region.
	 */
	uint32_t constituent_count;
	/**
	 * The offset in bytes from the base address of this
	 * `spci_memory_region` to the start of the first
	 * `spci_memory_region_constituent`.
	 */
	uint32_t constituent_offset;
	/**
	 * The number of `spci_memory_region_attributes` entries included in
	 * this memory region.
	 */
	uint32_t attribute_count;
	/** Reserved field, must be 0. */
	uint32_t reserved_1;
	/**
	 * An array of `attribute_count` memory region attribute descriptors.
	 * Each one specifies an endpoint and the attributes with which this
	 * memory region should be mapped in that endpoint's page table.
	 */
	struct spci_memory_region_attributes attributes[];
};

/**
 * Retrieval attributes for a single receiver. This corresponds to table 138 of
 * the SPCI beta specification, "Descriptor with properties to retrieve a memory
 * region".
 */
struct spci_memory_retrieve_properties {
	struct spci_memory_region_attributes attributes;
	uint32_t page_count;
	uint32_t constituent_count;
	/** Reserved field, must be 0. */
	uint32_t reserved;
	struct spci_memory_region_constituent constituents[];
};

/**
 * Descriptor used for SPCI_MEM_RETRIEVE_REQ. This corresponds to table 137 of
 * the SPCI beta specification, "Descriptor to retrieve a donated, lent or
 * shared memory region".
 */
struct spci_memory_retrieve_request {
	/** Globally unique handle to identify the memory transaction. */
	spci_memory_handle_t handle;
	/** ID of the VM which sent the memory. */
	spci_vm_id_t sender;
	/** Reserved field, must be 0. */
	uint16_t reserved_0;
	/** Function ID of the memory sharing operation. */
	uint32_t share_func;
	/**
	 * An implementation defined value associated with the receiver and the
	 * memory region.
	 */
	uint32_t tag;
	/**
	 * The number of descriptors to specify the attributes with which the
	 * memory region will be mapped in the other recipients. Hafnium doesn't
	 * support multi-way memory sharing so this should always be 0.
	 */
	uint32_t attribute_count;
	/**
	 * The offset in bytes from the base address of this
	 * `spci_memory_retrieve_request` to the start of the first attribute
	 * descriptor.
	 */
	uint32_t attribute_offset;
	/**
	 * The number of `spci_memory_retrieve_properties` entries included
	 * in this retrieve request, i.e. the number of receivers including the
	 * caller and any stream endpoints for which the caller is a proxy.
	 * Hafnium doesn't support stream endpoints, so this should always be 1.
	 */
	uint32_t retrieve_properties_count;
	/** Reserved field, must be 0. */
	uint32_t reserved_1;
	/*
	 * 'Array' of `struct spci_memory_retrieve_properties` goes here, but it
	 * is not included in the struct as the entries are variable length. Use
	 * `spci_memory_retrieve_request_first_retrieve_properties` to get the
	 * first one.
	 */
};

/**
 * Receiver address range descriptor. This corresponds to table 144 of the SPCI
 * beta specification, "Descriptor with address ranges of retrieved memory
 * region", and is included as part of the `spci_retrieved_memory_region`.
 */
struct spci_receiver_address_range {
	/** Receiver VM ID. */
	spci_vm_id_t receiver;
	/** Reserved field, must be 0. */
	uint16_t reserved_0;
	/**
	 * The total number of 4 kiB pages included in this memory region. This
	 * must be equal to the sum of page counts specified in each
	 * `spci_memory_region_constituent`.
	 */
	uint32_t page_count;
	/**
	 * The number of constituents (`spci_memory_region_constituent`)
	 * included in this memory region range.
	 */
	uint32_t constituent_count;
	/** Reserved field, must be 0. */
	uint32_t reserved_1;
	/** An array of `constituent_count` memory region constituents. */
	struct spci_memory_region_constituent constituents[];
};

/**
 * Descriptor used for SPCI_MEM_RETRIEVE_RESP. This corresponds to table 143 of
 * the SPCI beta specification, "Encoding of mapped address ranges of retrieved
 * memory region".
 */
struct spci_retrieved_memory_region {
	/**
	 * The number of `spci_receiver_address_range` entries included
	 * in this memory region.
	 */
	uint32_t receiver_count;
	/** Reserved field, must be 0. */
	uint32_t reserved_0;
	/** Reserved field, must be 0. */
	uint64_t reserved_1;
	/*
	 * 'Array' of `struct spci_receiver_address_range` goes here, but it is
	 * not included in the struct as the entries are variable length. Use
	 * `spci_retrieved_memory_region_first_receiver_range` to get the first
	 * one.
	 */
};

/**
 * Descriptor used for SPCI_MEM_RELINQUISH requests. This corresponds to table
 * 146 of the SPCI beta specification, "Descriptor to relinquish a memory
 * region".
 */
struct spci_mem_relinquish {
	spci_memory_handle_t handle;
	uint32_t flags;
	spci_vm_id_t sender;
	uint16_t reserved;
	uint32_t endpoint_count;
	spci_vm_id_t endpoints[];
};

static inline struct spci_memory_region_constituent
spci_memory_region_constituent_init(uint64_t address, uint32_t page_count)
{
	return (struct spci_memory_region_constituent){
		.address_high = (uint32_t)(address >> 32),
		.address_low = (uint32_t)address,
		.page_count = page_count,
	};
}

static inline uint64_t spci_memory_region_constituent_get_address(
	struct spci_memory_region_constituent *constituent)
{
	return (uint64_t)constituent->address_high << 32 |
	       constituent->address_low;
}

/**
 * Gets the constituent array for an `spci_memory_region`.
 */
static inline struct spci_memory_region_constituent *
spci_memory_region_get_constituents(struct spci_memory_region *memory_region)
{
	return (struct spci_memory_region_constituent
			*)((uint8_t *)memory_region +
			   memory_region->constituent_offset);
}

/**
 * Gets the first descriptor with address ranges of a retrieved memory region.
 *
 * Note that getting the second requires parsing the first, as they are variable
 * length due to the variable number of constituents.
 */
static inline struct spci_receiver_address_range *
spci_retrieved_memory_region_first_receiver_range(
	struct spci_retrieved_memory_region *memory_region)
{
	return (struct spci_receiver_address_range *)(memory_region + 1);
}

/**
 * Gets the first retrieval attributes descriptor of a memory region retrieval
 * request.
 *
 * Note that getting the second requires parsing the first, as they are variable
 * length due to the variable number of constituents.
 */
static inline struct spci_memory_retrieve_properties *
spci_memory_retrieve_request_first_retrieve_properties(
	struct spci_memory_retrieve_request *retrieve_request)
{
	return (struct spci_memory_retrieve_properties *)(retrieve_request + 1);
}

uint32_t spci_memory_region_init(
	struct spci_memory_region *memory_region, spci_vm_id_t sender,
	spci_vm_id_t receiver,
	const struct spci_memory_region_constituent constituents[],
	uint32_t constituent_count, uint32_t tag,
	spci_memory_region_flags_t flags, enum spci_memory_access access,
	enum spci_memory_type type, enum spci_memory_cacheability cacheability,
	enum spci_memory_shareability shareability);
uint32_t spci_memory_retrieve_request_init(
	struct spci_memory_retrieve_request *request,
	spci_memory_handle_t handle, spci_vm_id_t sender, spci_vm_id_t receiver,
	uint32_t share_func, uint32_t tag, uint32_t page_count,
	enum spci_memory_access access, enum spci_memory_type type,
	enum spci_memory_cacheability cacheability,
	enum spci_memory_shareability shareability);
uint32_t spci_retrieved_memory_region_init(
	struct spci_retrieved_memory_region *response, size_t response_max_size,
	spci_vm_id_t receiver,
	const struct spci_memory_region_constituent constituents[],
	uint32_t constituent_count, uint32_t page_count);
