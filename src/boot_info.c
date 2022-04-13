/*
 * Copyright 2022 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/boot_info.h"

#include "hf/assert.h"
#include "hf/dlog.h"
#include "hf/ffa.h"
#include "hf/memiter.h"
#include "hf/std.h"

#include "vmapi/hf/ffa.h"

/**
 * Initializes the ffa_boot_info_header in accordance to the specification.
 */
static void ffa_boot_info_header_init(struct ffa_boot_info_header *header,
				      size_t blob_size)
{
	assert(header != NULL);
	assert(blob_size != 0U);

	header->signature = FFA_BOOT_INFO_SIG;
	header->version = FFA_BOOT_INFO_VERSION;
	header->info_blob_size = blob_size;
	header->desc_size = sizeof(struct ffa_boot_info_desc);
	header->desc_count = 0;
	header->desc_offset =
		(uint32_t)offsetof(struct ffa_boot_info_header, boot_info);
	header->reserved = 0U;
}

static void ffa_boot_info_desc_init(struct ffa_boot_info_desc *info_desc,
				    uint8_t content_format, bool std_type,
				    uint8_t type_id, uint32_t size,
				    uint64_t content)
{
	assert(info_desc != NULL);

	/*
	 * Init name size with 0s, as it is currently unused. Data can be
	 * identified checking the type field.
	 */
	memset_s(info_desc, FFA_BOOT_INFO_NAME_LEN, 0, FFA_BOOT_INFO_NAME_LEN);

	info_desc->type = std_type == true ? FFA_BOOT_INFO_TYPE_STD
					   : FFA_BOOT_INFO_TYPE_IMPDEF;
	info_desc->type <<= FFA_BOOT_INFO_TYPE_SHIFT;
	info_desc->type |= (type_id & FFA_BOOT_INFO_TYPE_ID_MASK);

	info_desc->reserved = 0U;
	info_desc->flags =
		((content_format << FFA_BOOT_INFO_FLAG_CONTENT_FORMAT_SHIFT) &
		 FFA_BOOT_INFO_FLAG_CONTENT_FORMAT_MASK);
	info_desc->size = size;
	info_desc->content = content;
}

/*
 * Write initialization parameter to the boot info descriptor array.
 */
static void boot_info_write_desc(struct ffa_boot_info_header *header,
				 uint8_t content_format, bool std_type,
				 uint8_t type_id, uint32_t size,
				 uint64_t content,
				 const size_t max_info_desc_count)
{
	assert(header != NULL);

	/* Check that writing the data won't surpass the blob memory limit. */
	if (header->desc_count >= max_info_desc_count) {
		dlog_error(
			"Boot info memory is full. No space for a "
			"descriptor.\n");
		return;
	}

	ffa_boot_info_desc_init(&header->boot_info[header->desc_count],
				content_format, std_type, type_id, size,
				content);

	header->desc_count++;
}

/**
 * Looks for the FF-A manifest boot information node, and writes the
 * requested information into the boot info memory.
 */
bool ffa_boot_info_node(struct fdt_node *boot_info_node,
			uintpaddr_t sp_pkg_addr,
			struct ffa_boot_info_header *header,
			struct sp_pkg_header *sp_pkg)
{
	struct memiter data;
	const size_t boot_info_size = sp_pkg_get_boot_info_size(sp_pkg);
	const size_t max_boot_info_desc_count =
		boot_info_size / sizeof(struct ffa_boot_info_desc);

	assert(boot_info_node != NULL);
	assert(header != NULL);
	assert(sp_pkg != NULL);

	/*
	 * FF-A v1.1 EAC0 specification states the region for the boot info
	 * descriptors, and the contents of the boot info shall be contiguous.
	 * Together they constitute the boot info blob. The are for the boot
	 * info blob is allocated in the SP's respective package.
	 * Retrieve from the SP package the size of the region for the boot info
	 * descriptors. The size of boot info contents to be incremented,
	 * depending on the info specified in the partition's FF-A manifest.
	 */
	ffa_boot_info_header_init(header, boot_info_size);

	if (!fdt_is_compatible(boot_info_node, "arm,ffa-manifest-boot-info")) {
		dlog_verbose("The node 'boot-info' is not compatible.\n");
		return false;
	}

	dlog_verbose("  FF-A Boot Info:\n");

	if (fdt_read_property(boot_info_node, "ffa_manifest", &data) &&
	    memiter_size(&data) == 0U) {
		ipaddr_t load_addr = ipa_init(sp_pkg_addr);
		ipaddr_t pm_addr = ipa_add(load_addr, sp_pkg->pm_offset);

		dlog_verbose("    FF-A Manifest\n");
		boot_info_write_desc(
			header, FFA_BOOT_INFO_FLAG_CONTENT_FORMAT_ADDR, true,
			FFA_BOOT_INFO_TYPE_ID_FDT, sp_pkg->pm_size,
			ipa_addr(pm_addr), max_boot_info_desc_count);

		/*
		 * Incrementing the size of the boot information blob with the
		 * size of the partition's manifest.
		 */
		header->info_blob_size += sp_pkg->pm_size;

		/*
		 * Flush the data cache in case partition initializes with
		 * caches disabled.
		 */
		arch_mm_flush_dcache((void *)header, header->info_blob_size);
		return true;
	}

	return false;
}
