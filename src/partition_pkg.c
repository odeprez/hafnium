/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/partition_pkg.h"

#include <stdint.h>

#include "hf/arch/std.h"

#include "hf/addr.h"
#include "hf/check.h"
#include "hf/dlog.h"
#include "hf/mm.h"
#include "hf/sp_pkg.h"
#include "hf/std.h"
#include "hf/transfer_list.h"

static void dump_partition_package(struct partition_pkg *pkg)
{
	dlog_verbose("%s: pm: %lx %lx\n", __func__, pa_addr(pkg->pm.begin),
		     pa_addr(pkg->pm.end));
	dlog_verbose("%s: img: %lx %lx\n", __func__, pa_addr(pkg->img.begin),
		     pa_addr(pkg->img.end));
	dlog_verbose("%s: boot_info: %lx %lx\n", __func__,
		     pa_addr(pkg->boot_info.begin),
		     pa_addr(pkg->boot_info.end));
	dlog_verbose("%s: total %lx %lx\n", __func__, pa_addr(pkg->total.begin),
		     pa_addr(pkg->total.end));
}

static bool partition_pkg_from_sp_pkg(struct mm_stage1_locked stage1_locked,
				      paddr_t pkg_start,
				      struct partition_pkg *pkg,
				      struct mpool *ppool)
{
	struct sp_pkg_header header;
	bool ret = sp_pkg_init(stage1_locked, pkg_start, &header, ppool);
	size_t total_mem_size = sp_pkg_get_mem_size(&header);

	pkg->total.begin = pkg_start;
	pkg->total.end = pa_add(pkg_start, total_mem_size);

	pkg->pm.begin = pa_add(pkg_start, header.pm_offset);
	pkg->pm.end = pa_add(pkg->pm.begin, header.pm_size);

	pkg->img.begin = pa_add(pkg_start, header.img_offset);
	pkg->img.end = pa_add(pkg->img.begin, header.img_size);

	pkg->boot_info.begin = pkg_start;
	pkg->boot_info.end = pa_add(pkg_start, header.pm_offset);

	pkg->hob.begin = pa_init(0);
	pkg->hob.end = pa_init(0);

	dump_partition_package(pkg);

	/* Map the whole package as RO. */
	CHECK(mm_identity_map(stage1_locked, pkg->total.begin, pkg->total.end,
			      MM_MODE_R, ppool) != NULL);

	/* Map Boot info section as RW. */
	if (pa_addr(pkg->boot_info.begin) != 0U &&
	    pa_addr(pkg->boot_info.end) != 0U) {
		CHECK(mm_identity_map(stage1_locked, pkg->boot_info.begin,
				      pkg->boot_info.end, MM_MODE_R | MM_MODE_W,
				      ppool) != NULL);
	}

	return ret;
}

/**
 * Fetches the data from a Transfer Entry and expects it to be page aligned.
 * Returns false if the data is NULL.
 */
static bool partition_pkg_init_memory_range_from_te(
	struct mem_range *mem_range, struct transfer_list_entry *te)
{
	void *te_data;

	assert(mem_range != NULL);

	te_data = transfer_list_entry_data(te);

	if (te == NULL || te_data == NULL) {
		mem_range->begin = pa_init(0);
		mem_range->end = pa_init(0);
		return false;
	}

	mem_range->begin = pa_from_va(va_init((uintptr_t)te_data));
	mem_range->end = pa_add(mem_range->begin, te->data_size);

	return true;
}

static bool partition_pkg_is_range_page_aligned(struct mem_range *range)
{
	return (pa_addr(range->begin) % PAGE_SIZE) == 0U;
}

static bool partition_pkg_from_tl(struct mm_stage1_locked stage1_locked,
				  paddr_t pkg_start, struct partition_pkg *pkg,
				  struct mpool *ppool)
{
	struct transfer_list_header *tl = ptr_from_va(va_from_pa(pkg_start));

	dlog_verbose("%s: partition loaded in a transfer list.\n", __func__);

	/* The total memory for the partition package. */
	pkg->total.begin = pkg_start;
	pkg->total.end = pa_add(pkg_start, tl->size);

	/* Map the whole TL as RO. */
	CHECK(mm_identity_map(stage1_locked, pkg->total.begin, pkg->total.end,
			      MM_MODE_R, ppool));

	if (transfer_list_check_header(tl) == TL_OPS_NON) {
		return false;
	}

	/*
	 * Get the memory ranges from the TL for:
	 * - FFA_MANIFEST.
	 * - Partition Image.
	 * - Boot info descriptors: This reuses a voided entry.
	 */
	if (!partition_pkg_init_memory_range_from_te(
		    &(pkg->pm),
		    transfer_list_find(tl, TL_TAG_DT_FFA_MANIFEST)) ||
	    !partition_pkg_init_memory_range_from_te(
		    &(pkg->img),
		    transfer_list_find(tl, TL_TAG_FFA_SP_BINARY))) {
		return false;
	}

	partition_pkg_init_memory_range_from_te(
		&(pkg->hob), transfer_list_find(tl, TL_TAG_HOB_LIST));

	if (!partition_pkg_is_range_page_aligned(&pkg->pm)) {
		dlog_error(
			"%s: the partition manifest range must be 4k page "
			"aligned.\n",
			__func__);
		return false;
	}

	if (!partition_pkg_is_range_page_aligned(&pkg->img)) {
		dlog_error(
			"%s: the partition image range must be 4k page "
			"aligned.\n",
			__func__);
		return false;
	}

	/*
	 * For the boot information descriptor, repurpose the TL's first page.
	 * The TL is only processed by Hafnium, and all items are placed at
	 * a Page aligned offset.
	 * At this point, all references to artefacts in the TL have been
	 * obtained so the first page of the package can be repurposed to the
	 * FF-A boot information. There is not expectation that the first page
	 * won't suffice for the time being. If it does get full, Hafnium will
	 * fail at populating the boot info descriptors.
	 */
	pkg->boot_info.begin = pkg_start;
	pkg->boot_info.end = pa_add(pkg_start, PAGE_SIZE);

	/* Map the boot info region as RW. */
	CHECK(mm_identity_map(stage1_locked, pkg->boot_info.begin,
			      pkg->boot_info.end, MM_MODE_R | MM_MODE_W,
			      ppool));

	dump_partition_package(pkg);

	return true;
}

bool partition_pkg_init(struct mm_stage1_locked stage1_locked,
			paddr_t pkg_start, struct partition_pkg *pkg,
			struct mpool *ppool)
{
	bool ret = false;
	paddr_t pkg_end = pa_add(pkg_start, PAGE_SIZE);
	uint32_t *magic;
	void *mapped_ptr;

	/* Firstly, map a single page to be able to read package header. */
	mapped_ptr = mm_identity_map(stage1_locked, pkg_start, pkg_end,
				     MM_MODE_R, ppool);
	assert(pkg != NULL);

	magic = (uint32_t *)mapped_ptr;

	switch (*magic) {
	case SP_PKG_HEADER_MAGIC:
		if (partition_pkg_from_sp_pkg(stage1_locked, pkg_start, pkg,
					      ppool)) {
			return true;
		}
		break;
	case TRANSFER_LIST_SIGNATURE:
		if (partition_pkg_from_tl(stage1_locked, pkg_start, pkg,
					  ppool)) {
			return true;
		}
		break;
	default:
		dlog_error("%s: invalid secure partition package %x\n",
			   __func__, *magic);
	}

	/* If failing unmap the memory. */
	if (!ret) {
		CHECK(mm_unmap(stage1_locked, pkg_start, pkg_end, ppool));
	}

	return false;
}

void partition_pkg_deinit(struct mm_stage1_locked stage1_locked,
			  struct partition_pkg *pkg, struct mpool *ppool)
{
	CHECK(mm_unmap(stage1_locked, pkg->total.begin, pkg->total.end, ppool));
}
