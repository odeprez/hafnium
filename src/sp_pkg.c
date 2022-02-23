/*
 * Copyright 2022 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/sp_pkg.h"

#include <stdint.h>

#include "hf/arch/std.h"

#include "hf/addr.h"
#include "hf/check.h"
#include "hf/dlog.h"
#include "hf/std.h"

/*
 * Function initializes the Secure Partition Package:
 * - Maps whole region up to image such that Hafnium can parse the FF-A manifest
 * and can use the first chunk of memory for booting purposes.
 */
bool sp_pkg_init(struct mm_stage1_locked stage1_locked,
		 struct sp_pkg_header *sp_pkg, vaddr_t *sp_pkg_start,
		 void **pm_address, uintptr_t load_addr, struct mpool *ppool)
{
	paddr_t to_map_start;
	paddr_t to_map_end;
	paddr_t to_unmap_end;
	paddr_t to_unmap_start;
	bool ret = false;
	void *sp_pkg_addr;

	assert(sp_pkg != NULL);
	assert(pm_address != NULL);

	/* Map top of package as a single page to extract the header. */
	to_map_start = pa_init(load_addr);
	to_map_end = pa_add(to_map_start, PAGE_SIZE);

	/* Prepare addresses for possible unmap operation in 'exit_unmap'. */
	to_unmap_start = to_map_start;
	to_unmap_end = to_map_end;

	/* Map SP pkg header first. */
	sp_pkg_addr = mm_identity_map(stage1_locked, to_map_start, to_map_end,
				      MM_MODE_R | MM_MODE_W, ppool);

	assert(sp_pkg_addr != NULL);

	memcpy_s(sp_pkg, sizeof(struct sp_pkg_header), sp_pkg_addr,
		 sizeof(struct sp_pkg_header));

	*sp_pkg_start = va_from_ptr(sp_pkg_addr);

	/* Validate the header. */
	if (sp_pkg->magic != SP_PKG_HEADER_MAGIC) {
		dlog_error("Invalid package magic.\n");
		goto exit_unmap;
	}

	if (sp_pkg->version != SP_PKG_HEADER_VERSION) {
		dlog_error("Invalid package version.\n");
		goto exit_unmap;
	}

	if (sp_pkg->pm_offset % PAGE_SIZE != 0 ||
	    sp_pkg->img_offset % PAGE_SIZE != 0) {
		dlog_error("SP pkg offsets are not page aligned.\n");
		goto exit_unmap;
	}

	if (sp_pkg->pm_offset > sp_pkg->img_offset) {
		dlog_error(
			"SP pkg offsets must be in order: boot info < "
			"partition manifest < image offset.\n");
		goto exit_unmap;
	}

	/*
	 * Check for overflow and then check the pm shouldn't override the
	 * image.
	 */
	assert(UINT32_MAX - sp_pkg->pm_offset >= sp_pkg->pm_size);
	if (sp_pkg->pm_offset + sp_pkg->pm_size > sp_pkg->img_offset) {
		dlog_error("Partition manifest bigger than its region.\n");
		goto exit_unmap;
	}

	/*
	 * Remap section up to pm as RW, to allow for writing of boot info
	 * descriptors, if the SP specified boot info in its manifest.
	 */
	if (sp_pkg->pm_offset > PAGE_SIZE) {
		to_map_end = pa_add(to_map_start, sp_pkg->pm_offset);
		CHECK(mm_identity_map(stage1_locked, to_map_start, to_map_end,
				      MM_MODE_R | MM_MODE_W, ppool) != NULL);
	}

	/* Map partition manifest. */
	to_map_start = to_map_end;
	to_map_end = pa_add(to_map_start, sp_pkg->pm_size);
	to_unmap_end = to_map_end;

	*pm_address = mm_identity_map(stage1_locked, to_map_start, to_map_end,
				      MM_MODE_R, ppool);
	CHECK(*pm_address != NULL);

	ret = true;

exit_unmap:
	if (!ret) {
		CHECK(mm_unmap(stage1_locked, to_unmap_start, to_unmap_end,
			       ppool));
	}

	return ret;
}

/**
 * Unmap SP Pkg from Hafnium's address space.
 */
void sp_pkg_deinit(struct mm_stage1_locked stage1_locked,
		   struct sp_pkg_header *sp_pkg, vaddr_t sp_pkg_start,
		   struct mpool *ppool)
{
	paddr_t to_unmap_end;

	to_unmap_end = pa_from_va(
		va_add(sp_pkg_start, sp_pkg->pm_offset + sp_pkg->pm_size));

	CHECK(mm_unmap(stage1_locked, pa_from_va(sp_pkg_start), to_unmap_end,
		       ppool));
}
