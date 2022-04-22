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
#include "hf/memiter.h"
#include "hf/std.h"

#include "vmapi/hf/ffa.h"

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

	assert(boot_info_node != NULL);
	assert(sp_pkg != NULL);

	(void)sp_pkg_addr;
	(void)header;
	(void)sp_pkg;

	if (!fdt_is_compatible(boot_info_node, "arm,ffa-manifest-boot-info")) {
		dlog_verbose("The node 'boot-info' is not compatible.\n");
		return false;
	}

	dlog_verbose("  FF-A Boot Info:\n");

	if (fdt_read_property(boot_info_node, "ffa_manifest", &data) &&
	    memiter_size(&data) == 0U) {
		dlog_verbose("    FF-A Manifest\n");
		return true;
	}

	return false;
}
