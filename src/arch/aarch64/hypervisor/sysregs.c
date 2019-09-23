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

#include "sysregs.h"

#include "hf/check.h"
#include "hf/dlog.h"
#include "hf/panic.h"
#include "hf/types.h"

#include "msr.h"

/**
 * Returns the value for MDCR_EL2 for the particular VM.
 * For now, the primary VM has one value and all secondary VMs share a value.
 */
uintreg_t get_mdcr_el2_value(spci_vm_id_t vm_id)
{
	uintreg_t mdcr_el2_value = read_msr(MDCR_EL2);
	uintreg_t pmcr_el0 = read_msr(PMCR_EL0);

	/*
	 * Preserve E2PB for now, which depends on the SPE implementation.
	 * TODO: Investigate how to detect whether SPE is implemented, and which
	 * stage's translation regime is applicable, i.e., EL2 or EL1.
	 */
	mdcr_el2_value &= MDCR_EL2_E2PB;

	/*
	 * Trap all VM accesses to debug registers for fine-grained control.
	 * Do not trap the Primary VM's debug events, e.g., watchpoint or
	 * breakpoint events (!MDCR_EL2_TDE).
	 */
	mdcr_el2_value |=
		MDCR_EL2_TTRF | MDCR_EL2_TDRA | MDCR_EL2_TDOSA | MDCR_EL2_TDA;

	if (vm_id != HF_PRIMARY_VM_ID) {
		/*
		 * Debug event exceptions should be disabled in secondary VMs
		 * but trap them for additional security.
		 */
		mdcr_el2_value |= MDCR_EL2_TDE;
	}

	/* All available event counters accessible from all exception levels. */
	mdcr_el2_value |= GET_PMCR_EL0_N(pmcr_el0) & MDCR_EL2_HPMN;

	return mdcr_el2_value;
}
