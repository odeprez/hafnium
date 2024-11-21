/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "int_state.h"

void hftest_ipi_init_state_default(void);
void hftest_ipi_state_share_page_and_init(uint64_t page,
					  ffa_id_t receivers_ids[],
					  size_t receivers_count,
					  void *send_buf);
void hftest_ipi_init_state_from_message(void *recv_buf, void *send_buf);
bool hftest_ipi_state_is(enum int_state to_check);
void hftest_ipi_state_set(enum int_state to_set);
