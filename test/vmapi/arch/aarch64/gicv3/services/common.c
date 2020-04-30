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

#include "common.h"

#include "vmapi/hf/call.h"

#include "test/hftest.h"

/**
 * Try to receive a message from the mailbox, blocking if necessary, and
 * retrying if interrupted.
 */
struct ffa_value mailbox_receive_retry(void)
{
	struct ffa_value received;

	do {
		received = ffa_msg_wait();
	} while (received.func == FFA_ERROR_32 &&
		 received.arg2 == FFA_INTERRUPTED);

	return received;
}
