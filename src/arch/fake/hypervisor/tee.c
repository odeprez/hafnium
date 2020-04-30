/*
 * Copyright 2020 The Hafnium Authors.
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

#include "hf/arch/tee.h"

#include "hf/dlog.h"
#include "hf/ffa.h"
#include "hf/ffa_internal.h"

struct ffa_value arch_tee_call(struct ffa_value args)
{
	dlog_error("Attempted to call TEE function %#x\n", args.func);
	return ffa_error(FFA_NOT_SUPPORTED);
}
