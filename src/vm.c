/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/vm.h"

#include "hf/api.h"
#include "hf/assert.h"
#include "hf/check.h"
#include "hf/cpu.h"
#include "hf/dlog.h"
#include "hf/ffa.h"
#include "hf/layout.h"
#include "hf/plat/iommu.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

static struct vm vms[MAX_VMS];
static struct vm other_world;
static ffa_vm_count_t vm_count;
static struct vm *first_boot_vm;

/**
 * Counters on the status of notifications in the system. It helps to improve
 * the information retrieved by the receiver scheduler.
 */
static struct {
	/** Counts notifications pending. */
	uint32_t pending_count;
	/**
	 * Counts notifications pending, that have been retrieved by the
	 * receiver scheduler.
	 */
	uint32_t info_get_retrieved_count;
	struct spinlock lock;
} all_notifications_state;

static bool vm_init_mm(struct vm *vm, struct mpool *ppool)
{
	if (vm->el0_partition) {
		return mm_ptable_init(&vm->ptable, vm->id, MM_FLAG_STAGE1,
				      ppool);
	}
	return mm_vm_init(&vm->ptable, vm->id, ppool);
}

struct vm *vm_init(ffa_vm_id_t id, ffa_vcpu_count_t vcpu_count,
		   struct mpool *ppool, bool el0_partition)
{
	uint32_t i;
	struct vm *vm;

	if (id == HF_OTHER_WORLD_ID) {
		CHECK(el0_partition == false);
		vm = &other_world;
	} else {
		uint16_t vm_index = id - HF_VM_ID_OFFSET;

		CHECK(id >= HF_VM_ID_OFFSET);
		CHECK(vm_index < ARRAY_SIZE(vms));
		vm = &vms[vm_index];
	}

	memset_s(vm, sizeof(*vm), 0, sizeof(*vm));

	list_init(&vm->mailbox.waiter_list);
	list_init(&vm->mailbox.ready_list);
	sl_init(&vm->lock);

	vm->id = id;
	vm->vcpu_count = vcpu_count;
	vm->mailbox.state = MAILBOX_STATE_EMPTY;
	atomic_init(&vm->aborting, false);
	vm->el0_partition = el0_partition;

	if (!vm_init_mm(vm, ppool)) {
		return NULL;
	}

	/* Initialise waiter entries. */
	for (i = 0; i < MAX_VMS; i++) {
		vm->wait_entries[i].waiting_vm = vm;
		list_init(&vm->wait_entries[i].wait_links);
		list_init(&vm->wait_entries[i].ready_links);
	}

	/* Do basic initialization of vCPUs. */
	for (i = 0; i < vcpu_count; i++) {
		vcpu_init(vm_get_vcpu(vm, i), vm);
	}

	/* Basic initialization of the notifications structure. */
	vm_notifications_init_bindings(&vm->notifications.from_sp);
	vm_notifications_init_bindings(&vm->notifications.from_vm);

	return vm;
}

bool vm_init_next(ffa_vcpu_count_t vcpu_count, struct mpool *ppool,
		  struct vm **new_vm, bool el0_partition)
{
	if (vm_count >= MAX_VMS) {
		return false;
	}

	/* Generate IDs based on an offset, as low IDs e.g., 0, are reserved */
	*new_vm = vm_init(vm_count + HF_VM_ID_OFFSET, vcpu_count, ppool,
			  el0_partition);
	if (*new_vm == NULL) {
		return false;
	}
	++vm_count;

	return true;
}

ffa_vm_count_t vm_get_count(void)
{
	return vm_count;
}

/**
 * Returns a pointer to the VM with the corresponding id.
 */
struct vm *vm_find(ffa_vm_id_t id)
{
	uint16_t index;

	if (id == HF_OTHER_WORLD_ID) {
		if (other_world.id == HF_OTHER_WORLD_ID) {
			return &other_world;
		}
		return NULL;
	}

	/* Check that this is not a reserved ID. */
	if (id < HF_VM_ID_OFFSET) {
		return NULL;
	}

	index = id - HF_VM_ID_OFFSET;

	return vm_find_index(index);
}

/**
 * Returns a locked instance of the VM with the corresponding id.
 */
struct vm_locked vm_find_locked(ffa_vm_id_t id)
{
	struct vm *vm = vm_find(id);

	if (vm != NULL) {
		return vm_lock(vm);
	}

	return (struct vm_locked){.vm = NULL};
}

/**
 * Returns a pointer to the VM at the specified index.
 */
struct vm *vm_find_index(uint16_t index)
{
	/* Ensure the VM is initialized. */
	if (index >= vm_count) {
		return NULL;
	}

	return &vms[index];
}

/**
 * Locks the given VM and updates `locked` to hold the newly locked VM.
 */
struct vm_locked vm_lock(struct vm *vm)
{
	struct vm_locked locked = {
		.vm = vm,
	};

	sl_lock(&vm->lock);

	return locked;
}

/**
 * Locks two VMs ensuring that the locking order is according to the locks'
 * addresses.
 */
struct two_vm_locked vm_lock_both(struct vm *vm1, struct vm *vm2)
{
	struct two_vm_locked dual_lock;

	sl_lock_both(&vm1->lock, &vm2->lock);
	dual_lock.vm1.vm = vm1;
	dual_lock.vm2.vm = vm2;

	return dual_lock;
}

/**
 * Unlocks a VM previously locked with vm_lock, and updates `locked` to reflect
 * the fact that the VM is no longer locked.
 */
void vm_unlock(struct vm_locked *locked)
{
	sl_unlock(&locked->vm->lock);
	locked->vm = NULL;
}

/**
 * Get the vCPU with the given index from the given VM.
 * This assumes the index is valid, i.e. less than vm->vcpu_count.
 */
struct vcpu *vm_get_vcpu(struct vm *vm, ffa_vcpu_index_t vcpu_index)
{
	CHECK(vcpu_index < vm->vcpu_count);
	return &vm->vcpus[vcpu_index];
}

/**
 * Gets `vm`'s wait entry for waiting on the `for_vm`.
 */
struct wait_entry *vm_get_wait_entry(struct vm *vm, ffa_vm_id_t for_vm)
{
	uint16_t index;

	CHECK(for_vm >= HF_VM_ID_OFFSET);
	index = for_vm - HF_VM_ID_OFFSET;
	CHECK(index < MAX_VMS);

	return &vm->wait_entries[index];
}

/**
 * Gets the ID of the VM which the given VM's wait entry is for.
 */
ffa_vm_id_t vm_id_for_wait_entry(struct vm *vm, struct wait_entry *entry)
{
	uint16_t index = entry - vm->wait_entries;

	return index + HF_VM_ID_OFFSET;
}

/**
 * Return whether the given VM ID represents an entity in the current world:
 * i.e. the hypervisor or a normal world VM when running in the normal world, or
 * the SPM or an SP when running in the secure world.
 */
bool vm_id_is_current_world(ffa_vm_id_t vm_id)
{
	return (vm_id & HF_VM_ID_WORLD_MASK) !=
	       (HF_OTHER_WORLD_ID & HF_VM_ID_WORLD_MASK);
}

/**
 * Map a range of addresses to the VM in both the MMU and the IOMMU.
 *
 * mm_vm_defrag should always be called after a series of page table updates,
 * whether they succeed or fail. This is because on failure extra page table
 * entries may have been allocated and then not used, while on success it may be
 * possible to compact the page table by merging several entries into a block.
 *
 * Returns true on success, or false if the update failed and no changes were
 * made.
 *
 */
bool vm_identity_map(struct vm_locked vm_locked, paddr_t begin, paddr_t end,
		     uint32_t mode, struct mpool *ppool, ipaddr_t *ipa)
{
	if (!vm_identity_prepare(vm_locked, begin, end, mode, ppool)) {
		return false;
	}

	vm_identity_commit(vm_locked, begin, end, mode, ppool, ipa);

	return true;
}

/**
 * Prepares the given VM for the given address mapping such that it will be able
 * to commit the change without failure.
 *
 * In particular, multiple calls to this function will result in the
 * corresponding calls to commit the changes to succeed.
 *
 * Returns true on success, or false if the update failed and no changes were
 * made.
 */
bool vm_identity_prepare(struct vm_locked vm_locked, paddr_t begin, paddr_t end,
			 uint32_t mode, struct mpool *ppool)
{
	if (vm_locked.vm->el0_partition) {
		return mm_identity_prepare(&vm_locked.vm->ptable, begin, end,
					   mode, ppool);
	}
	return mm_vm_identity_prepare(&vm_locked.vm->ptable, begin, end, mode,
				      ppool);
}

/**
 * Commits the given address mapping to the VM assuming the operation cannot
 * fail. `vm_identity_prepare` must used correctly before this to ensure
 * this condition.
 */
void vm_identity_commit(struct vm_locked vm_locked, paddr_t begin, paddr_t end,
			uint32_t mode, struct mpool *ppool, ipaddr_t *ipa)
{
	if (vm_locked.vm->el0_partition) {
		mm_identity_commit(&vm_locked.vm->ptable, begin, end, mode,
				   ppool);
		if (ipa != NULL) {
			/*
			 * EL0 partitions are modeled as lightweight VM's, to
			 * promote code reuse. The below statement returns the
			 * mapped PA as an IPA, however, for an EL0 partition,
			 * this is really a VA.
			 */
			*ipa = ipa_from_pa(begin);
		}
	} else {
		mm_vm_identity_commit(&vm_locked.vm->ptable, begin, end, mode,
				      ppool, ipa);
	}
	plat_iommu_identity_map(vm_locked, begin, end, mode);
}

/**
 * Unmap a range of addresses from the VM.
 *
 * Returns true on success, or false if the update failed and no changes were
 * made.
 */
bool vm_unmap(struct vm_locked vm_locked, paddr_t begin, paddr_t end,
	      struct mpool *ppool)
{
	uint32_t mode = MM_MODE_UNMAPPED_MASK;

	return vm_identity_map(vm_locked, begin, end, mode, ppool, NULL);
}

/**
 * Defrag page tables for an EL0 partition or for a VM.
 */
void vm_ptable_defrag(struct vm_locked vm_locked, struct mpool *ppool)
{
	if (vm_locked.vm->el0_partition) {
		mm_stage1_defrag(&vm_locked.vm->ptable, ppool);
	} else {
		mm_vm_defrag(&vm_locked.vm->ptable, ppool);
	}
}

/**
 * Unmaps the hypervisor pages from the given page table.
 */
bool vm_unmap_hypervisor(struct vm_locked vm_locked, struct mpool *ppool)
{
	/* TODO: If we add pages dynamically, they must be included here too. */
	return vm_unmap(vm_locked, layout_text_begin(), layout_text_end(),
			ppool) &&
	       vm_unmap(vm_locked, layout_rodata_begin(), layout_rodata_end(),
			ppool) &&
	       vm_unmap(vm_locked, layout_data_begin(), layout_data_end(),
			ppool);
}

/**
 * Gets the first partition to boot, according to Boot Protocol from FFA spec.
 */
struct vm *vm_get_first_boot(void)
{
	return first_boot_vm;
}

/**
 * Insert in boot list, sorted by `boot_order` parameter in the vm structure
 * and rooted in `first_boot_vm`.
 */
void vm_update_boot(struct vm *vm)
{
	struct vm *current = NULL;
	struct vm *previous = NULL;

	if (first_boot_vm == NULL) {
		first_boot_vm = vm;
		return;
	}

	current = first_boot_vm;

	while (current != NULL && current->boot_order <= vm->boot_order) {
		previous = current;
		current = current->next_boot;
	}

	if (previous != NULL) {
		previous->next_boot = vm;
	} else {
		first_boot_vm = vm;
	}

	vm->next_boot = current;
}

/**
 * Gets the mode of the given range of ipa or va if they are mapped with the
 * same mode.
 *
 * Returns true if the range is mapped with the same mode and false otherwise.
 * The wrapper calls the appropriate mm function depending on if the partition
 * is a vm or a el0 partition.
 */
bool vm_mem_get_mode(struct vm_locked vm_locked, ipaddr_t begin, ipaddr_t end,
		     uint32_t *mode)
{
	if (vm_locked.vm->el0_partition) {
		return mm_get_mode(&vm_locked.vm->ptable,
				   va_from_pa(pa_from_ipa(begin)),
				   va_from_pa(pa_from_ipa(end)), mode);
	}
	return mm_vm_get_mode(&vm_locked.vm->ptable, begin, end, mode);
}

static struct notifications *vm_get_notifications(struct vm_locked vm_locked,
						  bool is_from_vm)
{
	return is_from_vm ? &vm_locked.vm->notifications.from_vm
			  : &vm_locked.vm->notifications.from_sp;
}

/*
 * Initializes the notifications structure.
 */
void vm_notifications_init_bindings(struct notifications *notifications)
{
	for (uint32_t i = 0U; i < MAX_FFA_NOTIFICATIONS; i++) {
		notifications->bindings_sender_id[i] = HF_INVALID_VM_ID;
	}
}

/**
 * Checks if there are pending notifications.
 */
bool vm_are_notifications_pending(struct vm_locked vm_locked, bool from_vm,
				  ffa_notifications_bitmap_t notifications)
{
	struct notifications *to_check;

	CHECK(vm_locked.vm != NULL);

	to_check = vm_get_notifications(vm_locked, from_vm);

	/* Check if there are pending per vcpu notifications */
	for (uint32_t i = 0U; i < MAX_CPUS; i++) {
		if ((to_check->per_vcpu[i].pending & notifications) != 0U) {
			return true;
		}
	}

	/* Check if there are global pending notifications */
	return (to_check->global.pending & notifications) != 0U;
}

/**
 * Checks if there are pending global notifications, either from SPs or from
 * VMs.
 */
bool vm_are_global_notifications_pending(struct vm_locked vm_locked)
{
	return vm_get_notifications(vm_locked, true)->global.pending != 0ULL ||
	       vm_get_notifications(vm_locked, false)->global.pending != 0ULL;
}

/**
 * Checks if there are pending per-vCPU notifications, in a specific vCPU either
 * from SPs or from VMs.
 */
bool vm_are_per_vcpu_notifications_pending(struct vm_locked vm_locked,
					   ffa_vcpu_index_t vcpu_id)
{
	CHECK(vcpu_id < MAX_CPUS);

	return vm_get_notifications(vm_locked, true)
			       ->per_vcpu[vcpu_id]
			       .pending != 0ULL ||
	       vm_get_notifications(vm_locked, false)
			       ->per_vcpu[vcpu_id]
			       .pending != 0ULL;
}

bool vm_are_notifications_enabled(struct vm *vm)
{
	return vm->notifications.enabled == true;
}

bool vm_locked_are_notifications_enabled(struct vm_locked vm_locked)
{
	return vm_are_notifications_enabled(vm_locked.vm);
}

static bool vm_is_notification_bit_set(ffa_notifications_bitmap_t notifications,
				       uint32_t i)
{
	return (notifications & FFA_NOTIFICATION_MASK(i)) != 0U;
}

static void vm_notifications_global_state_count_update(
	ffa_notifications_bitmap_t bitmap, uint32_t *counter, int inc)
{
	/*
	 * Helper to increment counters from global notifications
	 * state. Count update by increments or decrements of 1 or -1,
	 * respectively.
	 */
	assert(inc == 1 || inc == -1);

	sl_lock(&all_notifications_state.lock);

	for (uint32_t i = 0; i < MAX_FFA_NOTIFICATIONS; i++) {
		if (vm_is_notification_bit_set(bitmap, i)) {
			CHECK((inc > 0 && *counter < UINT32_MAX) ||
			      (inc < 0 && *counter > 0));
			*counter += inc;
		}
	}

	sl_unlock(&all_notifications_state.lock);
}

/**
 * Helper function to increment the pending notifications based on a bitmap
 * passed as argument.
 * Function to be used at setting notifications for a given VM.
 */
static void vm_notifications_pending_count_add(
	ffa_notifications_bitmap_t to_add)
{
	vm_notifications_global_state_count_update(
		to_add, &all_notifications_state.pending_count, 1);
}

/**
 * Helper function to decrement the pending notifications count.
 * Function to be used when getting the receiver's pending notifications.
 */
static void vm_notifications_pending_count_sub(
	ffa_notifications_bitmap_t to_sub)
{
	vm_notifications_global_state_count_update(
		to_sub, &all_notifications_state.pending_count, -1);
}

/**
 * Helper function to count the notifications whose information has been
 * retrieved by the scheduler of the system, and are still pending.
 */
static void vm_notifications_info_get_retrieved_count_add(
	ffa_notifications_bitmap_t to_add)
{
	vm_notifications_global_state_count_update(
		to_add, &all_notifications_state.info_get_retrieved_count, 1);
}

/**
 * Helper function to subtract the notifications that the receiver is getting
 * and whose information has been retrieved by the receiver scheduler.
 */
static void vm_notifications_info_get_retrieved_count_sub(
	ffa_notifications_bitmap_t to_sub)
{
	vm_notifications_global_state_count_update(
		to_sub, &all_notifications_state.info_get_retrieved_count, -1);
}

/**
 * Helper function to determine if there are notifications pending whose info
 * hasn't been retrieved by the receiver scheduler.
 */
bool vm_notifications_pending_not_retrieved_by_scheduler(void)
{
	bool ret;

	sl_lock(&all_notifications_state.lock);
	ret = all_notifications_state.pending_count >
	      all_notifications_state.info_get_retrieved_count;
	sl_unlock(&all_notifications_state.lock);

	return ret;
}

bool vm_is_notifications_pending_count_zero(void)
{
	bool ret;

	sl_lock(&all_notifications_state.lock);
	ret = all_notifications_state.pending_count == 0;
	sl_unlock(&all_notifications_state.lock);

	return ret;
}

/**
 * Checks that all provided notifications are bound to the specified sender, and
 * are per VCPU or global, as specified.
 */
bool vm_notifications_validate_binding(struct vm_locked vm_locked,
				       bool is_from_vm, ffa_vm_id_t sender_id,
				       ffa_notifications_bitmap_t notifications,
				       bool is_per_vcpu)
{
	return vm_notifications_validate_bound_sender(
		       vm_locked, is_from_vm, sender_id, notifications) &&
	       vm_notifications_validate_per_vcpu(vm_locked, is_from_vm,
						  is_per_vcpu, notifications);
}

/**
 * Update binds information in notification structure for the specified
 * notifications.
 */
void vm_notifications_update_bindings(struct vm_locked vm_locked,
				      bool is_from_vm, ffa_vm_id_t sender_id,
				      ffa_notifications_bitmap_t notifications,
				      bool is_per_vcpu)
{
	CHECK(vm_locked.vm != NULL);
	struct notifications *to_update =
		vm_get_notifications(vm_locked, is_from_vm);

	for (uint32_t i = 0; i < MAX_FFA_NOTIFICATIONS; i++) {
		if (vm_is_notification_bit_set(notifications, i)) {
			to_update->bindings_sender_id[i] = sender_id;
		}
	}

	/*
	 * Set notifications if they are per VCPU, else clear them as they are
	 * global.
	 */
	if (is_per_vcpu) {
		to_update->bindings_per_vcpu |= notifications;
	} else {
		to_update->bindings_per_vcpu &= ~notifications;
	}
}

bool vm_notifications_validate_bound_sender(
	struct vm_locked vm_locked, bool is_from_vm, ffa_vm_id_t sender_id,
	ffa_notifications_bitmap_t notifications)
{
	CHECK(vm_locked.vm != NULL);
	struct notifications *to_check =
		vm_get_notifications(vm_locked, is_from_vm);

	for (uint32_t i = 0; i < MAX_FFA_NOTIFICATIONS; i++) {
		if (vm_is_notification_bit_set(notifications, i) &&
		    to_check->bindings_sender_id[i] != sender_id) {
			return false;
		}
	}

	return true;
}

bool vm_notifications_validate_per_vcpu(struct vm_locked vm_locked,
					bool is_from_vm, bool is_per_vcpu,
					ffa_notifications_bitmap_t notif)
{
	CHECK(vm_locked.vm != NULL);
	struct notifications *to_check =
		vm_get_notifications(vm_locked, is_from_vm);

	return is_per_vcpu ? (~to_check->bindings_per_vcpu & notif) == 0U
			   : (to_check->bindings_per_vcpu & notif) == 0U;
}

void vm_notifications_set(struct vm_locked vm_locked, bool is_from_vm,
			  ffa_notifications_bitmap_t notifications,
			  ffa_vcpu_index_t vcpu_id, bool is_per_vcpu)
{
	CHECK(vm_locked.vm != NULL);
	struct notifications *to_set =
		vm_get_notifications(vm_locked, is_from_vm);
	CHECK(vcpu_id < MAX_CPUS);

	if (is_per_vcpu) {
		to_set->per_vcpu[vcpu_id].pending |= notifications;
	} else {
		to_set->global.pending |= notifications;
	}

	/* Update count of notifications pending. */
	vm_notifications_pending_count_add(notifications);
}

/**
 * Get Global notifications and per CPU only of the current VCPU.
 */
ffa_notifications_bitmap_t vm_notifications_get_pending_and_clear(
	struct vm_locked vm_locked, bool is_from_vm,
	ffa_vcpu_index_t cur_vcpu_id)
{
	ffa_notifications_bitmap_t to_ret = 0;
	ffa_notifications_bitmap_t pending_and_info_get_retrieved;

	CHECK(vm_locked.vm != NULL);
	struct notifications *to_get =
		vm_get_notifications(vm_locked, is_from_vm);
	CHECK(cur_vcpu_id < MAX_CPUS);

	to_ret |= to_get->global.pending;

	/* Update count of currently pending notifications in the system. */
	vm_notifications_pending_count_sub(to_get->global.pending);

	/*
	 * If notifications receiver is getting have been retrieved by the
	 * receiver scheduler, decrement those from respective count.
	 */
	pending_and_info_get_retrieved =
		to_get->global.pending & to_get->global.info_get_retrieved;

	if (pending_and_info_get_retrieved != 0) {
		vm_notifications_info_get_retrieved_count_sub(
			pending_and_info_get_retrieved);
	}

	to_get->global.pending = 0U;
	to_get->global.info_get_retrieved = 0U;

	to_ret |= to_get->per_vcpu[cur_vcpu_id].pending;

	/*
	 * Update counts of notifications, this time for per-vCPU notifications.
	 */
	vm_notifications_pending_count_sub(
		to_get->per_vcpu[cur_vcpu_id].pending);

	pending_and_info_get_retrieved =
		to_get->per_vcpu[cur_vcpu_id].pending &
		to_get->per_vcpu[cur_vcpu_id].info_get_retrieved;

	if (pending_and_info_get_retrieved != 0) {
		vm_notifications_info_get_retrieved_count_sub(
			pending_and_info_get_retrieved);
	}

	to_get->per_vcpu[cur_vcpu_id].pending = 0U;
	to_get->per_vcpu[cur_vcpu_id].info_get_retrieved = 0U;

	return to_ret;
}

/**
 * Get pending notification's information to return to the receiver scheduler.
 */
void vm_notifications_info_get_pending(
	struct vm_locked vm_locked, bool is_from_vm, uint16_t *ids,
	uint32_t *ids_count, uint32_t *lists_sizes, uint32_t *lists_count,
	const uint32_t ids_max_count,
	enum notifications_info_get_state *info_get_state)
{
	ffa_notifications_bitmap_t pending_not_retrieved;

	CHECK(vm_locked.vm != NULL);
	struct notifications *notifications =
		vm_get_notifications(vm_locked, is_from_vm);

	if (*info_get_state == FULL) {
		return;
	}

	CHECK(*ids_count <= ids_max_count);
	CHECK(*lists_count <= ids_max_count);

	pending_not_retrieved = notifications->global.pending &
				~notifications->global.info_get_retrieved;

	if (pending_not_retrieved != 0U && *info_get_state == INIT) {
		/*
		 * If action is to INIT, means that no list has been
		 * created for the given VM ID, which also means that global
		 * notifications are not represented in the list yet.
		 */
		if (*ids_count == ids_max_count) {
			*info_get_state = FULL;
			return;
		}

		*info_get_state = INSERTING;

		(*lists_count)++;
		ids[*ids_count] = vm_locked.vm->id;
		++(*ids_count);
	}

	notifications->global.info_get_retrieved |= pending_not_retrieved;

	vm_notifications_info_get_retrieved_count_add(pending_not_retrieved);

	for (ffa_vcpu_count_t i = 0; i < vm_locked.vm->vcpu_count; i++) {
		/*
		 * Include VCPU ID of per-VCPU notifications.
		 */
		pending_not_retrieved =
			notifications->per_vcpu[i].pending &
			~notifications->per_vcpu[i].info_get_retrieved;

		if (pending_not_retrieved == 0U) {
			continue;
		}

		switch (*info_get_state) {
		case INIT:
		case STARTING_NEW:
			/*
			 * At this iteration two ids need to be added: the VM ID
			 * and VCPU ID. If there is not space, change state and
			 * terminate function.
			 */
			if (ids_max_count - *ids_count < 2) {
				*info_get_state = FULL;
				return;
			}

			ids[*ids_count] = vm_locked.vm->id;
			++(*ids_count);

			/* Insert VCPU ID */
			ids[*ids_count] = i;
			++(*ids_count);

			++lists_sizes[*lists_count];
			++(*lists_count);

			*info_get_state = INSERTING;
			break;
		case INSERTING:
			if (*ids_count == ids_max_count) {
				*info_get_state = FULL;
				return;
			}

			/* Insert VCPU ID */
			ids[*ids_count] = i;
			(*ids_count)++;

			/* Increment respective list size */
			++lists_sizes[*lists_count - 1];

			if (lists_sizes[*lists_count - 1] == 3) {
				*info_get_state = STARTING_NEW;
			}
			break;
		default:
			panic("Notification info get action error!!\n");
		}

		notifications->per_vcpu[i].info_get_retrieved |=
			pending_not_retrieved;

		vm_notifications_info_get_retrieved_count_add(
			pending_not_retrieved);
	}
}

/**
 * Gets all info from VM's pending notifications.
 * Returns true if the list is full, and there is more pending.
 */
bool vm_notifications_info_get(struct vm_locked vm_locked, uint16_t *ids,
			       uint32_t *ids_count, uint32_t *lists_sizes,
			       uint32_t *lists_count,
			       const uint32_t ids_max_count)
{
	enum notifications_info_get_state current_state = INIT;

	/* Get info of pending notifications from SPs */
	vm_notifications_info_get_pending(vm_locked, false, ids, ids_count,
					  lists_sizes, lists_count,
					  ids_max_count, &current_state);

	/* Get info of pending notifications from VMs */
	vm_notifications_info_get_pending(vm_locked, true, ids, ids_count,
					  lists_sizes, lists_count,
					  ids_max_count, &current_state);

	/*
	 * State transitions to FULL when trying to insert a new ID in the
	 * list and there is not more space. This means there are notifications
	 * pending, whose info is not retrieved.
	 */
	return current_state == FULL;
}

/**
 * Checks VM's messaging method support.
 */
bool vm_supports_messaging_method(struct vm *vm, uint8_t msg_method)
{
	return (vm->messaging_method & msg_method) != 0;
}

void vm_notifications_set_npi_injected(struct vm_locked vm_locked,
				       bool npi_injected)
{
	vm_locked.vm->notifications.npi_injected = npi_injected;
}

bool vm_notifications_is_npi_injected(struct vm_locked vm_locked)
{
	return vm_locked.vm->notifications.npi_injected;
}

/**
 * Sets the designated GP register that the VM expects to receive the boot
 * info's address.
 */
void vm_set_boot_info_gp_reg(struct vm *vm, struct vcpu *vcpu)
{
	if (!vm->initialized && vm->boot_info.blob_addr.ipa != 0U) {
		arch_regs_set_gp_reg(&vcpu->regs,
				     ipa_addr(vm->boot_info.blob_addr),
				     vm->boot_info.gp_register_num);
	}
}
