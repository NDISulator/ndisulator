/*-
 * Copyright (c) 2003
 *	Bill Paul <wpaul@windriver.com>.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by Bill Paul.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY Bill Paul AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL Bill Paul OR THE VOICES IN HIS HEAD
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef _NTOSKRNL_VAR_H_
#define	_NTOSKRNL_VAR_H_

struct unicode_string {
	uint16_t	len;
	uint16_t	maxlen;
	uint16_t	*buf;
};

struct ansi_string {
	uint16_t	len;
	uint16_t	maxlen;
	char		*buf;
};

/*
 * Windows memory descriptor list. In Windows, it's possible for
 * buffers to be passed between user and kernel contexts without
 * copying. Buffers may also be allocated in either paged or
 * non-paged memory regions. An MDL describes the pages of memory
 * used to contain a particular buffer. Note that a single MDL
 * may describe a buffer that spans multiple pages. An array of
 * page addresses appears immediately after the MDL structure itself.
 * MDLs are therefore implicitly variably sized, even though they
 * don't look it.
 *
 * Note that in FreeBSD, we can take many shortcuts in the way
 * we handle MDLs because:
 *
 * - We are only concerned with pages in kernel context. This means
 *   we will only ever use the kernel's memory map, and remapping
 *   of buffers is never needed.
 *
 * - Kernel pages can never be paged out, so we don't have to worry
 *   about whether or not a page is actually mapped before going to
 *   touch it.
 */
struct mdl {
	struct mdl	*next;
	uint16_t	size;
	uint16_t	flags;
	void		*process;
	void		*mappedsystemva;
	void		*startva;
	uint32_t	bytecount;
	uint32_t	byteoffset;
};

/* MDL flags */
#define	MDL_MAPPED_TO_SYSTEM_VA		0x0001
#define	MDL_PAGES_LOCKED		0x0002
#define	MDL_SOURCE_IS_NONPAGED_POOL	0x0004
#define	MDL_ALLOCATED_FIXED_SIZE	0x0008
#define	MDL_PARTIAL			0x0010
#define	MDL_PARTIAL_HAS_BEEN_MAPPED	0x0020
#define	MDL_IO_PAGE_READ		0x0040
#define	MDL_WRITE_OPERATION		0x0080
#define	MDL_PARENT_MAPPED_SYSTEM_VA	0x0100
#define	MDL_FREE_EXTRA_PTES		0x0200
#define	MDL_IO_SPACE			0x0800
#define	MDL_NETWORK_HEADER		0x1000
#define	MDL_MAPPING_CAN_FAIL		0x2000
#define	MDL_ALLOCATED_MUST_SUCCEED	0x4000
#define	MDL_ZONE_ALLOCED		0x8000	/* BSD private */
#define	MDL_ZONE_PAGES 16
#define	MDL_ZONE_SIZE (sizeof(struct mdl) + (sizeof(vm_offset_t) * MDL_ZONE_PAGES))

/* Note: assumes x86 page size of 4K. */
#define	SPAN_PAGES(ptr, len)					\
	((uint32_t)((((uintptr_t)(ptr) & (PAGE_SIZE - 1)) +	\
	(len) + (PAGE_SIZE - 1)) >> PAGE_SHIFT))

#define	PAGE_ALIGN(ptr) ((void *)((uintptr_t)(ptr) & ~(PAGE_SIZE - 1)))
#define	BYTE_OFFSET(ptr) ((uint32_t)((uintptr_t)(ptr) & (PAGE_SIZE - 1)))
#define	MDL_PAGES(m) (vm_offset_t *)(m + 1)

#define	MmInitializeMdl(b, baseva, len)					\
	(b)->next = NULL;						\
	(b)->size = (uint16_t)(sizeof(struct mdl) +			\
		(sizeof(vm_offset_t) * SPAN_PAGES((baseva), (len))));	\
	(b)->flags = 0;							\
	(b)->startva = (void *)PAGE_ALIGN((baseva));			\
	(b)->byteoffset = BYTE_OFFSET((baseva));			\
	(b)->bytecount = (uint32_t)(len);

#define	MmGetMdlByteOffset(mdl) ((mdl)->byteoffset)
#define	MmGetMdlByteCount(mdl) ((mdl)->bytecount)
#define	MmGetMdlVirtualAddress(mdl)					\
	((void *)((char *)((mdl)->startva) + (mdl)->byteoffset))
#define	MmGetMdlStartVa(mdl) ((mdl)->startva)
#define	MmGetMdlPfnArray(mdl) MDL_PAGES(mdl)

#define	WDM_MAJOR		1
#define	WDM_MINOR_WIN98		0x00
#define	WDM_MINOR_WINME		0x05
#define	WDM_MINOR_WIN2000	0x10
#define	WDM_MINOR_WINXP		0x20
#define	WDM_MINOR_WIN2003	0x30

struct slist_entry {
	struct slist_entry *sl_next;
};

union slist_header {  /* FIXME: amd64 */
	uint64_t	slh_align;
	struct {
		struct slist_entry	*slh_next;
		uint16_t 		slh_depth;
		uint16_t		slh_seq;
	} slh_list;
};

struct list_entry {
	struct list_entry	*flink;
	struct list_entry	*blink;
};

static inline void
InitializeListHead(struct list_entry *head)
{
	head->flink = head->blink = head;
}

static inline uint8_t
IsListEmpty(struct list_entry *head)
{
	if (head->flink == head)
		return TRUE;
	else
		return FALSE;
}

static inline void
RemoveEntryList(struct list_entry *entry)
{
	entry->blink->flink = entry->flink;
	entry->flink->blink = entry->blink;
}

static inline struct list_entry *
RemoveHeadList(struct list_entry *head)
{
	struct list_entry *flink;
	struct list_entry *entry;

	entry = head->flink;
	flink = entry->flink;
	head->flink = flink;
	flink->blink = head;

	return (entry);
}

static inline struct list_entry *
RemoveTailList(struct list_entry *head)
{
	struct list_entry *blink;
	struct list_entry *entry;

	entry = head->blink;
	blink = entry->blink;
	head->blink = blink;
	blink->flink = head;

	return (entry);
}

static inline void
InsertHeadList(struct list_entry *head, struct list_entry *entry)
{
	struct list_entry *flink;

	flink = head->flink;
	entry->flink = flink;
	entry->blink = head;
	flink->blink = entry;
	head->flink = entry;
}

static inline void
InsertTailList(struct list_entry *head, struct list_entry *entry)
{
	struct list_entry *blink;

	blink = head->blink;
	entry->flink = head;
	entry->blink = blink;
	blink->flink = entry;
	head->blink = entry;
}

#define	CONTAINING_RECORD(addr, type, field)	\
	((type *)((vm_offset_t)(addr) - (vm_offset_t)(&((type *)0)->field)))

struct nt_dispatcher_header {
	uint8_t			type;
	uint8_t			absolute;
	uint8_t			size;
	uint8_t			inserted;
	int32_t			signal_state;
	struct list_entry	wait_list_head;
};

enum dispatcher_header_type {
	NOTIFICATION_EVENT_OBJECT,
	SYNCHRONIZATION_EVENT_OBJECT,
	MUTANT_OBJECT,
	PROCESS_OBJECT,
	QUEUE_OBJECT,
	SEMAPHORE_OBJECT,
	THREAD_OBJECT,
	NOTIFICATION_TIMER_OBJECT,
	SYNCHRONIZATION_TIMER_OBJECT
};

#define	PASSIVE_LEVEL	0
#define	APC_LEVEL	1
#define	DISPATCH_LEVEL	2

struct nt_objref {
	struct nt_dispatcher_header	header;
	void				*obj;
	TAILQ_ENTRY(nt_objref)		link;
};
TAILQ_HEAD(nt_objref_head, nt_objref);

struct nt_ktimer {
	struct nt_dispatcher_header	header;
	uint64_t			duetime;
	union {
		struct list_entry	timerlistentry;
		struct callout		*callout;
	} u;
	void				*dpc;
	uint32_t 			period;
};

struct nt_kevent {
	struct nt_dispatcher_header	header;
};

struct nt_kdpc;
typedef void (*nt_kdpc_func)(struct nt_kdpc *, void *, void *, void *);

struct nt_kdpc {
	uint16_t		type;
	uint8_t			num;		/* CPU number */
	uint8_t			importance;	/* priority */
	struct list_entry	dpclistentry;
	nt_kdpc_func		deferedfunc;
	void			*deferredctx;
	void			*sysarg1;
	void			*sysarg2;
	void			*lock;
};

enum kdpc_importance {
	IMPORTANCE_LOW,
	IMPORTANCE_MEDIUM,
	IMPORTANCE_HIGH
};

#define	KDPC_CPU_DEFAULT 255

struct nt_kmutex {
	struct nt_dispatcher_header	header;
	struct list_entry		list;
	void				*owner_thread;
	uint8_t				abandoned;
	uint8_t				apc_disable;
};

struct nt_ksemaphore {
	struct nt_dispatcher_header	header;
	int32_t				limit;
};

enum pool_type {
	NON_PAGED_POOL,
	PAGED_POOL,
	NON_PAGED_POOL_MUST_SUCCEED,
	DONT_USE_THIS_TYPE,
	NON_PAGED_POOL_CACHE_ALIGNED,
	PAGED_POOL_CACHE_ALIGNED,
	NON_PAGED_POOL_CACHE_ALIGNED_MUST_S
};

enum memory_caching_type {
	MM_NON_CACHED,
	MM_CACHED,
	MM_WRITE_COMBINED,
	MM_HARDWARE_COHERENT_CACHED,
	MM_NON_CACHED_UNORDERED,
	MM_USWC_CACHED
};

#define	LOOKASIDE_DEPTH 256

struct general_lookaside {
	union slist_header	list_head;
	uint16_t		depth;
	uint16_t		maximum_depth;
	uint32_t		total_alocates;
	union {
		uint32_t	allocate_misses;
		uint32_t	allocate_hits;
	} u_a;
	uint32_t		total_frees;
	union {
		uint32_t	free_misses;
		uint32_t	free_hits;
	} u_f;
	enum pool_type		type;
	uint32_t		tag;
	uint32_t		size;
	void			*allocfunc;
	void			*freefunc;
	struct list_entry	listent;
	uint32_t		last_total_allocates;
	union {
		uint32_t	last_allocate_misses;
		uint32_t	last_allocate_hits;
	} u_l;
	uint32_t		feature[2];
};

struct npaged_lookaside_list {
	struct general_lookaside	nll_l;
#ifdef __i386__
	unsigned long		nll_obsoletelock;
#endif
};

typedef void * (*lookaside_alloc_func)(uint32_t, size_t, uint32_t);
typedef void (*lookaside_free_func)(void *);

struct irp;

struct kdevice_qentry {
	struct list_entry	kqe_devlistent;
	uint32_t		kqe_sortkey;
	uint8_t			kqe_inserted;
};

struct kdevice_queue {
	uint16_t		kq_type;
	uint16_t		kq_size;
	struct list_entry	kq_devlisthead;
	unsigned long		kq_lock;
	uint8_t			kq_busy;
};

struct wait_ctx_block {
	struct kdevice_qentry	wcb_waitqueue;
	void			*wcb_devfunc;
	void			*wcb_devctx;
	uint32_t		wcb_mapregcnt;
	void			*wcb_devobj;
	void			*wcb_curirp;
	void			*wcb_bufchaindpc;
};

struct wait_block {
	struct list_entry		wb_waitlist;
	void				*wb_kthread;
	struct nt_dispatcher_header	*wb_object;
	struct wait_block		*wb_next;
	uint8_t				wb_waitkey;
	uint8_t				wb_waittype;
	uint8_t				wb_awakened;
	uint8_t				wb_oldpri;
};

#define	wb_ext wb_kthread

#define	THREAD_WAIT_OBJECTS 3
#define	MAX_WAIT_OBJECTS 64

#define	WAITKEY_VALID 0x8000

/* kthread priority  */
#define	LOW_PRIORITY		0
#define	LOW_REALTIME_PRIORITY	16
#define	HIGH_PRIORITY		31

struct thread_context {
	void	*tc_thrctx;
	void	*tc_thrfunc;
};

/* Forward declaration */
struct driver_object;
struct devobj_extension;

struct driver_extension {
	struct driver_object	*driver_object;
	void			*add_device;
	uint32_t		count;
	struct unicode_string	service_key_name;

	/*
	 * Drivers are allowed to add one or more custom extensions
	 * to the driver object, but there's no special pointer
	 * for them. Hang them off here for now.
	 */
	struct list_entry 	usrext;
};

struct custom_extension {
	struct list_entry	ce_list;
	void			*ce_clid;
};

struct nt_kinterrupt;
typedef uint8_t (*service_func)(struct nt_kinterrupt *interrupt, void *ctx);
typedef uint8_t (*synchronize_func)(void *ctx);

struct nt_kinterrupt {
	struct list_entry	list;
	unsigned long		lock_priv;
	unsigned long		*lock;
	service_func		func;
	void			*ctx;
};

struct object_attributes {
	uint32_t		length;
	void			*root_directory;
	struct unicode_string	*name;
	uint32_t		attributes;
	void			*security_descriptor;
	void			*security_qos;
};

struct ksystem_time {
	uint32_t	low_part;
	int32_t		high1_time;
	int32_t		high2_time;
};

enum nt_product_type {
	NT_PRODUCT_WIN_NT = 1,
	NT_PRODUCT_LAN_MAN_NT,
	NT_PRODUCT_SERVER
};

enum event_type {
	NOTIFICATION_EVENT,
	SYNCHRONIZATION_EVENT
};

enum timer_type {
	NOTIFICATION_TIMER,
	SYNCHRONIZATION_TIMER
};

enum wait_type {
	WAIT_ALL,
	WAIT_ANY
};

enum alt_arch_type {
	STANDARD_DESIGN,
	NEC98x86,
	END_ALTERNATIVES
};

struct kuser_shared_data {
	uint32_t		tick_count;
	uint32_t		tick_count_multiplier;
	volatile struct		ksystem_time interrupt_time;
	volatile struct		ksystem_time system_time;
	volatile struct		ksystem_time time_zone_bias;
	uint16_t		image_number_low;
	uint16_t		image_number_high;
	int16_t			nt_system_root[260];
	uint32_t		max_stack_trace_depth;
	uint32_t		crypto_exponent;
	uint32_t		time_zone_id;
	uint32_t		large_page_min;
	uint32_t		reserved2[7];
	enum nt_product_type	nt_product_type;
	uint8_t			product_type_is_valid;
	uint32_t		nt_major_version;
	uint32_t		nt_minor_version;
	uint8_t			processor_features[64];
	uint32_t		reserved1;
	uint32_t		reserved3;
	volatile uint32_t	time_slip;
	enum alt_arch_type	alt_arch_type;
	int64_t			system_expiration_date;
	uint32_t		suite_mask;
	uint8_t			kdbg_enabled;
	volatile uint32_t	active_console;
	volatile uint32_t	dismount_count;
	uint32_t		com_plus_package;
	uint32_t		last_system_rit_event_tick_count;
	uint32_t		num_phys_pages;
	uint8_t			safe_boot_mode;
	uint32_t		trace_log;
	uint64_t		fill0;
	uint64_t		sys_call[4];
	union {
		volatile struct	ksystem_time	tick_count;
		volatile uint64_t		tick_count_quad;
	} tick;
};

/*
 * In Windows, there are Physical Device Objects (PDOs) and
 * Functional Device Objects (FDOs). Physical Device Objects are
 * created and maintained by bus drivers. For example, the PCI
 * bus driver might detect two PCI ethernet cards on a given
 * bus. The PCI bus driver will then allocate two device_objects
 * for its own internal bookeeping purposes. This is analagous
 * to the device_t that the FreeBSD PCI code allocates and passes
 * into each PCI driver's probe and attach routines.
 *
 * When an ethernet driver claims one of the ethernet cards
 * on the bus, it will create its own device_object. This is
 * the Functional Device Object. This object is analagous to the
 * device-specific softc structure.
 */
struct device_object {
	int16_t			type;
	uint16_t		size;
	int32_t			refcnt;
	struct driver_object	*drvobj;
	struct device_object	*nextdev;
	struct device_object	*attacheddev;
	struct irp	 	*currirp;
	void			*iotimer;
	uint32_t		flags;
	uint32_t		characteristics;
	void			*vpb;
	void			*devext;
	uint8_t			stacksize;
	union {
		struct list_entry	listent;
		struct wait_ctx_block	wcb;
	} queue;
	uint32_t		alignreq;
	struct kdevice_queue	devqueue;
	struct nt_kdpc 		dpc;
	uint32_t		activethreads;
	void			*securitydesc;
	struct			nt_kevent devlock;
	uint16_t		sectorsz;
	uint16_t		spare1;
	struct devobj_extension	*devobj_ext;
	void			*rsvd;
};

struct devobj_extension {
	uint16_t		type;
	uint16_t		size;
	struct device_object	*devobj;
};

/* Device object flags */
#define	DO_VERIFY_VOLUME		0x00000002
#define	DO_BUFFERED_IO			0x00000004
#define	DO_EXCLUSIVE			0x00000008
#define	DO_DIRECT_IO			0x00000010
#define	DO_MAP_IO_BUFFER		0x00000020
#define	DO_DEVICE_HAS_NAME		0x00000040
#define	DO_DEVICE_INITIALIZING		0x00000080
#define	DO_SYSTEM_BOOT_PARTITION	0x00000100
#define	DO_LONG_TERM_REQUESTS		0x00000200
#define	DO_NEVER_LAST_DEVICE		0x00000400
#define	DO_SHUTDOWN_REGISTERED		0x00000800
#define	DO_BUS_ENUMERATED_DEVICE	0x00001000
#define	DO_POWER_PAGABLE		0x00002000
#define	DO_POWER_INRUSH			0x00004000
#define	DO_LOW_PRIORITY_FILESYSTEM	0x00010000

/* Priority boosts */
#define	IO_NO_INCREMENT		0
#define	IO_CD_ROM_INCREMENT	1
#define	IO_DISK_INCREMENT	1
#define	IO_KEYBOARD_INCREMENT	6
#define	IO_MAILSLOT_INCREMENT	2
#define	IO_MOUSE_INCREMENT	6
#define	IO_NAMED_PIPE_INCREMENT	2
#define	IO_NETWORK_INCREMENT	2
#define	IO_PARALLEL_INCREMENT	1
#define	IO_SERIAL_INCREMENT	2
#define	IO_SOUND_INCREMENT	8
#define	IO_VIDEO_INCREMENT	1

/* IRP major codes */
#define	IRP_MJ_CREATE			0x00
#define	IRP_MJ_CREATE_NAMED_PIPE	0x01
#define	IRP_MJ_CLOSE			0x02
#define	IRP_MJ_READ			0x03
#define	IRP_MJ_WRITE			0x04
#define	IRP_MJ_QUERY_INFORMATION	0x05
#define	IRP_MJ_SET_INFORMATION		0x06
#define	IRP_MJ_QUERY_EA			0x07
#define	IRP_MJ_SET_EA			0x08
#define	IRP_MJ_FLUSH_BUFFERS		0x09
#define	IRP_MJ_QUERY_VOLUME_INFORMATION	0x0a
#define	IRP_MJ_SET_VOLUME_INFORMATION	0x0b
#define	IRP_MJ_DIRECTORY_CONTROL	0x0c
#define	IRP_MJ_FILE_SYSTEM_CONTROL	0x0d
#define	IRP_MJ_DEVICE_CONTROL		0x0e
#define	IRP_MJ_INTERNAL_DEVICE_CONTROL	0x0f
#define	IRP_MJ_SHUTDOWN			0x10
#define	IRP_MJ_LOCK_CONTROL		0x11
#define	IRP_MJ_CLEANUP			0x12
#define	IRP_MJ_CREATE_MAILSLOT		0x13
#define	IRP_MJ_QUERY_SECURITY		0x14
#define	IRP_MJ_SET_SECURITY		0x15
#define	IRP_MJ_POWER			0x16
#define	IRP_MJ_SYSTEM_CONTROL		0x17
#define	IRP_MJ_DEVICE_CHANGE		0x18
#define	IRP_MJ_QUERY_QUOTA		0x19
#define	IRP_MJ_SET_QUOTA		0x1a
#define	IRP_MJ_PNP			0x1b
#define	IRP_MJ_PNP_POWER		IRP_MJ_PNP	/* Obsolete.... */
#define	IRP_MJ_MAXIMUM_FUNCTION		0x1b
#define	IRP_MJ_SCSI			IRP_MJ_INTERNAL_DEVICE_CONTROL

/* IRP minor codes */
#define	IRP_MN_QUERY_DIRECTORY		0x01
#define	IRP_MN_NOTIFY_CHANGE_DIRECTORY	0x02
#define	IRP_MN_USER_FS_REQUEST		0x00

#define	IRP_MN_MOUNT_VOLUME	0x01
#define	IRP_MN_VERIFY_VOLUME	0x02
#define	IRP_MN_LOAD_FILE_SYSTEM	0x03
#define	IRP_MN_TRACK_LINK	0x04
#define	IRP_MN_KERNEL_CALL	0x04

#define	IRP_MN_LOCK			0x01
#define	IRP_MN_UNLOCK_SINGLE		0x02
#define	IRP_MN_UNLOCK_ALL		0x03
#define	IRP_MN_UNLOCK_ALL_BY_KEY	0x04

#define	IRP_MN_NORMAL		0x00
#define	IRP_MN_DPC		0x01
#define	IRP_MN_MDL		0x02
#define	IRP_MN_COMPLETE		0x04
#define	IRP_MN_COMPRESSED	0x08

#define	IRP_MN_MDL_DPC		(IRP_MN_MDL|IRP_MN_DPC)
#define	IRP_MN_COMPLETE_MDL	(IRP_MN_COMPLETE|IRP_MN_MDL)
#define	IRP_MN_COMPLETE_MDL_DPC	(IRP_MN_COMPLETE_MDL|IRP_MN_DPC)

#define	IRP_MN_SCSI_CLASS	0x01

#define	IRP_MN_START_DEVICE			0x00
#define	IRP_MN_QUERY_REMOVE_DEVICE		0x01
#define	IRP_MN_REMOVE_DEVICE			0x02
#define	IRP_MN_CANCEL_REMOVE_DEVICE		0x03
#define	IRP_MN_STOP_DEVICE			0x04
#define	IRP_MN_QUERY_STOP_DEVICE		0x05
#define	IRP_MN_CANCEL_STOP_DEVICE		0x06
#define	IRP_MN_QUERY_DEVICE_RELATIONS		0x07
#define	IRP_MN_QUERY_INTERFACE			0x08
#define	IRP_MN_QUERY_CAPABILITIES		0x09
#define	IRP_MN_QUERY_RESOURCES			0x0A
#define	IRP_MN_QUERY_RESOURCE_REQUIREMENTS	0x0B
#define	IRP_MN_QUERY_DEVICE_TEXT		0x0C
#define	IRP_MN_FILTER_RESOURCE_REQUIREMENTS	0x0D

#define	IRP_MN_READ_CONFIG			0x0F
#define	IRP_MN_WRITE_CONFIG			0x10
#define	IRP_MN_EJECT				0x11
#define	IRP_MN_SET_LOCK				0x12
#define	IRP_MN_QUERY_ID				0x13
#define	IRP_MN_QUERY_PNP_DEVICE_STATE		0x14
#define	IRP_MN_QUERY_BUS_INFORMATION		0x15
#define	IRP_MN_DEVICE_USAGE_NOTIFICATION	0x16
#define	IRP_MN_SURPRISE_REMOVAL			0x17
#define	IRP_MN_QUERY_LEGACY_BUS_INFORMATION	0x18

#define	IRP_MN_WAIT_WAKE	0x00
#define	IRP_MN_POWER_SEQUENCE	0x01
#define	IRP_MN_SET_POWER	0x02
#define	IRP_MN_QUERY_POWER	0x03

#define	IRP_MN_QUERY_ALL_DATA		0x00
#define	IRP_MN_QUERY_SINGLE_INSTANCE	0x01
#define	IRP_MN_CHANGE_SINGLE_INSTANCE	0x02
#define	IRP_MN_CHANGE_SINGLE_ITEM	0x03
#define	IRP_MN_ENABLE_EVENTS		0x04
#define	IRP_MN_DISABLE_EVENTS		0x05
#define	IRP_MN_ENABLE_COLLECTION	0x06
#define	IRP_MN_DISABLE_COLLECTION	0x07
#define	IRP_MN_REGINFO			0x08
#define	IRP_MN_EXECUTE_METHOD		0x09
#define	IRP_MN_REGINFO_EX		0x0b

/* IRP flags */
#define	IRP_NOCACHE			0x00000001
#define	IRP_PAGING_IO			0x00000002
#define	IRP_MOUNT_COMPLETION		0x00000002
#define	IRP_SYNCHRONOUS_API		0x00000004
#define	IRP_ASSOCIATED_IRP		0x00000008
#define	IRP_BUFFERED_IO			0x00000010
#define	IRP_DEALLOCATE_BUFFER		0x00000020
#define	IRP_INPUT_OPERATION		0x00000040
#define	IRP_SYNCHRONOUS_PAGING_IO	0x00000040
#define	IRP_CREATE_OPERATION		0x00000080
#define	IRP_READ_OPERATION		0x00000100
#define	IRP_WRITE_OPERATION		0x00000200
#define	IRP_CLOSE_OPERATION		0x00000400
#define	IRP_DEFER_IO_COMPLETION		0x00000800
#define	IRP_OB_QUERY_NAME		0x00001000
#define	IRP_HOLD_DEVICE_QUEUE		0x00002000
#define	IRP_RETRY_IO_COMPLETION		0x00004000
#define	IRP_CLASS_CACHE_OPERATION	0x00008000
#define	IRP_SET_USER_EVENT		IRP_CLOSE_OPERATION

/* IRP I/O control flags */
#define	IRP_QUOTA_CHARGED		0x01
#define	IRP_ALLOCATED_MUST_SUCCEED	0x02
#define	IRP_ALLOCATED_FIXED_SIZE	0x04
#define	IRP_LOOKASIDE_ALLOCATION	0x08

/* I/O method types */
#define	METHOD_BUFFERED		0
#define	METHOD_IN_DIRECT	1
#define	METHOD_OUT_DIRECT	2
#define	METHOD_NEITHER		3

/* File access types */
#define	FILE_ANY_ACCESS		0x0000
#define	FILE_SPECIAL_ACCESS	FILE_ANY_ACCESS
#define	FILE_READ_ACCESS	0x0001
#define	FILE_WRITE_ACCESS	0x0002

/* Recover I/O access method from IOCTL code. */
#define	IO_METHOD(x) ((x) & 0xFFFFFFFC)

/* Recover function code from IOCTL code */
#define	IO_FUNC(x) (((x) & 0x7FFC) >> 2)

/* Macro to construct an IOCTL code. */
#define	IOCTL_CODE(dev, func, iomethod, acc)	\
	((dev) << 16)|(acc << 14)|(func << 2)|(iomethod))

struct io_status_block {
	union {
		uint32_t	status;
		void		*ptr;
	} u;
	register_t	info;
};

struct kapc {
	uint16_t		apc_type;
	uint16_t		apc_size;
	uint32_t		apc_spare0;
	void			*apc_thread;
	struct list_entry	apc_list;
	void			*apc_kernfunc;
	void			*apc_rundownfunc;
	void			*apc_normalfunc;
	void			*apc_normctx;
	void			*apc_sysarg1;
	void			*apc_sysarg2;
	uint8_t			apc_stateidx;
	uint8_t			apc_cpumode;
	uint8_t			apc_inserted;
};

typedef uint32_t (*completion_func)(struct device_object *, struct irp *, void *);
typedef uint32_t (*cancel_func)(struct device_object *, struct irp *);

struct io_stack_location {
	uint8_t		major;
	uint8_t		minor;
	uint8_t		flags;
	uint8_t		ctl;

	/*
	 * There's a big union here in the actual Windows
	 * definition of the structure, but it contains stuff
	 * that doesn't really apply to BSD, and defining it
	 * all properly would require duplicating over a dozen
	 * other structures that we'll never use. Since the
	 * io_stack_location structure is opaque to drivers anyway,
	 * there is no reason to bother with the extra stuff.
	 */
	union {
		struct {
			uint32_t	len;
			uint32_t	*key;
			uint64_t	byteoff;
		} read;
		struct {
			uint32_t	len;
			uint32_t	*key;
			uint64_t	byteoff;
		} write;
		struct {
			uint32_t	obuflen;
			uint32_t	ibuflen;
			uint32_t	iocode;
			void		*type3ibuf;
		} ioctl;
		struct {
			void	*arg1;
			void	*arg2;
			void	*arg3;
			void	*arg4;
		} others;
	} parameters __attribute__((packed));

	void		*devobj;
	void		*fileobj;
	completion_func	completionfunc;
	void		*completionctx;
};

/* Stack location control flags */
#define	SL_PENDING_RETURNED	0x01
#define	SL_INVOKE_ON_CANCEL	0x20
#define	SL_INVOKE_ON_SUCCESS	0x40
#define	SL_INVOKE_ON_ERROR	0x80

struct irp {
	uint16_t		type;
	uint16_t		size;
	struct mdl		*mdl;
	uint32_t		flags;
	union {
		struct irp	*master;
		uint32_t	irpcnt;
		void		*sysbuf;
	} assoc;
	struct list_entry	thlist;
	struct io_status_block	iostat;
	uint8_t			reqmode;
	uint8_t			pendingreturned;
	uint8_t			stackcnt;
	uint8_t			currentstackloc;
	uint8_t			cancel;
	uint8_t			cancelirql;
	uint8_t			apcenv;
	uint8_t			allocflags;
	struct io_status_block	*usriostat;
	struct nt_kevent	*usrevent;
	union {
		struct {
			void	*apcfunc;
			void	*apcctx;
		} asyncparms;
		uint64_t	allocsz;
	} overlay;
	cancel_func	cancelfunc;
	void		*userbuf;

	/* Windows kernel info */
	union {
		struct {
			union {
				struct kdevice_qentry	dqe;
				struct {
					void	*drvctx[4];
				} s1;
			} u1;
			void	*thread;
			char	*auxbuf;
			struct {
				struct list_entry	list;
				union {
					struct io_stack_location	*csl;
					uint32_t			pkttype;
				} u2;
			} s2;
			void	*fileobj;
		} overlay;
		union {
			struct kapc	apc;
			struct {
				void	*ep;
				void	*dev;
			} usb;
		} misc;
		void	*compkey;
	} tail;
};

#define	IRP_NDIS_DEV(irp) (irp)->tail.misc.usb.dev
#define	IRP_NDISUSB_EP(irp) (irp)->tail.misc.usb.ep

#define	InterlockedExchangePointer(dst, val)				\
	(void *)InterlockedExchange((uint32_t *)(dst), (uintptr_t)(val))

#define	IoSizeOfIrp(ssize)						\
	((uint16_t) (sizeof(struct irp) +				\
	((ssize) * (sizeof(struct io_stack_location)))))

#define	IoSetCancelRoutine(irp, func)					\
	(cancel_func)InterlockedExchangePointer(			\
	(void *)&(ip)->cancelfunc, (void *)(func))

#define	IoSetCancelValue(irp, val)					\
	(unsigned long)InterlockedExchangePointer(			\
	(void *)&(ip)->cancel, (void *)(val))

#define	IoGetCurrentIrpStackLocation(irp)				\
	(irp)->tail.overlay.s2.u2.csl

#define	IoGetNextIrpStackLocation(irp)					\
	((irp)->tail.overlay.s2.u2.csl - 1)

#define	IoSetNextIrpStackLocation(irp)					\
	do {								\
		irp->currentstackloc--;				\
		irp->tail.overlay.s2.u2.csl--;			\
	} while (0)

#define	IoSetCompletionRoutine(irp, func, ctx, ok, err, cancel)		\
	do {								\
		struct io_stack_location *s;				\
		s = IoGetNextIrpStackLocation((irp));			\
		s->completionfunc = (func);				\
		s->completionctx = (ctx);				\
		s->ctl = 0;						\
		if (ok) s->ctl = SL_INVOKE_ON_SUCCESS;		\
		if (err) s->ctl |= SL_INVOKE_ON_ERROR;		\
		if (cancel) s->ctl |= SL_INVOKE_ON_CANCEL;		\
	} while (0)

#define	IoMarkIrpPending(irp)						\
	IoGetCurrentIrpStackLocation(irp)->ctl |= SL_PENDING_RETURNED
#define	IoUnmarkIrpPending(irp)						\
	IoGetCurrentIrpStackLocation(irp)->ctl &= ~SL_PENDING_RETURNED

#define	IoCopyCurrentIrpStackLocationToNext(irp)			\
	do {								\
		struct io_stack_location *src, *dst;			\
		src = IoGetCurrentIrpStackLocation(irp);		\
		dst = IoGetNextIrpStackLocation(irp);			\
		memcpy(dst, src						\
		    offsetof(io_stack_location, completionfunc));	\
	} while (0)

#define	IoSkipCurrentIrpStackLocation(irp)				\
	do {								\
		(irp)->currentstackloc++;				\
		(irp)->tail.overlay.s2.u2.csl++;			\
	} while (0)

#define	IoInitializeDpcRequest(dobj, dpcfunc)				\
	KeInitializeDpc(&(dobj)->dpc, dpcfunc, dobj)

#define	IoRequestDpc(dobj, irp, ctx)					\
	KeInsertQueueDpc(&(dobj)->dpc, irp, ctx)

typedef uint32_t (*driver_dispatch)(struct device_object *, struct irp *);

/*
 * The driver_object is allocated once for each driver that's loaded
 * into the system. A new one is allocated for each driver and
 * populated a bit via the driver's DriverEntry function.
 * In general, a Windows DriverEntry() function will provide a pointer
 * to its AddDevice() method and set up the dispatch table.
 * For NDIS drivers, this is all done behind the scenes in the
 * NdisInitializeWrapper() and/or NdisMRegisterMiniport() routines.
 */
struct driver_object {
	int16_t			type;
	int16_t			size;
	struct device_object	*device_object;
	uint32_t		flags;
	void			*driver_start;
	uint32_t		driver_size;
	void			*driver_section;
	struct driver_extension	*driver_extension;
	struct unicode_string	driver_name;
	struct unicode_string	*hardware_database;
	void			*fast_io_dispatch;
	void			*driver_init_func;
	void			*driver_start_io_func;
	void			*driver_unload_func;
	driver_dispatch		dispatch[IRP_MJ_MAXIMUM_FUNCTION + 1];
};

enum device_registry_property {
	DEVICE_PROPERTY_DEVICE_DESCRIPTION,
	DEVICE_PROPERTY_HARDWARE_ID,
	DEVICE_PROPERTY_COMPATIBLE_IDS,
	DEVICE_PROPERTY_BOOT_CONFIGURATION,
	DEVICE_PROPERTY_BOOT_CONFIGURATION_TRANSLATED,
	DEVICE_PROPERTY_CLASS_NAME,
	DEVICE_PROPERTY_CLASS_GUID,
	DEVICE_PROPERTY_DRIVER_KEY_NAME,
	DEVICE_PROPERTY_MANUFACTURER,
	DEVICE_PROPERTY_FRIENDLY_NAME,
	DEVICE_PROPERTY_LOCATION_INFORMATION,
	DEVICE_PROPERTY_PHYSICAL_DEVICE_OBJECT_NAME,
	DEVICE_PROPERTY_BUS_TYPE_GUID,
	DEVICE_PROPERTY_LEGACY_BUS_TYPE,
	DEVICE_PROPERTY_BUS_NUMBER,
	DEVICE_PROPERTY_ENUMERATOR_NAME,
	DEVICE_PROPERTY_ADDRESS,
	DEVICE_PROPERTY_UI_NUMBER,
	DEVICE_PROPERTY_INSTALL_STATE,
	DEVICE_PROPERTY_REMOVAL_POLICY
};

enum device_type {
	FILE_DEVICE_BEEP = 1,
	FILE_DEVICE_CD_ROM,
	FILE_DEVICE_CD_ROM_FILE_SYSTEM,
	FILE_DEVICE_CONTROLLER,
	FILE_DEVICE_DATALINK,
	FILE_DEVICE_DFS,
	FILE_DEVICE_DISK,
	FILE_DEVICE_DISK_FILE_SYSTEM,
	FILE_DEVICE_FILE_SYSTEM,
	FILE_DEVICE_INPORT_PORT,
	FILE_DEVICE_KEYBOARD,
	FILE_DEVICE_MAILSLOT,
	FILE_DEVICE_MIDI_IN,
	FILE_DEVICE_MIDI_OUT,
	FILE_DEVICE_MOUSE,
	FILE_DEVICE_MULTI_UNC_PROVIDER,
	FILE_DEVICE_NAMED_PIPE,
	FILE_DEVICE_NETWORK,
	FILE_DEVICE_NETWORK_BROWSER,
	FILE_DEVICE_NETWORK_FILE_SYSTEM,
	FILE_DEVICE_NULL,
	FILE_DEVICE_PARALLEL_PORT,
	FILE_DEVICE_PHYSICAL_NETCARD,
	FILE_DEVICE_PRINTER,
	FILE_DEVICE_SCANNER,
	FILE_DEVICE_SERIAL_MOUSE_PORT,
	FILE_DEVICE_SERIAL_PORT,
	FILE_DEVICE_SCREEN,
	FILE_DEVICE_SOUND,
	FILE_DEVICE_STREAMS,
	FILE_DEVICE_TAPE,
	FILE_DEVICE_TAPE_FILE_SYSTEM,
	FILE_DEVICE_TRANSPORT,
	FILE_DEVICE_UNKNOWN,
	FILE_DEVICE_VIDEO,
	FILE_DEVICE_VIRTUAL_DISK,
	FILE_DEVICE_WAVE_IN,
	FILE_DEVICE_WAVE_OUT,
	FILE_DEVICE_8042_PORT,
	FILE_DEVICE_NETWORK_REDIRECTOR,
	FILE_DEVICE_BATTERY,
	FILE_DEVICE_BUS_EXTENDER,
	FILE_DEVICE_MODEM,
	FILE_DEVICE_VDM,
	FILE_DEVICE_MASS_STORAGE,
	FILE_DEVICE_SMB,
	FILE_DEVICE_KS,
	FILE_DEVICE_CHANGER,
	FILE_DEVICE_SMARTCARD,
	FILE_DEVICE_ACPI,
	FILE_DEVICE_DVD,
	FILE_DEVICE_FULLSCREEN_VIDEO,
	FILE_DEVICE_DFS_FILE_SYSTEM,
	FILE_DEVICE_DFS_VOLUME,
	FILE_DEVICE_SERENUM,
	FILE_DEVICE_TERMSRV,
	FILE_DEVICE_KSEC,
	FILE_DEVICE_FIPS
};

/* Device characteristics */
#define	FILE_REMOVABLE_MEDIA		0x00000001
#define	FILE_READ_ONLY_DEVICE		0x00000002
#define	FILE_FLOPPY_DISKETTE		0x00000004
#define	FILE_WRITE_ONCE_MEDIA		0x00000008
#define	FILE_REMOTE_DEVICE		0x00000010
#define	FILE_DEVICE_IS_MOUNTED		0x00000020
#define	FILE_VIRTUAL_VOLUME		0x00000040
#define	FILE_AUTOGENERATED_DEVICE_NAME	0x00000080
#define	FILE_DEVICE_SECURE_OPEN		0x00000100

/*
 * IO_WORKITEM is an opaque structures that must be allocated
 * via IoAllocateWorkItem() and released via IoFreeWorkItem().
 * Consequently, we can define it any way we want.
 */
typedef void (*io_workitem_func)(struct device_object *, void *);

struct io_workitem {
	io_workitem_func	func;
	void			*ctx;
	struct list_entry	list;
	struct device_object	*dobj;
};

enum work_queue_type {
	CRITICAL,
	DELAYED,
	HYPERCRITICAL
};

#define	NDIS_KSTACK_PAGES	12

enum windrv_wrap_type {
	STDCALL	= 1,
	FASTCALL,
	REGPARM,
	CDECL,
	AMD64
};

struct drvdb_ent {
	struct driver_object		*windrv_object;
	void				*windrv_devlist;
	struct ndis_cfg			*windrv_regvals;
	uint32_t			windrv_bustype;
	STAILQ_ENTRY(drvdb_ent)	link;
};

extern struct image_patch_table ntoskrnl_functbl[];
#ifdef __amd64__
extern struct kuser_shared_data kuser_data;
#endif
typedef void (*funcptr)(void);
typedef int (*matchfuncptr)(uint32_t, void *, void *);

void	windrv_libinit(void);
void	windrv_libfini(void);
struct drvdb_ent	*windrv_match(matchfuncptr, void *);
int	windrv_load(module_t, vm_offset_t, size_t, uint32_t, void *, void *);
int	windrv_unload(module_t, vm_offset_t);
int32_t	windrv_create_pdo(struct driver_object *, device_t);
void	windrv_destroy_pdo(struct driver_object *, device_t);
int	windrv_bus_attach(struct driver_object *, const char *);
void	windrv_wrap(funcptr, funcptr *, uint8_t, enum windrv_wrap_type);
void	windrv_unwrap(funcptr);
void	windrv_wrap_table(struct image_patch_table *);
void	windrv_unwrap_table(struct image_patch_table *);
void	ntoskrnl_libinit(void);
void	ntoskrnl_libfini(void);
void	ntoskrnl_intr(void *);
void	ntoskrnl_time(uint64_t *);
void	schedule_ndis_work_item(void *);
void	flush_queue(void);
uint16_t ExQueryDepthSList(union slist_header *);
struct slist_entry *InterlockedPushEntrySList(union slist_header *,
	    struct slist_entry *);
struct slist_entry *InterlockedPopEntrySList(union slist_header *);
int32_t	RtlUnicodeStringToAnsiString(struct ansi_string *,
	    const struct unicode_string *, uint8_t);
int32_t	RtlUpcaseUnicodeString(struct unicode_string *, struct unicode_string *,
	    uint8_t);
int32_t	RtlAnsiStringToUnicodeString(struct unicode_string *,
	    const struct ansi_string *, uint8_t);
void	RtlInitAnsiString(struct ansi_string *, const char *);
void	RtlInitUnicodeString(struct unicode_string *, const uint16_t *);
void	RtlFreeUnicodeString(struct unicode_string *);
void	RtlFreeAnsiString(struct ansi_string *);
void	KeInitializeDpc(struct nt_kdpc *, void *, void *);
uint8_t	KeInsertQueueDpc(struct nt_kdpc *, void *, void *);
uint8_t	KeRemoveQueueDpc(struct nt_kdpc *);
void	KeSetImportanceDpc(struct nt_kdpc *, uint32_t);
void	KeSetTargetProcessorDpc(struct nt_kdpc *, uint8_t);
void	KeInitializeTimer(struct nt_ktimer *);
void	KeInitializeTimerEx(struct nt_ktimer *, uint32_t);
uint8_t	KeSetTimer(struct nt_ktimer *, int64_t, struct nt_kdpc *);
uint8_t	KeSetTimerEx(struct nt_ktimer *, int64_t, uint32_t, struct nt_kdpc *);
uint8_t	KeCancelTimer(struct nt_ktimer *);
int32_t	KeWaitForSingleObject(void *, uint32_t, uint32_t, uint8_t, int64_t *);
void	KeInitializeEvent(struct nt_kevent *, uint32_t, uint8_t);
int32_t	KeSetEvent(struct nt_kevent *, int32_t, uint8_t);
int32_t	KeResetEvent(struct nt_kevent *);
#ifdef __i386__
void	KefAcquireSpinLockAtDpcLevel(unsigned long *);
void	KefReleaseSpinLockFromDpcLevel(unsigned long *);
uint8_t	KeAcquireSpinLockRaiseToDpc(unsigned long *);
#else
void	KeAcquireSpinLockAtDpcLevel(unsigned long *);
void	KeReleaseSpinLockFromDpcLevel(unsigned long *);
#endif
void	KeInitializeSpinLock(unsigned long *);
uint8_t	KeAcquireInterruptSpinLock(struct nt_kinterrupt *);
void	KeReleaseInterruptSpinLock(struct nt_kinterrupt *, uint8_t);
uint8_t	KeSynchronizeExecution(struct nt_kinterrupt *, synchronize_func,
	    void *);
uintptr_t	InterlockedExchange(volatile uint32_t *, uintptr_t);
void	*ExAllocatePool(size_t);
void	ExFreePool(void *);
void	MmBuildMdlForNonPagedPool(struct mdl *);
void	IoDisconnectInterrupt(struct nt_kinterrupt *);
void	*IoGetDriverObjectExtension(struct driver_object *, void *);
int32_t IoConnectInterrupt(struct nt_kinterrupt **, void *, void *,
	    unsigned long *, uint32_t, uint8_t, uint8_t, uint8_t, uint8_t,
	    uint32_t, uint8_t);
int32_t	IoAllocateDriverObjectExtension(struct driver_object *, void *,
	    uint32_t, void **);
int32_t	IoCreateDevice(struct driver_object *, uint32_t,
	    struct unicode_string *, enum device_type, uint32_t, uint8_t,
	    struct device_object **);
void	IoDeleteDevice(struct device_object *);
int32_t	IofCallDriver(struct device_object *, struct irp *);
void	IofCompleteRequest(struct irp *, uint8_t);
void	IoAcquireCancelSpinLock(uint8_t *);
void	IoReleaseCancelSpinLock(uint8_t);
void	IoDetachDevice(struct device_object *);
struct mdl *IoAllocateMdl(void *, uint32_t, uint8_t, uint8_t, struct irp *);
void	IoFreeMdl(struct mdl *);
void	IoFreeWorkItem(struct io_workitem *);
void	IoQueueWorkItem(struct io_workitem *, io_workitem_func,
	    enum work_queue_type, void *);
struct io_workitem	*IoAllocateWorkItem(struct device_object *);
struct driver_object	*windrv_lookup(vm_offset_t, const char *);
struct device_object	*IoGetAttachedDevice(struct device_object *);
struct device_object	*IoAttachDeviceToDeviceStack(struct device_object *,
			    struct device_object *);
struct device_object	*windrv_find_pdo(const struct driver_object *,
			    device_t);

#define	IoCallDriver(a, b)		IofCallDriver(a, b)
#define	IoCompleteRequest(a, b)		IofCompleteRequest(a, b)

/*
 * On the Windows x86 arch, KeAcquireSpinLock() and KeReleaseSpinLock()
 * routines live in the HAL. We try to imitate this behavior.
 */
#ifdef __i386__
#define	KI_USER_SHARED_DATA 0xffdf0000
#define	KeAcquireSpinLock(a, b)	*(b) = KfAcquireSpinLock(a)
#define	KeReleaseSpinLock(a, b)	KfReleaseSpinLock(a, b)
#define	KeRaiseIrql(a, b)	*(b) = KfRaiseIrql(a)
#define	KeLowerIrql(a)		KfLowerIrql(a)
#define	KeAcquireSpinLockAtDpcLevel(a)	KefAcquireSpinLockAtDpcLevel(a)
#define	KeReleaseSpinLockFromDpcLevel(a)  KefReleaseSpinLockFromDpcLevel(a)
#endif /* __i386__ */

#ifdef __amd64__
#define	KI_USER_SHARED_DATA 0xfffff78000000000UL
#define	KeAcquireSpinLock(a, b)	*(b) = KfAcquireSpinLock(a)
#define	KeReleaseSpinLock(a, b)	KfReleaseSpinLock(a, b)

/*
 * These may need to be redefined later;
 * not sure where they live on amd64 yet.
 */
#define	KeRaiseIrql(a, b)	*(b) = KfRaiseIrql(a)
#define	KeLowerIrql(a)		KfLowerIrql(a)
#endif /* __amd64__ */

#endif /* _NTOSKRNL_VAR_H_ */
