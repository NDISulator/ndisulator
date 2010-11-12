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

/*
 * us_buf is really a wchar_t *, but it's inconvenient to include
 * all the necessary header goop needed to define it, and it's a
 * pointer anyway, so for now, just make it a uint16_t *.
 */
struct unicode_string {
	uint16_t	us_len;
	uint16_t	us_maxlen;
	uint16_t	*us_buf;
};
typedef struct unicode_string unicode_string;

struct ansi_string {
	uint16_t	as_len;
	uint16_t	as_maxlen;
	char		*as_buf;
};
typedef struct ansi_string ansi_string;

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
	struct mdl	*mdl_next;
	uint16_t	mdl_size;
	uint16_t	mdl_flags;
	void		*mdl_process;
	void		*mdl_mappedsystemva;
	void		*mdl_startva;
	uint32_t	mdl_bytecount;
	uint32_t	mdl_byteoffset;
};
typedef struct mdl mdl, ndis_buffer;

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
#define	MDL_ZONE_SIZE (sizeof(mdl) + (sizeof(vm_offset_t) * MDL_ZONE_PAGES))

/* Note: assumes x86 page size of 4K. */

#ifndef PAGE_SHIFT
#if PAGE_SIZE == 4096
#define	PAGE_SHIFT 12
#elif PAGE_SIZE == 8192
#define	PAGE_SHIFT 13
#else
#error PAGE_SHIFT undefined!
#endif
#endif

#define	SPAN_PAGES(ptr, len)					\
	((uint32_t)((((uintptr_t)(ptr) & (PAGE_SIZE - 1)) +	\
	(len) + (PAGE_SIZE - 1)) >> PAGE_SHIFT))

#define	PAGE_ALIGN(ptr) ((void *)((uintptr_t)(ptr) & ~(PAGE_SIZE - 1)))
#define	BYTE_OFFSET(ptr) ((uint32_t)((uintptr_t)(ptr) & (PAGE_SIZE - 1)))
#define	MDL_PAGES(m) (vm_offset_t *)(m + 1)

#define	MmInitializeMdl(b, baseva, len)					\
	(b)->mdl_next = NULL;						\
	(b)->mdl_size = (uint16_t)(sizeof(mdl) +			\
		(sizeof(vm_offset_t) * SPAN_PAGES((baseva), (len))));	\
	(b)->mdl_flags = 0;						\
	(b)->mdl_startva = (void *)PAGE_ALIGN((baseva));		\
	(b)->mdl_byteoffset = BYTE_OFFSET((baseva));			\
	(b)->mdl_bytecount = (uint32_t)(len);

#define	MmGetMdlByteOffset(mdl) ((mdl)->mdl_byteoffset)
#define	MmGetMdlByteCount(mdl) ((mdl)->mdl_bytecount)
#define	MmGetMdlVirtualAddress(mdl)					\
	((void *)((char *)((mdl)->mdl_startva) + (mdl)->mdl_byteoffset))
#define	MmGetMdlStartVa(mdl) ((mdl)->mdl_startva)
#define	MmGetMdlPfnArray(mdl) MDL_PAGES(mdl)

#define	WDM_MAJOR		1
#define	WDM_MINOR_WIN98		0x00
#define	WDM_MINOR_WINME		0x05
#define	WDM_MINOR_WIN2000	0x10
#define	WDM_MINOR_WINXP		0x20
#define	WDM_MINOR_WIN2003	0x30

/*-
 * The ndis_kspin_lock type is called KSPIN_LOCK in MS-Windows.
 * According to the Windows DDK header files, KSPIN_LOCK is defined like this:
 *	typedef ULONG_PTR KSPIN_LOCK;
 *
 * From basetsd.h (SDK, Feb. 2003):
 *	typedef [public] unsigned __int3264 ULONG_PTR, *PULONG_PTR;
 *	typedef unsigned __int64 ULONG_PTR, *PULONG_PTR;
 *	typedef _W64 unsigned long ULONG_PTR, *PULONG_PTR;
 *
 * The keyword __int3264 specifies an integral type that has the following
 * properties:
 *	+ It is 32-bit on 32-bit platforms
 *	+ It is 64-bit on 64-bit platforms
 *	+ It is 32-bit on the wire for backward compatibility.
 *	  It gets truncated on the sending side and extended appropriately
 *	  (signed or unsigned) on the receiving side.
 *
 * Thus register_t seems the proper mapping onto FreeBSD for spin locks.
 */

typedef register_t kspin_lock;

struct slist_entry {
	struct slist_entry *sl_next;
};
typedef struct slist_entry slist_entry;

union slist_header {  /* FIXME: amd64 */
	uint64_t	slh_align;
	struct {
		struct slist_entry	*slh_next;
		uint16_t 		slh_depth;
		uint16_t		slh_seq;
	} slh_list;
};
typedef union slist_header slist_header;

struct list_entry {
	struct list_entry	*nle_flink;
	struct list_entry	*nle_blink;
};
typedef struct list_entry list_entry;

#define	InitializeListHead(l) (l)->nle_flink = (l)->nle_blink = (l)
#define	IsListEmpty(h) ((h)->nle_flink == (h))

#define	RemoveEntryList(e)			\
	do {					\
		list_entry *b;			\
		list_entry *f;			\
						\
		f = (e)->nle_flink;		\
		b = (e)->nle_blink;		\
		b->nle_flink = f;		\
		f->nle_blink = b;		\
	} while (0)

/* These two have to be inlined since they return things. */
static __inline__ list_entry *
RemoveHeadList(list_entry *l)
{
	list_entry *f;
	list_entry *e;

	e = l->nle_flink;
	f = e->nle_flink;
	l->nle_flink = f;
	f->nle_blink = l;

	return (e);
}

static __inline__ list_entry *
RemoveTailList(list_entry *l)
{
	list_entry *b;
	list_entry *e;

	e = l->nle_blink;
	b = e->nle_blink;
	l->nle_blink = b;
	b->nle_flink = l;

	return (e);
}

#define	InsertTailList(l, e)			\
	do {					\
		list_entry *b;			\
						\
		b = l->nle_blink;		\
		e->nle_flink = l;		\
		e->nle_blink = b;		\
		b->nle_flink = (e);		\
		l->nle_blink = (e);		\
	} while (0)

#define	InsertHeadList(l, e)			\
	do {					\
		list_entry *f;			\
						\
		f = l->nle_flink;		\
		e->nle_flink = f;		\
		e->nle_blink = l;		\
		f->nle_blink = e;		\
		l->nle_flink = e;		\
	} while (0)

#define	CONTAINING_RECORD(addr, type, field)	\
	((type *)((vm_offset_t)(addr) - (vm_offset_t)(&((type *)0)->field)))

struct nt_dispatch_header {
	uint8_t		dh_type;
	uint8_t		dh_abs;
	uint8_t		dh_size;
	uint8_t		dh_inserted;
	int32_t		dh_sigstate;
	list_entry	dh_waitlisthead;
};
typedef struct nt_dispatch_header nt_dispatch_header;

/* Dispatcher object types */
#define	DISP_TYPE_NOTIFICATION_EVENT	0	/* KEVENT */
#define	DISP_TYPE_SYNCHRONIZATION_EVENT	1	/* KEVENT */
#define	DISP_TYPE_MUTANT		2	/* KMUTANT/KMUTEX */
#define	DISP_TYPE_PROCESS		3	/* KPROCESS */
#define	DISP_TYPE_QUEUE			4	/* KQUEUE */
#define	DISP_TYPE_SEMAPHORE		5	/* KSEMAPHORE */
#define	DISP_TYPE_THREAD		6	/* KTHREAD */
#define	DISP_TYPE_NOTIFICATION_TIMER	8	/* KTIMER */
#define	DISP_TYPE_SYNCHRONIZATION_TIMER	9	/* KTIMER */

#define	OTYPE_EVENT	0
#define	OTYPE_MUTEX	1
#define	OTYPE_THREAD	2
#define	OTYPE_TIMER	3

/* Windows dispatcher levels. */
#define	PASSIVE_LEVEL	0
#define	LOW_LEVEL	0
#define	APC_LEVEL	1
#define	DISPATCH_LEVEL	2
#define	DEVICE_LEVEL	(DISPATCH_LEVEL + 1)
#define	PROFILE_LEVEL	27
#define	CLOCK1_LEVEL	28
#define	CLOCK2_LEVEL	28
#define	IPI_LEVEL	29
#define	POWER_LEVEL	30
#define	HIGH_LEVEL	31

#define	SYNC_LEVEL_UP DISPATCH_LEVEL
#define	SYNC_LEVEL_MP (IPI_LEVEL - 1)

#define	AT_PASSIVE_LEVEL(td) ((td)->td_proc->p_flag & P_KTHREAD == FALSE)
#define	AT_DISPATCH_LEVEL(td) ((td)->td_base_pri == PI_REALTIME)
#define	AT_DIRQL_LEVEL(td) ((td)->td_priority <= PI_NET)
#define	AT_HIGH_LEVEL(td) ((td)->td_critnest != 0)

struct nt_objref {
	nt_dispatch_header	no_dh;
	void			*no_obj;
	TAILQ_ENTRY(nt_objref)	link;
};
TAILQ_HEAD(nt_objref_head, nt_objref);
typedef struct nt_objref nt_objref;

#define	EVENT_TYPE_NOTIFY 0
#define	EVENT_TYPE_SYNC 1

/*
 * We need to use the timeout()/untimeout() API for ktimers
 * since timers can be initialized, but not destroyed (so
 * malloc()ing our own callout structures would mean a leak,
 * since there'd be no way to free() them). This means we
 * need to use struct callout_handle, which is really just a
 * pointer. To make it easier to deal with, we use a union
 * to overlay the callout_handle over the k_timerlistentry.
 * The latter is a list_entry, which is two pointers, so
 * there's enough space available to hide a callout_handle
 * there.
 */
struct ktimer {
	nt_dispatch_header	k_header;
	uint64_t		k_duetime;
	union {
		list_entry	k_timerlistentry;
		struct callout	*k_callout;
	} u;
	void			*k_dpc;
	uint32_t 		k_period;
};

#define	k_timerlistentry u.k_timerlistentry
#define	k_callout u.k_callout

typedef struct ktimer ktimer;

struct nt_kevent {
	nt_dispatch_header	k_header;
};
typedef struct nt_kevent nt_kevent;

/* Kernel defered procedure call (i.e. timer callback) */
struct kdpc;
typedef void (*kdpc_func)(struct kdpc *, void *, void *, void *);

struct kdpc {
	uint16_t	k_type;
	uint8_t		k_num;		/* CPU number */
	uint8_t		k_importance;	/* priority */
	list_entry	k_dpclistentry;
	void		*k_deferedfunc;
	void		*k_deferredctx;
	void		*k_sysarg1;
	void		*k_sysarg2;
	void		*k_lock;
};
typedef struct kdpc kdpc;

#define	KDPC_IMPORTANCE_LOW 0
#define	KDPC_IMPORTANCE_MEDIUM 1
#define	KDPC_IMPORTANCE_HIGH 2

#define	KDPC_CPU_DEFAULT 255

/*
 * Note: the acquisition count is BSD-specific. The Microsoft
 * documentation says that mutexes can be acquired recursively
 * by a given thread, but that you must release the mutex as
 * many times as you acquired it before it will be set to the
 * signalled state (i.e. before any other threads waiting on
 * the object will be woken up). However the Windows KMUTANT
 * structure has no field for keeping track of the number of
 * acquisitions, so we need to add one ourselves. As long as
 * driver code treats the mutex as opaque, we should be ok.
 */
struct kmutant {
	nt_dispatch_header	km_header;
	list_entry		km_listentry;
	void			*km_ownerthread;
	uint8_t			km_abandoned;
	uint8_t			km_apcdisable;
};
typedef struct kmutant kmutant;

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
	MM_NON_CACHED = 0,
	MM_CACHED,
	MM_WRITE_COMBINED,
	MM_HARDWARE_COHERENT_CACHED,
	MM_NON_CACHED_UNORDERED,
	MM_USWC_CACHED
};

#define	LOOKASIDE_DEPTH 256

struct general_lookaside {
	slist_header	list_head;
	uint16_t	depth;
	uint16_t	maximum_depth;
	uint32_t	total_alocates;
	union {
		uint32_t	allocate_misses;
		uint32_t	allocate_hits;
	} u_a;
	uint32_t	total_frees;
	union {
		uint32_t	free_misses;
		uint32_t	free_hits;
	} u_f;
	enum pool_type	type;
	uint32_t	tag;
	uint32_t	size;
	void		*allocfunc;
	void		*freefunc;
	list_entry	listent;
	uint32_t	last_total_allocates;
	union {
		uint32_t	last_allocate_misses;
		uint32_t	last_allocate_hits;
	} u_l;
	uint32_t	feature[2];
};

struct npaged_lookaside_list {
	struct general_lookaside	nll_l;
#ifdef __i386__
	kspin_lock		nll_obsoletelock;
#endif
};

typedef struct npaged_lookaside_list npaged_lookaside_list;

typedef void * (*lookaside_alloc_func)(uint32_t, size_t, uint32_t);
typedef void (*lookaside_free_func)(void *);

struct irp;

struct kdevice_qentry {
	list_entry	kqe_devlistent;
	uint32_t	kqe_sortkey;
	uint8_t		kqe_inserted;
};
typedef struct kdevice_qentry kdevice_qentry;

struct kdevice_queue {
	uint16_t	kq_type;
	uint16_t	kq_size;
	list_entry	kq_devlisthead;
	kspin_lock	kq_lock;
	uint8_t		kq_busy;
};
typedef struct kdevice_queue kdevice_queue;

struct wait_ctx_block {
	kdevice_qentry	wcb_waitqueue;
	void		*wcb_devfunc;
	void		*wcb_devctx;
	uint32_t	wcb_mapregcnt;
	void		*wcb_devobj;
	void		*wcb_curirp;
	void		*wcb_bufchaindpc;
};
typedef struct wait_ctx_block wait_ctx_block;

struct wait_block {
	list_entry		wb_waitlist;
	void			*wb_kthread;
	nt_dispatch_header	*wb_object;
	struct wait_block	*wb_next;
#ifdef notdef
	uint16_t		wb_waitkey;
	uint16_t		wb_waittype;
#endif
	uint8_t			wb_waitkey;
	uint8_t			wb_waittype;
	uint8_t			wb_awakened;
	uint8_t			wb_oldpri;
};
typedef struct wait_block wait_block;

#define	wb_ext wb_kthread

#define	THREAD_WAIT_OBJECTS 3
#define	MAX_WAIT_OBJECTS 64

#define	WAITTYPE_ALL 0
#define	WAITTYPE_ANY 1

#define	WAITKEY_VALID 0x8000

/* kthread priority  */
#define	LOW_PRIORITY		0
#define	LOW_REALTIME_PRIORITY	16
#define	HIGH_PRIORITY		31

struct thread_context {
	void	*tc_thrctx;
	void	*tc_thrfunc;
};
typedef struct thread_context thread_context;

/* Forward declaration */
struct driver_object;
struct devobj_extension;

struct driver_extension {
	struct driver_object	*driver_object;
	void			*add_device;
	uint32_t		count;
	unicode_string		service_key_name;

	/*
	 * Drivers are allowed to add one or more custom extensions
	 * to the driver object, but there's no special pointer
	 * for them. Hang them off here for now.
	 */
	list_entry 		usrext;
};

struct custom_extension {
	list_entry	ce_list;
	void		*ce_clid;
};
typedef struct custom_extension custom_extension;

/*
 * The KINTERRUPT structure in Windows is opaque to drivers.
 * We define our own custom version with things we need.
 */
struct kinterrupt {
	list_entry	ki_list;
	device_t	ki_dev;
	int		ki_rid;
	void		*ki_cookie;
	struct		resource *ki_irq;
	kspin_lock	ki_lock_priv;
	kspin_lock	*ki_lock;
	void		*ki_svcfunc;
	void		*ki_svcctx;
};
typedef struct kinterrupt kinterrupt;

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
		list_entry	listent;
		wait_ctx_block	wcb;
	} queue;
	uint32_t		alignreq;
	kdevice_queue		devqueue;
	struct			kdpc dpc;
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
	uint16_t	apc_type;
	uint16_t	apc_size;
	uint32_t	apc_spare0;
	void		*apc_thread;
	list_entry	apc_list;
	void		*apc_kernfunc;
	void		*apc_rundownfunc;
	void		*apc_normalfunc;
	void		*apc_normctx;
	void		*apc_sysarg1;
	void		*apc_sysarg2;
	uint8_t		apc_stateidx;
	uint8_t		apc_cpumode;
	uint8_t		apc_inserted;
};
typedef struct kapc kapc;

typedef uint32_t (*completion_func)(struct device_object *, struct irp *, void *);
typedef uint32_t (*cancel_func)(struct device_object *, struct irp *);

struct io_stack_location {
	uint8_t		major;
	uint8_t		minor;
	uint8_t		flags;
	uint8_t		ctl;

	/*
	 * There's a big-ass union here in the actual Windows
	 * definition of the stucture, but it contains stuff
	 * that doesn't really apply to BSD, and defining it
	 * all properly would require duplicating over a dozen
	 * other structures that we'll never use. Since the
	 * io_stack_location structure is opaque to drivers
	 * anyway, I'm not going to bother with the extra crap.
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
	mdl			*mdl;
	uint32_t		flags;
	union {
		struct irp	*master;
		uint32_t	irpcnt;
		void		*sysbuf;
	} assoc;
	list_entry		thlist;
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
	nt_kevent		*usrevent;
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
				kdevice_qentry	dqe;
				struct {
					void	*drvctx[4];
				} s1;
			} u1;
			void	*thread;
			char	*auxbuf;
			struct {
				list_entry list;
				union {
					struct io_stack_location	*csl;
					uint32_t			pkttype;
				} u2;
			} s2;
			void	*fileobj;
		} overlay;
		union {
			kapc	apc;
			struct {
				void	*ep;
				void	*dev;
			} usb;
		} misc;
		void	*compkey;
	} tail;
};
typedef struct irp irp;

#define	IRP_NDIS_DEV(irp) (irp)->tail.misc.usb.dev
#define	IRP_NDISUSB_EP(irp) (irp)->tail.misc.usb.ep

#define	InterlockedExchangePointer(dst, val)				\
	(void *)InterlockedExchange((uint32_t *)(dst), (uintptr_t)(val))

#define	IoSizeOfIrp(ssize)						\
	((uint16_t) (sizeof(irp) +					\
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

typedef uint32_t (*driver_dispatch)(struct device_object *, irp *);

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
	unicode_string		driver_name;
	unicode_string		*hardware_database;
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
	io_workitem_func	iw_func;
	void			*iw_ctx;
	list_entry		iw_listentry;
	struct device_object	*iw_dobj;
	int			iw_idx;
};
typedef struct io_workitem io_workitem;

enum work_queue_type {
	WORKQUEUE_CRITICAL,
	WORKQUEUE_DELAYED,
	WORKQUEUE_HYPERCRITICAL
};

#define	WORKITEM_THREADS	4
#define	WORKITEM_LEGACY_THREAD	3
#define	WORKIDX_INC(x)		(x) = (x + 1) % WORKITEM_LEGACY_THREAD

/*
 * Older, deprecated work item API, needed to support NdisQueueWorkItem().
 */
struct work_queue_item;

typedef void (*work_item_func)(struct work_queue_item *, void *);

struct work_queue_item {
	list_entry	wqi_entry;
	work_item_func	wqi_func;
	void		*wqi_ctx;
};
typedef struct work_queue_item work_queue_item;

#define	ExInitializeWorkItem(w, func, ctx)		\
	do {						\
		(w)->wqi_func = (func);			\
		(w)->wqi_ctx = (ctx);			\
		InitializeListHead(&((w)->wqi_entry));	\
	} while (0)

/*
 * FreeBSD's kernel stack is 2 pages in size by default. The
 * Windows stack is larger, so we need to give our threads more
 * stack pages. 4 should be enough, we use 8 just to extra safe.
 */
#define	NDIS_KSTACK_PAGES	8

/*
 * Different kinds of function wrapping we can do.
 */
#define	WINDRV_WRAP_STDCALL	1
#define	WINDRV_WRAP_FASTCALL	2
#define	WINDRV_WRAP_REGPARM	3
#define	WINDRV_WRAP_CDECL	4
#define	WINDRV_WRAP_AMD64	5

struct drvdb_ent {
	struct driver_object		*windrv_object;
	void				*windrv_devlist;
	struct ndis_cfg			*windrv_regvals;
	enum ndis_interface_type	windrv_bustype;
	STAILQ_ENTRY(drvdb_ent)	link;
};

extern struct image_patch_table ntoskrnl_functbl[];
#ifdef __amd64__
extern struct kuser_shared_data kuser_shared_data;
#endif
typedef void (*funcptr)(void);
typedef int (*matchfuncptr)(enum ndis_interface_type, void *, void *);

void	windrv_libinit(void);
void	windrv_libfini(void);
struct drvdb_ent	*windrv_match(matchfuncptr, void *);
int	windrv_load(module_t, vm_offset_t, size_t, enum ndis_interface_type,
	    void *, void *);
int	windrv_unload(module_t, vm_offset_t);
int32_t	windrv_create_pdo(struct driver_object *, device_t);
void	windrv_destroy_pdo(struct driver_object *, device_t);
int	windrv_bus_attach(struct driver_object *, const char *);
void	windrv_wrap(funcptr, funcptr *, uint8_t, uint8_t);
void	windrv_unwrap(funcptr);
void	windrv_wrap_table(struct image_patch_table *);
void	windrv_unwrap_table(struct image_patch_table *);
void	ctxsw_utow(void);
void	ctxsw_wtou(void);
void	ntoskrnl_libinit(void);
void	ntoskrnl_libfini(void);
void	ntoskrnl_intr(void *);
void	ntoskrnl_time(uint64_t *);
uint16_t ExQueryDepthSList(slist_header *);
slist_entry *InterlockedPushEntrySList(slist_header *, slist_entry *);
slist_entry *InterlockedPopEntrySList(slist_header *);
int32_t	RtlUnicodeStringToAnsiString(ansi_string *, const unicode_string *,
	    uint8_t);
int32_t	RtlAnsiStringToUnicodeString(unicode_string *, const ansi_string *,
	    uint8_t);
void	RtlInitAnsiString(ansi_string *, const char *);
void	RtlInitUnicodeString(unicode_string *, const uint16_t *);
void	RtlFreeUnicodeString(unicode_string *);
void	RtlFreeAnsiString(ansi_string *);
void	KeInitializeDpc(kdpc *, void *, void *);
uint8_t	KeInsertQueueDpc(kdpc *, void *, void *);
uint8_t	KeRemoveQueueDpc(kdpc *);
void	KeSetImportanceDpc(kdpc *, uint32_t);
void	KeSetTargetProcessorDpc(kdpc *, uint8_t);
void	KeFlushQueuedDpcs(void);
uint32_t	KeGetCurrentProcessorNumber(void);
void	KeInitializeTimer(ktimer *);
void	KeInitializeTimerEx(ktimer *, uint32_t);
uint8_t	KeSetTimer(ktimer *, int64_t, kdpc *);
uint8_t	KeSetTimerEx(ktimer *, int64_t, uint32_t, kdpc *);
uint8_t	KeCancelTimer(ktimer *);
uint8_t	KeReadStateTimer(ktimer *);
int32_t	KeWaitForSingleObject(void *, uint32_t, uint32_t, uint8_t, int64_t *);
void	KeInitializeEvent(nt_kevent *, uint32_t, uint8_t);
void	KeClearEvent(nt_kevent *);
int32_t	KeReadStateEvent(nt_kevent *);
int32_t	KeSetEvent(nt_kevent *, int32_t, uint8_t);
int32_t	KeResetEvent(nt_kevent *);
#ifdef __i386__
void	KefAcquireSpinLockAtDpcLevel(kspin_lock *);
void	KefReleaseSpinLockFromDpcLevel(kspin_lock *);
uint8_t	KeAcquireSpinLockRaiseToDpc(kspin_lock *);
#else
void	KeAcquireSpinLockAtDpcLevel(kspin_lock *);
void	KeReleaseSpinLockFromDpcLevel(kspin_lock *);
#endif
void	KeInitializeSpinLock(kspin_lock *);
uint8_t	KeAcquireInterruptSpinLock(kinterrupt *);
void	KeReleaseInterruptSpinLock(kinterrupt *, uint8_t);
uint8_t	KeSynchronizeExecution(kinterrupt *, void *, void *);
uintptr_t	InterlockedExchange(volatile uint32_t *, uintptr_t);
void	*ExAllocatePool(size_t);
void	ExFreePool(void *);
void	*MmMapIoSpace(uint64_t, uint32_t, enum memory_caching_type);
void	MmUnmapIoSpace(void *, size_t);
void	MmBuildMdlForNonPagedPool(mdl *);
void	IoDisconnectInterrupt(kinterrupt *);
void	*IoGetDriverObjectExtension(struct driver_object *, void *);
int32_t IoConnectInterrupt(kinterrupt **, void *, void *, kspin_lock *,
	    uint32_t, uint8_t, uint8_t, uint8_t, uint8_t, uint32_t, uint8_t);
int32_t	IoAllocateDriverObjectExtension(struct driver_object *, void *,
	    uint32_t, void **);
int32_t	IoCreateDevice(struct driver_object *, uint32_t, unicode_string *,
	    enum device_type, uint32_t, uint8_t, struct device_object **);
void	IoDeleteDevice(struct device_object *);
int32_t	IofCallDriver(struct device_object *, irp *);
void	IofCompleteRequest(irp *, uint8_t);
void	IoAcquireCancelSpinLock(uint8_t *);
void	IoReleaseCancelSpinLock(uint8_t);
void	IoDetachDevice(struct device_object *);
mdl	*IoAllocateMdl(void *, uint32_t, uint8_t, uint8_t, irp *);
void	IoFreeMdl(mdl *);
void	ExQueueWorkItem(work_queue_item *, enum work_queue_type);
void	IoFreeWorkItem(io_workitem *);
void	IoQueueWorkItem(io_workitem *, io_workitem_func, enum work_queue_type,
	    void *);
io_workitem	*IoAllocateWorkItem(struct device_object *);
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
