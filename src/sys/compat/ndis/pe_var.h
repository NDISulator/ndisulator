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

#ifndef _PE_VAR_H_
#define	_PE_VAR_H_

/* Image Format */
#define	IMAGE_DOS_SIGNATURE	0x5A4D		/* MZ */
#define	IMAGE_OS2_SIGNATURE	0x454E		/* NE */
#define	IMAGE_OS2_SIGNATURE_LE	0x454C		/* LE */
#define	IMAGE_VXD_SIGNATURE	0x454C		/* LE */
#define	IMAGE_NT_SIGNATURE	0x00004550	/* PE00 */

struct image_dos_header {
	uint16_t	e_magic;	/* Magic number */
	uint16_t	e_cblp;		/* Bytes on last page of file */
	uint16_t	e_cp;		/* Pages in file */
	uint16_t	e_crlc;		/* Relocations */
	uint16_t	e_cparhdr;	/* Size of header in paragraphs */
	uint16_t	e_minalloc;	/* Minimum extra paragraphs needed */
	uint16_t	e_maxalloc;	/* Maximum extra paragraphs needed */
	uint16_t	e_ss;		/* Initial (relative) SS value */
	uint16_t	e_sp;		/* Initial SP value */
	uint16_t	e_csum;		/* Checksum */
	uint16_t	e_ip;		/* Initial IP value */
	uint16_t	e_cs;		/* Initial (relative) CS value */
	uint16_t	e_lfarlc;	/* File address of relocation table */
	uint16_t	e_ovno;		/* Overlay number */
	uint16_t	e_res[4];	/* Reserved words */
	uint16_t	e_oemid;	/* OEM identifier (for oeminfo) */
	uint16_t	e_oeminfo;	/* OEM information; oemid specific */
	uint16_t	e_res2[10];	/* Reserved words */
	uint32_t	e_lfanew;	/* File address of new exe header */
};

struct image_file_header {
	uint16_t	machine;
	uint16_t	number_of_sections;
	uint32_t	time_date_stamp;
	uint32_t	pointer_to_symbol_table;
	uint32_t	number_of_symbols;
	uint16_t	size_of_optional_header;
	uint16_t	characteristics;
};

/* Machine types */
#define	IMAGE_FILE_MACHINE_UNKNOWN	0x0000
#define	IMAGE_FILE_MACHINE_I860		0x014d
#define	IMAGE_FILE_MACHINE_I386		0x014c
#define	IMAGE_FILE_MACHINE_R3000	0x0162
#define	IMAGE_FILE_MACHINE_R4000	0x0166
#define	IMAGE_FILE_MACHINE_R10000	0x0168
#define	IMAGE_FILE_MACHINE_WCEMIPSV2	0x0169
#define	IMAGE_FILE_MACHINE_ALPHA	0x0184
#define	IMAGE_FILE_MACHINE_SH3		0x01a2
#define	IMAGE_FILE_MACHINE_SH3DSP	0x01a3
#define	IMAGE_FILE_MACHINE_SH3E		0x01a4
#define	IMAGE_FILE_MACHINE_SH4		0x01a6
#define	IMAGE_FILE_MACHINE_SH5		0x01a8
#define	IMAGE_FILE_MACHINE_ARM		0x01c0
#define	IMAGE_FILE_MACHINE_THUMB	0x01c2
#define	IMAGE_FILE_MACHINE_AM33		0x01d3
#define	IMAGE_FILE_MACHINE_POWERPC	0x01f0
#define	IMAGE_FILE_MACHINE_POWERPCFP	0x01f1
#define	IMAGE_FILE_MACHINE_IA64		0x0200
#define	IMAGE_FILE_MACHINE_MIPS16	0x0266
#define	IMAGE_FILE_MACHINE_ALPHA64	0x0284
#define	IMAGE_FILE_MACHINE_MIPSFPU	0x0366
#define	IMAGE_FILE_MACHINE_MIPSFPU16	0x0466
#define	IMAGE_FILE_MACHINE_AXP64	IMAGE_FILE_MACHINE_ALPHA64
#define	IMAGE_FILE_MACHINE_TRICORE	0x0520
#define	IMAGE_FILE_MACHINE_CEF		0x0cef
#define	IMAGE_FILE_MACHINE_EBC		0x0ebc
#define	IMAGE_FILE_MACHINE_AMD64	0x8664
#define	IMAGE_FILE_MACHINE_M32R		0x9041
#define	IMAGE_FILE_MACHINE_CEE		0xc0ee

/* Characteristics */
#define	IMAGE_FILE_RELOCS_STRIPPED		0x0001 /* No relocation info */
#define	IMAGE_FILE_EXECUTABLE_IMAGE		0x0002
#define	IMAGE_FILE_LINE_NUMS_STRIPPED		0x0004
#define	IMAGE_FILE_LOCAL_SYMS_STRIPPED		0x0008
#define	IMAGE_FILE_AGGRESIVE_WS_TRIM		0x0010
#define	IMAGE_FILE_LARGE_ADDRESS_AWARE		0x0020
#define	IMAGE_FILE_16BIT_MACHINE		0x0040
#define	IMAGE_FILE_BYTES_REVERSED_LO		0x0080
#define	IMAGE_FILE_32BIT_MACHINE		0x0100
#define	IMAGE_FILE_DEBUG_STRIPPED		0x0200
#define	IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP	0x0400
#define	IMAGE_FILE_NET_RUN_FROM_SWAP		0x0800
#define	IMAGE_FILE_SYSTEM			0x1000
#define	IMAGE_FILE_DLL				0x2000
#define	IMAGE_FILE_UP_SYSTEM_ONLY		0x4000
#define	IMAGE_FILE_BYTES_REVERSED_HI		0x8000

struct image_data_directory {
	uint32_t	virtual_address;
	uint32_t	size;
};

#define	IMAGE_DIRECTORY_ENTRIES_MAX	16

struct image_optional_header {
	/* Standard fields */
	uint16_t	magic;
	uint8_t		mayor_linker_version;
	uint8_t		minor_linker_version;
	uint32_t	size_of_code;
	uint32_t	size_of_initialized_data;
	uint32_t	size_of_uninitialized_data;
	uint32_t	address_of_entry_point;
	uint32_t	base_of_code;
#ifndef __amd64__
	uint32_t	base_of_data;
#endif
	/* NT-specific fields */
	uintptr_t	image_base;
	uint32_t	section_aligment;
	uint32_t	file_aligment;
	uint16_t	mayor_operating_system_version;
	uint16_t	minor_operating_system_version;
	uint16_t	mayor_image_version;
	uint16_t	minor_image_version;
	uint16_t	mayor_subsystem_version;
	uint16_t	minor_subsystem_version;
	uint32_t	win32_version_value;
	uint32_t	size_of_image;
	uint32_t	size_of_headers;
	uint32_t	check_sum;
	uint16_t	subsystem;
	uint16_t	dll_characteristics;
	uintptr_t	size_of_stack_reserve;
	uintptr_t	size_of_stack_commit;
	uintptr_t	size_of_heap_reserve;
	uintptr_t	size_of_heap_commit;
	uint32_t	loader_flags;
	uint32_t	number_of_rva_and_sizes;
	struct image_data_directory	data_directory[IMAGE_DIRECTORY_ENTRIES_MAX];
};

/* Magic */
#define	IMAGE_OPTIONAL_MAGIC_32			0x010B
#define	IMAGE_OPTIONAL_MAGIC_64			0x020B

struct image_nt_header {
	uint32_t			signature;
	struct image_file_header	file_header;
	struct image_optional_header	optional_header;
};

enum image_directory_entry {
	IMAGE_DIRECTORY_ENTRY_EXPORT,
	IMAGE_DIRECTORY_ENTRY_IMPORT,
	IMAGE_DIRECTORY_ENTRY_RESOURCE,
	IMAGE_DIRECTORY_ENTRY_EXCEPTION,
	IMAGE_DIRECTORY_ENTRY_SECURITY,
	IMAGE_DIRECTORY_ENTRY_BASERELOC,
	IMAGE_DIRECTORY_ENTRY_DEBUG,
	IMAGE_DIRECTORY_ENTRY_COPYRIGHT,
	IMAGE_DIRECTORY_ENTRY_GLOBALPTR,
	IMAGE_DIRECTORY_ENTRY_TLS,
	IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
	IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT,
	IMAGE_DIRECTORY_ENTRY_IAT,
	IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
	IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
};

/* Resource types */
#define	RT_CURSOR	1
#define	RT_BITMAP	2
#define	RT_ICON		3
#define	RT_MENU		4
#define	RT_DIALOG	5
#define	RT_STRING	6
#define	RT_FONTDIR	7
#define	RT_FONT		8
#define	RT_ACCELERATOR	9
#define	RT_RCDATA	10
#define	RT_MESSAGETABLE	11
#define	RT_GROUP_CURSOR	12
#define	RT_GROUP_ICON	14
#define	RT_VERSION	16
#define	RT_DLGINCLUDE	17
#define	RT_PLUGPLAY	19
#define	RT_VXD		20
#define	RT_ANICURSOR	21
#define	RT_ANIICON	22
#define	RT_HTML		23

/* Section header format */
#define	IMAGE_SHORT_NAME_LEN	8

struct image_section_header {
	uint8_t		name[IMAGE_SHORT_NAME_LEN];
	union {
		uint32_t	physical_address;
		uint32_t	virtual_size;
	} misc;
	uint32_t	virtual_address;
	uint32_t	size_of_raw_data;
	uint32_t	pointer_to_raw_data;
	uint32_t	pointer_to_relocations;
	uint32_t	pointer_to_linenumbers;
	uint16_t	number_of_relocations;
	uint16_t	number_of_linenumbers;
	uint32_t	characteristics;
};

/* Import format */
struct image_import_by_name {
	uint16_t	hint;
	uint8_t		name[1];
};

#ifdef __i386__
#define	IMAGE_ORDINAL_FLAG	0x80000000
#endif

#ifdef __amd64__
#define	IMAGE_ORDINAL_FLAG	0x8000000000000000UL
#endif

struct image_import_descriptor {
	union {
		uint32_t	characteristics;
		uint32_t	original_first_thunk;
	} u;
	uint32_t	time_data_stamp;
	uint32_t	forward_chain;
	uint32_t	name;
	uint32_t	first_thunk;
};

struct image_base_relocation {
	uint32_t	virtual_address;
	uint32_t	size_of_block;
	uint16_t	type_offset[1];
};

#define	IMR_RELTYPE(x)		((x >> 12) & 0xF)
#define	IMR_RELOFFSET(x)	(x & 0xFFF)

/* Generic relocation types */
#define	IMAGE_REL_BASED_ABSOLUTE		0
#define	IMAGE_REL_BASED_HIGH			1
#define	IMAGE_REL_BASED_LOW			2
#define	IMAGE_REL_BASED_HIGHLOW			3
#define	IMAGE_REL_BASED_HIGHADJ			4
#define	IMAGE_REL_BASED_MIPS_JMPADDR		5
#define	IMAGE_REL_BASED_SECTION			6
#define	IMAGE_REL_BASED_REL			7
#define	IMAGE_REL_BASED_MIPS_JMPADDR16		9
#define	IMAGE_REL_BASED_IA64_IMM64		9 /* yes, 9 too */
#define	IMAGE_REL_BASED_DIR64			10
#define	IMAGE_REL_BASED_HIGH3ADJ		11

struct image_resource_directory_entry {
	uint32_t	name;
	uint32_t	dataoff;
};

#define	RESOURCE_NAME_STR	0x80000000
#define	RESOURCE_DIR_FLAG	0x80000000

struct image_resource_directory {
	uint32_t	characteristics;
	uint32_t	time_date_stamp;
	uint16_t	major_version;
	uint16_t	minor_version;
	uint16_t	number_of_named_entries;
	uint16_t	number_of_id_entries;
	/* struct image_resource_directory_entry	directory_entries[1]; */
};

struct image_resource_directory_string {
	uint16_t	length;
	char		name_string[1];
};

struct image_resource_data_entry {
	uint32_t	offset_to_data;
	uint32_t	size;
	uint32_t	code_page;
	uint32_t	reserved;
};

struct message_resource_data {
	uint32_t			numblocks;
	/* struct message_resource_block	blocks[1]; */
};

struct message_resource_block {
	uint32_t	lowid;
	uint32_t	highid;
	uint32_t	entryoff;
};

struct message_resource_entry {
	uint16_t	len;
	uint16_t	flags;
	char		text[];
};

#define	MESSAGE_RESOURCE_UNICODE	0x0001

struct image_patch_table {
	char	*name;
	void	(*func)(void);
	void	(*wrap)(void);
	uint8_t	argcnt;
	uint8_t	ftype;
};

/*
 * AMD64 support. Microsoft uses a different calling convention
 * than everyone else on the amd64 platform. Sadly, gcc has no
 * built-in support for it (yet).
 *
 * The three major differences we're concerned with are:
 *
 * - The first 4 register-sized arguments are passed in the
 *   %rcx, %rdx, %r8 and %r9 registers, and the rest are pushed
 *   onto the stack. (The ELF ABI uses 6 registers, not 4).
 *
 * - The caller must reserve space on the stack for the 4
 *   register arguments in case the callee has to spill them.
 *
 * - The stack must be 16-byte aligned by the time the caller
 *   executes. A call instruction implicitly pushes an 8 byte
 *   return address onto the stack. We have to make sure that
 *   the amount of space we consume, plus the return address,
 *   is a multiple of 16 bytes in size. This means that in
 *   some cases, we may need to chew up an extra 8 bytes on
 *   the stack that will be unused.
 *
 * On the bright side, Microsoft seems to be using just the one
 * calling convention for all functions on amd64, unlike x86 where
 * they use a mix of _stdcall, _fastcall and _cdecl.
 */

#define	FUNC void(*)(void)

#ifdef __amd64__
uint64_t x86_64_call1(void *, uint64_t);
uint64_t x86_64_call2(void *, uint64_t, uint64_t);
uint64_t x86_64_call3(void *, uint64_t, uint64_t, uint64_t);
uint64_t x86_64_call4(void *, uint64_t, uint64_t, uint64_t, uint64_t);
uint64_t x86_64_call5(void *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
uint64_t x86_64_call6(void *, uint64_t, uint64_t, uint64_t, uint64_t,
    uint64_t, uint64_t);

#define	MSCALL1(fn, a)							\
	x86_64_call1((fn), (uint64_t)(a))
#define	MSCALL2(fn, a, b)						\
	x86_64_call2((fn), (uint64_t)(a), (uint64_t)(b))
#define	MSCALL3(fn, a, b, c)						\
	x86_64_call3((fn), (uint64_t)(a), (uint64_t)(b), (uint64_t)(c))
#define	MSCALL4(fn, a, b, c, d)						\
	x86_64_call4((fn), (uint64_t)(a), (uint64_t)(b),		\
	(uint64_t)(c), (uint64_t)(d))
#define	MSCALL5(fn, a, b, c, d, e)					\
	x86_64_call5((fn), (uint64_t)(a), (uint64_t)(b),		\
	(uint64_t)(c), (uint64_t)(d), (uint64_t)(e))
#define	MSCALL6(fn, a, b, c, d, e, f)					\
	x86_64_call6((fn), (uint64_t)(a), (uint64_t)(b),		\
	(uint64_t)(c), (uint64_t)(d), (uint64_t)(e), (uint64_t)(f))

#define	IMPORT_SFUNC(x, y)	{ #x, (FUNC)x, NULL, y, WINDRV_WRAP_AMD64 }
#define	IMPORT_SFUNC_MAP(x, y, z)					\
				{ #x, (FUNC)y, NULL, z, WINDRV_WRAP_AMD64 }
#define	IMPORT_FFUNC(x, y)	{ #x, (FUNC)x, NULL, y, WINDRV_WRAP_AMD64 }
#define	IMPORT_FFUNC_MAP(x, y, z)					\
				{ #x, (FUNC)y, NULL, z, WINDRV_WRAP_AMD64 }
#define	IMPORT_RFUNC(x, y)	{ #x, (FUNC)x, NULL, y, WINDRV_WRAP_AMD64 }
#define	IMPORT_RFUNC_MAP(x, y, z)					\
				{ #x, (FUNC)y, NULL, z, WINDRV_WRAP_AMD64 }
#define	IMPORT_CFUNC(x, y)	{ #x, (FUNC)x, NULL, y, WINDRV_WRAP_AMD64 }
#define	IMPORT_CFUNC_MAP(x, y, z)					\
				{ #x, (FUNC)y, NULL, z, WINDRV_WRAP_AMD64 }
#endif /* __amd64__ */

#ifdef __i386__
uint32_t x86_stdcall_call(void *, int, ...);

#define	MSCALL1(fn, a)		x86_stdcall_call(fn, 1, (a))
#define	MSCALL2(fn, a, b)	x86_stdcall_call(fn, 2, (a), (b))
#define	MSCALL3(fn, a, b, c)	x86_stdcall_call(fn, 3, (a), (b), (c))
#define	MSCALL4(fn, a, b, c, d)	x86_stdcall_call(fn, 4, (a), (b), (c), (d))
#define	MSCALL5(fn, a, b, c, d, e)	\
		x86_stdcall_call(fn, 5, (a), (b), (c), (d), (e))
#define	MSCALL6(fn, a, b, c, d, e, f)	\
		x86_stdcall_call(fn, 6, (a), (b), (c), (d), (e), (f))

#define	IMPORT_SFUNC(x, y)	{ #x, (FUNC)x, NULL, y, WINDRV_WRAP_STDCALL }
#define	IMPORT_SFUNC_MAP(x, y, z)					\
				{ #x, (FUNC)y, NULL, z, WINDRV_WRAP_STDCALL }
#define	IMPORT_FFUNC(x, y)	{ #x, (FUNC)x, NULL, y, WINDRV_WRAP_FASTCALL }
#define	IMPORT_FFUNC_MAP(x, y, z)					\
				{ #x, (FUNC)y, NULL, z, WINDRV_WRAP_FASTCALL }
#define	IMPORT_RFUNC(x, y)	{ #x, (FUNC)x, NULL, y, WINDRV_WRAP_REGPARM }
#define	IMPORT_RFUNC_MAP(x, y, z)					\
				{ #x, (FUNC)y, NULL, z, WINDRV_WRAP_REGPARM }
#define	IMPORT_CFUNC(x, y)	{ #x, (FUNC)x, NULL, y, WINDRV_WRAP_CDECL }
#define	IMPORT_CFUNC_MAP(x, y, z)					\
				{ #x, (FUNC)y, NULL, z, WINDRV_WRAP_CDECL }
#endif /* __i386__ */

void	pe_get_optional_header(vm_offset_t, struct image_optional_header **);
void	pe_get_section_header(vm_offset_t, struct image_section_header **);
int	pe_get_message(vm_offset_t, uint32_t, char **, int *, uint16_t *);
int	pe_patch_imports(vm_offset_t, const char *, struct image_patch_table *);
int	pe_numsections(vm_offset_t);
int	pe_relocate(vm_offset_t);
int	pe_validate_header(vm_offset_t);
vm_offset_t pe_translate_addr(vm_offset_t, vm_offset_t);

#endif /* _PE_VAR_H_ */
