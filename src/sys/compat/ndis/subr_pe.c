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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

/*
 * This file contains routines for relocating and dynamically linking
 * executable object code files in the Windows(r) PE (Portable Executable)
 * format. In Windows, anything with a .EXE, .DLL or .SYS extention is
 * considered an executable, and all such files have some structures in
 * common. The PE format was apparently based largely on COFF but has
 * mutated significantly over time. We are mainly concerned with .SYS files,
 * so this module implements only enough routines to be able to parse the
 * headers and sections of a .SYS object file and perform the necessary
 * relocations and jump table patching to allow us to call into it
 * (and to have it call back to us). Note that while this module can handle
 * fixups for imported symbols, it knows nothing about exporting them.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/errno.h>
#ifdef _KERNEL
#include <sys/systm.h>
#else
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define KASSERT(exp, msg) do {		\
	if (!(exp)) 			\
		return (EINVAL);	\
} while (0)
#endif

#include <compat/ndis/pe_var.h>

static vm_offset_t pe_functbl_match(struct image_patch_table *, char *);

/*
 * Verify that this image has a Windows NT PE signature.
 */
static int
pe_is_nt_image(vm_offset_t imgbase)
{
	uint32_t signature;
	struct image_dos_header *dos_hdr;

	KASSERT(imgbase != 0, ("bad imgbase"));

	signature = *(uint16_t *)imgbase;
	if (signature == IMAGE_DOS_SIGNATURE) {
		dos_hdr = (struct image_dos_header *)imgbase;
		signature = *(uint32_t *)(imgbase + dos_hdr->e_lfanew);
		if (signature == IMAGE_NT_SIGNATURE)
			return (0);
	}

	return (ENOEXEC);
}

/*
 * Return a copy of the optional header. This contains the
 * executable entry point and the directory listing which we
 * need to find the relocations and imports later.
 */
int
pe_get_optional_header(vm_offset_t imgbase, struct image_optional_header *hdr)
{
	struct image_dos_header *dos_hdr;
	struct image_nt_header *nt_hdr;

	KASSERT(imgbase != 0, ("bad imgbase"));
	KASSERT(hdr != NULL, ("no hdr"));

	dos_hdr = (struct image_dos_header *)(imgbase);
	nt_hdr = (struct image_nt_header *)(imgbase + dos_hdr->e_lfanew);

	bcopy((char *)&nt_hdr->optional_header, (char *)hdr,
	    nt_hdr->file_header.size_of_optional_header);
	return (0);
}

static int
pe_get_file_header(vm_offset_t imgbase, struct image_file_header **hdr)
{
	struct image_dos_header *dos_hdr;
	struct image_nt_header *nt_hdr;

	KASSERT(imgbase != 0, ("bad imgbase"));
	KASSERT(hdr != NULL, ("no hdr"));

	dos_hdr = (struct image_dos_header *)imgbase;
	nt_hdr = (struct image_nt_header *)(imgbase + dos_hdr->e_lfanew);

	*hdr = &nt_hdr->file_header;
	return (0);
}

int
pe_validate_header(vm_offset_t imgbase)
{
	struct image_file_header *file_hdr;
	struct image_optional_header opt_hdr;

	if (pe_is_nt_image(imgbase))
		return (EINVAL);
	if (pe_get_file_header(imgbase, &file_hdr))
		return (EINVAL);
	if (!(file_hdr->characteristics & IMAGE_FILE_EXECUTABLE_IMAGE))
		return (ENOEXEC);
	if (file_hdr->characteristics & IMAGE_FILE_RELOCS_STRIPPED)
		return (ENOEXEC);
#ifdef __amd64__
	if (file_hdr->machine != IMAGE_FILE_MACHINE_AMD64)
		return (ENOEXEC);
#endif
#ifdef __i386__
	if (file_hdr->machine != IMAGE_FILE_MACHINE_I386)
		return (ENOEXEC);
#endif
	if (file_hdr->number_of_sections == 0)
		return (ENOEXEC);
	if (pe_get_optional_header(imgbase, &opt_hdr))
		return (EINVAL);
#ifdef __amd64__
	if (opt_hdr.magic != IMAGE_OPTIONAL_MAGIC_64)
		return (ENOEXEC);
#endif
#ifdef __i386__
	if (opt_hdr.magic != IMAGE_OPTIONAL_MAGIC_32)
		return (ENOEXEC);
#endif
	return (0);
}

/*
 * Return the number of sections in this executable, or 0 on error.
 */
int
pe_numsections(vm_offset_t imgbase)
{
	struct image_file_header *file_hdr;

	if (pe_get_file_header(imgbase, &file_hdr))
		return (0);

	return (file_hdr->number_of_sections);
}

/*
 * Return the base address that this image was linked for.
 * This helps us calculate relocation addresses later.
 */
static vm_offset_t
pe_imagebase(vm_offset_t imgbase)
{
	struct image_optional_header optional_hdr;

	if (pe_get_optional_header(imgbase, &optional_hdr))
		return (0);

	return (optional_hdr.image_base);
}

/*
 * Return the offset of a given directory structure within the
 * image. Directories reside within sections.
 */
static vm_offset_t
pe_directory_offset(vm_offset_t imgbase, uint32_t diridx)
{
	struct image_optional_header opt_hdr;
	vm_offset_t dir;

	if (pe_get_optional_header(imgbase, &opt_hdr))
		return (0);

	if (diridx >= opt_hdr.number_of_rva_and_sizes)
		return (0);

	dir = opt_hdr.data_directory[diridx].virtual_address;

	return (pe_translate_addr(imgbase, dir));
}

vm_offset_t
pe_translate_addr(vm_offset_t imgbase, vm_offset_t rva)
{
	struct image_optional_header opt_hdr;
	struct image_section_header *sect_hdr;
	struct image_dos_header *dos_hdr;
	struct image_nt_header *nt_hdr;
	int i = 0, sections, fixedlen;

	if (pe_get_optional_header(imgbase, &opt_hdr))
		return (0);

	sections = pe_numsections(imgbase);

	dos_hdr = (struct image_dos_header *)imgbase;
	nt_hdr = (struct image_nt_header *)(imgbase + dos_hdr->e_lfanew);
	sect_hdr = IMAGE_FIRST_SECTION(nt_hdr);

	/*
	 * The test here is to see if the RVA falls somewhere
	 * inside the section, based on the section's start RVA
	 * and its length. However it seems sometimes the
	 * virtual length isn't enough to cover the entire
	 * area of the section. We fudge by taking into account
	 * the section alignment and rounding the section length
	 * up to a page boundary.
	 */
	while (i++ < sections) {
		fixedlen = sect_hdr->misc.virtual_size;
		fixedlen += ((opt_hdr.section_aligment - 1) -
		    sect_hdr->misc.virtual_size) &
		    (opt_hdr.section_aligment - 1);
		if (sect_hdr->virtual_address <= (uint32_t)rva &&
		    (sect_hdr->virtual_address + fixedlen) >
		    (uint32_t)rva)
			break;
		sect_hdr++;
	}

	if (i > sections)
		return (0);

	return ((vm_offset_t)(imgbase + rva - sect_hdr->virtual_address +
	    sect_hdr->pointer_to_raw_data));
}

/*
 * Get the section header for a particular section. Note that
 * section names can be anything, but there are some standard
 * ones (.text, .data, .rdata, .reloc).
 */
static int
pe_get_section(vm_offset_t imgbase, struct image_section_header *hdr,
    const char *name)
{
	struct image_dos_header *dos_hdr;
	struct image_nt_header *nt_hdr;
	struct image_section_header *sect_hdr;
	int i, sections;

	KASSERT(imgbase != 0, ("bad imgbase"));
	KASSERT(hdr != NULL, ("no hdr"));

	sections = pe_numsections(imgbase);

	dos_hdr = (struct image_dos_header *)imgbase;
	nt_hdr = (struct image_nt_header *)(imgbase + dos_hdr->e_lfanew);
	sect_hdr = IMAGE_FIRST_SECTION(nt_hdr);

	for (i = 0; i < sections; i++) {
		if (!strcmp((char *)&sect_hdr->name, name)) {
			bcopy((char *)sect_hdr, (char *)hdr,
			    sizeof(struct image_section_header));
			return (0);
		} else
			sect_hdr++;
	}
	return (ENOEXEC);
}

/*
 * Apply the base relocations to this image. The relocation table resides
 * within the .reloc section. Relocations are specified in blocks which refer
 * to a particular page. We apply the relocations one page block at a time.
 */
int
pe_relocate(vm_offset_t imgbase)
{
	struct image_section_header sect;
	struct image_base_relocation *relhdr;
	vm_offset_t base, txt;
	vm_size_t delta;
	uint64_t *qloc;
	uint32_t *lloc;
	uint16_t rel, *sloc;
	int i, count;

	base = pe_imagebase(imgbase);
	pe_get_section(imgbase, &sect, ".text");
	txt = pe_translate_addr(imgbase, sect.virtual_address);
	delta = (uint32_t)(txt) - base - sect.virtual_address;

	pe_get_section(imgbase, &sect, ".reloc");

	relhdr = (struct image_base_relocation *)(imgbase +
	    sect.pointer_to_raw_data);

	do {
		count = (relhdr->size_of_block -
		    (sizeof(uint32_t) * 2)) / sizeof(uint16_t);
		for (i = 0; i < count; i++) {
			rel = relhdr->type_offset[i];
			switch (IMR_RELTYPE(rel)) {
			case IMAGE_REL_BASED_ABSOLUTE:
				break;
			case IMAGE_REL_BASED_HIGHLOW:
				lloc = (uint32_t *)pe_translate_addr(imgbase,
				    relhdr->virtual_address +
				    IMR_RELOFFSET(rel));
				*lloc = pe_translate_addr(imgbase,
				    (*lloc - base));
				break;
			case IMAGE_REL_BASED_HIGH:
				sloc = (uint16_t *)pe_translate_addr(imgbase,
				    relhdr->virtual_address +
				    IMR_RELOFFSET(rel));
				*sloc += (delta & 0xFFFF0000) >> 16;
				break;
			case IMAGE_REL_BASED_LOW:
				sloc = (uint16_t *)pe_translate_addr(imgbase,
				    relhdr->virtual_address +
				    IMR_RELOFFSET(rel));
				*sloc += (delta & 0xFFFF);
				break;
			case IMAGE_REL_BASED_DIR64:
				qloc = (uint64_t *)pe_translate_addr(imgbase,
				    relhdr->virtual_address +
				    IMR_RELOFFSET(rel));
				*qloc = pe_translate_addr(imgbase,
				    (*qloc - base));
				break;
			default:
				printf("[%d]reloc type: %d\n",i,
				    IMR_RELTYPE(rel));
				break;
			}
		}
		relhdr = (struct image_base_relocation *)((vm_offset_t)relhdr +
		    relhdr->size_of_block);
	} while (relhdr->size_of_block);

	return (0);
}

/*
 * Return the import descriptor for a particular module. An image
 * may be linked against several modules, typically HAL.dll, ntoskrnl.exe
 * and NDIS.SYS. For each module, there is a list of imported function
 * names and their addresses.
 *
 * Note: module names are case insensitive!
 */
int
pe_get_import_descriptor(vm_offset_t imgbase,
    struct image_import_descriptor *desc, char *module)
{
	struct image_import_descriptor *imp_desc;
	vm_offset_t offset;
	char *modname;

	if (imgbase == 0 || module == NULL || desc == NULL)
		return (EINVAL);

	offset = pe_directory_offset(imgbase, IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (offset == 0)
		return (ENOENT);

	imp_desc = (void *)offset;

	while (imp_desc->name) {
		modname = (char *)pe_translate_addr(imgbase,
		    imp_desc->name);
		if (!strncasecmp(module, modname, strlen(module))) {
			bcopy((char *)imp_desc, (char *)desc,
			    sizeof(struct image_import_descriptor));
			return (0);
		}
		imp_desc++;
	}
	return (ENOENT);
}

static int
pe_get_messagetable(vm_offset_t imgbase, struct message_resource_data **md)
{
	struct image_resource_directory *rdir, *rtype;
	struct image_resource_directory_entry *dent, *dent2;
	struct image_resource_data_entry *rent;
	vm_offset_t offset;
	int i;

	KASSERT(imgbase != 0, ("bad imgbase"));

	offset = pe_directory_offset(imgbase, IMAGE_DIRECTORY_ENTRY_RESOURCE);
	if (offset == 0)
		return (ENOENT);

	rdir = (struct image_resource_directory *)offset;

	dent = (struct image_resource_directory_entry *)(offset +
	    sizeof(struct image_resource_directory));

	for (i = 0; i < rdir->number_of_id_entries; i++) {
		if (dent->name != RT_MESSAGETABLE) {
			dent++;
			continue;
		}
		dent2 = dent;
		while (dent2->dataoff & RESOURCE_DIR_FLAG) {
			rtype = (struct image_resource_directory *)(offset +
			    (dent2->dataoff & ~RESOURCE_DIR_FLAG));
			dent2 = (struct image_resource_directory_entry *)
			    ((uintptr_t)rtype +
			     sizeof(struct image_resource_directory));
		}
		rent = (struct image_resource_data_entry *)(offset +
		    dent2->dataoff);
		*md = (struct message_resource_data *)pe_translate_addr(imgbase,
		    rent->offset_to_data);
		return (0);
	}

	return (ENOENT);
}

int
pe_get_message(vm_offset_t imgbase, uint32_t id, char **str, int *len,
    uint16_t *flags)
{
	struct message_resource_data *md = NULL;
	struct message_resource_block *mb;
	struct message_resource_entry *me;
	uint32_t i;

	pe_get_messagetable(imgbase, &md);
	if (md == NULL)
		return (ENOENT);

	mb = (struct message_resource_block *)((uintptr_t)md +
	    sizeof(struct message_resource_data));

	for (i = 0; i < md->numblocks; i++) {
		if (id >= mb->lowid && id <= mb->highid) {
			me = (struct message_resource_entry *)((uintptr_t)md +
			    mb->entryoff);
			for (i = id - mb->lowid; i > 0; i--)
				me = (struct message_resource_entry *)
				    ((uintptr_t)me + me->len);
			*str = me->text;
			*len = me->len;
			*flags = me->flags;
			return (0);
		}
		mb++;
	}

	return (ENOENT);
}

/*
 * Find the function that matches a particular name. This doesn't
 * need to be particularly speedy since it's only run when loading
 * a module for the first time.
 */
static vm_offset_t
pe_functbl_match(struct image_patch_table *functbl, char *name)
{
	struct image_patch_table *p;

	if (functbl == NULL || name == NULL)
		return (0);
	p = functbl;

	while (p->name != NULL) {
		if (!strcmp(p->name, name))
			return ((vm_offset_t)p->wrap);
		p++;
	}
	printf("NDIS: no match for %s\n", name);

	/*
	 * Return the wrapper pointer for this routine.
	 * For x86, this is the same as the funcptr.
	 * For amd64, this points to a wrapper routine
	 * that does calling convention translation and
	 * then invokes the underlying routine.
	 */
	return ((vm_offset_t)p->wrap);
}

/*
 * Patch the imported function addresses for a given module.
 * The caller must specify the module name and provide a table
 * of function pointers that will be patched into the jump table.
 * Note that there are actually two copies of the jump table: one
 * copy is left alone. In a .SYS file, the jump tables are usually
 * merged into the INIT segment.
 */
int
pe_patch_imports(vm_offset_t imgbase, char *module,
     struct image_patch_table *functbl)
{
	struct image_import_descriptor imp_desc;
	char *fname;
	vm_offset_t *nptr, *fptr, func;

	if (imgbase == 0 || module == NULL || functbl == NULL)
		return (EINVAL);

	if (pe_get_import_descriptor(imgbase, &imp_desc, module))
		return (ENOEXEC);

	nptr = (vm_offset_t *)pe_translate_addr(imgbase,
	    imp_desc.u.original_first_thunk);
	fptr = (vm_offset_t *)pe_translate_addr(imgbase,
	    imp_desc.first_thunk);

	while (nptr != NULL && pe_translate_addr(imgbase, *nptr)) {
		fname = (char *)pe_translate_addr(imgbase,
		    (*nptr & ~IMAGE_ORDINAL_FLAG) + 2);
		func = pe_functbl_match(functbl, fname);
		if (func)
			*fptr = func;
#ifdef notdef
		if (*fptr == 0)
			return (ENOENT);
#endif
		nptr++;
		fptr++;
	}

	return (0);
}
