/*-
 * Copyright (c) 2005
 *      Bill Paul <wpaul@windriver.com>.  All rights reserved.
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
 *      This product includes software developed by Bill Paul.
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/unistd.h>

#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/module.h>
#include <sys/conf.h>
#include <sys/ioccom.h>
#include <sys/mbuf.h>
#include <sys/bus.h>
#include <sys/proc.h>
#include <sys/sched.h>
#include <sys/smp.h>

#ifdef __amd64__
#include <machine/fpu.h>
#endif

#include <dev/usb/usb.h>

#include "pe_var.h"
#include "resource_var.h"
#include "ntoskrnl_var.h"
#include "ndis_var.h"
#include "hal_var.h"
#include "usbd_var.h"
#include "loader.h"

extern devclass_t ndis_devclass;
extern driver_t ndis_pccard_driver;
extern driver_t ndis_pci_driver;
extern driver_t ndis_usb_driver;

static d_ioctl_t windrv_ioctl;

static struct cdev *ndis_dev;

static struct cdevsw ndis_cdevsw = {
	.d_version = D_VERSION,
	.d_ioctl = windrv_ioctl,
	.d_name = "ndis",
};

static struct mtx drvdb_mtx;
static STAILQ_HEAD(drvdb, drvdb_ent) drvdb_head;

static struct driver_object fake_pci_driver; /* serves both PCI and cardbus */
static struct driver_object fake_pccard_driver;

MALLOC_DEFINE(M_NDIS_WINDRV, "ndis_windrv", "ndis_windrv buffers");

#define	DUMMY_REGISTRY_PATH "\\\\some\\bogus\\path"

void
windrv_libinit(void)
{
	STAILQ_INIT(&drvdb_head);
	mtx_init(&drvdb_mtx, "drvdb_mtx", NULL, MTX_DEF);

	ndis_dev = make_dev_credf(0, &ndis_cdevsw, 0, NULL,
	    UID_ROOT, GID_WHEEL, 0600, "ndis");
	/*
	 * PCI and pccard devices don't need to use IRPs to
	 * interact with their bus drivers (usually), so our
	 * emulated PCI and pccard drivers are just stubs.
	 * USB devices, on the other hand, do all their I/O
	 * by exchanging IRPs with the USB bus driver, so
	 * for that we need to provide emulator dispatcher
	 * routines, which are in a separate module.
	 */
	windrv_bus_attach(&fake_pci_driver, "PCI Bus");
	windrv_bus_attach(&fake_pccard_driver, "PCCARD Bus");
}

void
windrv_libfini(void)
{
	struct drvdb_ent *d;

	destroy_dev(ndis_dev);

	mtx_lock(&drvdb_mtx);
	while (STAILQ_FIRST(&drvdb_head) != NULL) {
		d = STAILQ_FIRST(&drvdb_head);
		STAILQ_REMOVE_HEAD(&drvdb_head, link);
		if (d->windrv_devlist) {
			free(d->windrv_object->driver_extension, M_NDIS_WINDRV);
			free(d->windrv_object->driver_start, M_NDIS_WINDRV);
			free(d->windrv_object, M_NDIS_WINDRV);
			free(d->windrv_devlist->name, M_NDIS_WINDRV);
			free(d->windrv_devlist, M_NDIS_WINDRV);
		}
		free(d, M_NDIS_WINDRV);
	}
	mtx_unlock(&drvdb_mtx);

	RtlFreeUnicodeString(&fake_pci_driver.driver_name);
	RtlFreeUnicodeString(&fake_pccard_driver.driver_name);

	mtx_destroy(&drvdb_mtx);
}

/*
 * Given the address of a driver image, find its corresponding driver_object.
 */
struct driver_object *
windrv_lookup(vm_offset_t img, const char *name)
{
	struct unicode_string us;
	struct ansi_string as;
	struct drvdb_ent *d;

	bzero((char *)&us, sizeof(us));

	if (name != NULL) {
		RtlInitAnsiString(&as, name);
		if (RtlAnsiStringToUnicodeString(&us, &as, TRUE))
			return (NULL);
	}

	mtx_lock(&drvdb_mtx);
	STAILQ_FOREACH(d, &drvdb_head, link) {
		if (d->windrv_object->driver_start == (void *)img ||
		    (bcmp((char *)d->windrv_object->driver_name.buf,
		    (char *)us.buf, us.len) == 0 && us.len)) {
			mtx_unlock(&drvdb_mtx);
			if (name != NULL)
				RtlFreeUnicodeString(&us);
			return (d->windrv_object);
		}
	}
	mtx_unlock(&drvdb_mtx);

	if (name != NULL)
		RtlFreeUnicodeString(&us);

	return (NULL);
}

struct drvdb_ent *
windrv_match(matchfuncptr matchfunc, void *ctx)
{
	struct drvdb_ent *d;

	mtx_lock(&drvdb_mtx);
	STAILQ_FOREACH(d, &drvdb_head, link) {
		if (d->windrv_devlist == NULL)
			continue;
		if (matchfunc(d->windrv_bustype, d->windrv_devlist, ctx)) {
			mtx_unlock(&drvdb_mtx);
			return (d);
		}
	}
	mtx_unlock(&drvdb_mtx);

	return (NULL);
}

/*
 * Remove a driver_object from our datatabase and destroy it. Throw
 * away any custom driver extension info that may have been added.
 */
static int
windrv_unload(vm_offset_t img)
{
	struct drvdb_ent *db, *r = NULL;
	struct driver_object *drv;
	struct device_object *pdo;
	device_t dev;
	struct list_entry *e;

	drv = windrv_lookup(img, NULL);

	/*
	 * When we unload a driver image, we need to force a
	 * detach of any devices that might be using it. We
	 * need the PDOs of all attached devices for this.
	 * Getting at them is a little hard. We basically
	 * have to walk the device lists of all our bus
	 * drivers.
	 */
	mtx_lock(&drvdb_mtx);
	STAILQ_FOREACH(db, &drvdb_head, link) {
		/*
		 * Fake bus drivers have no devlist info.
		 * If this driver has devlist info, it's
		 * a loaded Windows driver and has no PDOs,
		 * so skip it.
		 */
		if (db->windrv_devlist != NULL)
			continue;
		pdo = db->windrv_object->device_object;
		while (pdo != NULL) {
			if (pdo->attacheddev->drvobj != drv) {
				pdo = pdo->nextdev;
				continue;
			}
			dev = pdo->devext;
			pdo = pdo->nextdev;
			mtx_unlock(&drvdb_mtx);
			device_detach(dev);
			mtx_lock(&drvdb_mtx);
		}
	}

	STAILQ_FOREACH(db, &drvdb_head, link) {
		if (db->windrv_object->driver_start == (void *)img) {
			r = db;
			STAILQ_REMOVE(&drvdb_head, db, drvdb_ent, link);
			break;
		}
	}
	mtx_unlock(&drvdb_mtx);

	if (r == NULL || drv == NULL)
		return (ENOENT);

	/* Destroy any custom extensions that may have been added. */
	drv = r->windrv_object;
	while (!IsListEmpty(&drv->driver_extension->usrext)) {
		e = RemoveHeadList(&drv->driver_extension->usrext);
		ExFreePool(e);
	}

	free(drv->driver_extension, M_NDIS_WINDRV);
	RtlFreeUnicodeString(&drv->driver_name);
	free(drv->driver_start, M_NDIS_WINDRV);
	free(drv, M_NDIS_WINDRV);
	free(r->windrv_devlist->name, M_NDIS_WINDRV);
	free(r->windrv_devlist, M_NDIS_WINDRV);
	free(r, M_NDIS_WINDRV);		/* Free our DB handle */

	return (0);
}

#define	WINDRV_LOADED		htonl(0x42534F44)

#ifdef __amd64__
static void
patch_user_shared_data_address(vm_offset_t img, size_t len)
{
	unsigned long i, n, max_addr, *addr;

	n = len - sizeof(unsigned long);
	max_addr = KI_USER_SHARED_DATA + sizeof(struct kuser_shared_data);
	for (i = 0; i < n; i++) {
		addr = (unsigned long *)(img + i);
		if (*addr >= KI_USER_SHARED_DATA && *addr < max_addr) {
			*addr -= KI_USER_SHARED_DATA;
			*addr += (unsigned long)&kuser_data;
		}
	}
}
#endif

/*
 * Loader routine for actual Windows driver modules, ultimately
 * calls the driver's DriverEntry() routine.
 */
static int
windrv_load(vm_offset_t img, size_t len,
    uint32_t bustype, void *devlist, void *regvals)
{
	struct ansi_string as;
	struct image_optional_header *opt_hdr;
	driver_entry entry;
	struct drvdb_ent *new;
	struct driver_object *drv;
	uint32_t *ptr;
	int32_t ret;

	if (pe_validate_header(img))
		return (ENOEXEC);
	/*
	 * First step: try to relocate and dynalink the executable
	 * driver image.
	 */
	ptr = (uint32_t *)(img + 8);
	if (*ptr == WINDRV_LOADED)
		goto skipreloc;

	/* Perform text relocation */
	if (pe_relocate(img))
		return (ENOEXEC);

	/* Dynamically link the NDIS.SYS routines -- required. */
	if (pe_patch_imports(img, "NDIS", ndis_functbl))
		return (ENOEXEC);

	/* Dynamically link the HAL.dll routines -- optional. */
	pe_patch_imports(img, "HAL", hal_functbl);

	/* Dynamically link ntoskrnl.exe -- optional. */
	pe_patch_imports(img, "ntoskrnl", ntoskrnl_functbl);

	/* Dynamically link USBD.SYS -- optional */
	pe_patch_imports(img, "USBD", usbd_functbl);
#ifdef __amd64__
	patch_user_shared_data_address(img, len);
#endif
	*ptr = WINDRV_LOADED;
skipreloc:
	/* Next step: find the driver entry point. */
	pe_get_optional_header(img, &opt_hdr);
	entry = (driver_entry)pe_translate_addr(img,
	    opt_hdr->address_of_entry_point);

	/* Next step: allocate and store a driver object. */
	new = malloc(sizeof(struct drvdb_ent), M_NDIS_WINDRV, M_NOWAIT|M_ZERO);
	if (new == NULL)
		return (ENOMEM);

	drv = malloc(sizeof(struct driver_object), M_NDIS_WINDRV,
	    M_NOWAIT|M_ZERO);
	if (drv == NULL) {
		free (new, M_NDIS_WINDRV);
		return (ENOMEM);
	}

	/* Allocate a driver extension structure too. */
	drv->driver_extension = malloc(sizeof(struct driver_extension),
	    M_NDIS_WINDRV, M_NOWAIT|M_ZERO);
	if (drv->driver_extension == NULL) {
		free(new, M_NDIS_WINDRV);
		free(drv, M_NDIS_WINDRV);
		return (ENOMEM);
	}

	InitializeListHead((&drv->driver_extension->usrext));

	drv->driver_start = (void *)img;
	drv->driver_size = len;

	RtlInitAnsiString(&as, DUMMY_REGISTRY_PATH);
	if (RtlAnsiStringToUnicodeString(&drv->driver_name, &as, TRUE)) {
		free(drv->driver_extension, M_NDIS_WINDRV);
		free(drv, M_NDIS_WINDRV);
		free(new, M_NDIS_WINDRV);
		return (ENOMEM);
	}

	/* Now call the DriverEntry() function. */
	ret = MSCALL2(entry, drv, &drv->driver_name);
	if (ret) {
		RtlFreeUnicodeString(&drv->driver_name);
		free(drv->driver_extension, M_NDIS_WINDRV);
		free(drv, M_NDIS_WINDRV);
		free(new, M_NDIS_WINDRV);
		printf("NDIS: driver entry failed; status: 0x%08X\n", ret);
		return (ENODEV);
	}

	new->windrv_object = drv;
	new->windrv_regvals = regvals;
	new->windrv_devlist = devlist;
	new->windrv_bustype = bustype;

	mtx_lock(&drvdb_mtx);
	STAILQ_INSERT_HEAD(&drvdb_head, new, link);
	mtx_unlock(&drvdb_mtx);

	return (0);
}

/* ARGSUSED */
static int
windrv_ioctl(struct cdev *dev __unused, u_long cmd, caddr_t data,
    int flags __unused, struct thread *td __unused)
{
	int ret;
	ndis_load_driver_args_t *l;
	ndis_unload_driver_args_t *u;
	enum ndis_bus_type bustype;
	struct ndis_device_type *devlist;
	void *image;
	char *name;
	driver_t *driver = NULL;
	devclass_t bus_devclass;

	switch (cmd) {
	case NDIS_LOAD_DRIVER:
		l = (ndis_load_driver_args_t *)data;
		switch (l->bustype) {
		case 'p':
			bustype = NDIS_PCIBUS;
			driver = &ndis_pci_driver;
			bus_devclass = devclass_find("pci");
			break;
		case 'P':
			bustype = NDIS_PCMCIABUS;
			driver = &ndis_pccard_driver;
			bus_devclass = devclass_find("pccard");
			break;
		case 'u':
			bustype = NDIS_PNPBUS;
			driver = &ndis_usb_driver;
			bus_devclass = devclass_find("uhub");
			break;
		default:
			return (EINVAL);
			break;
		}
		if (l->img == NULL || l->len == 0 || l->namelen == 0 ||
		    l->vendor == 0 || l->device == 0 || l->name == NULL)
			return (EINVAL);

		image = malloc(l->len, M_NDIS_WINDRV, M_NOWAIT|M_ZERO);
		if (image == NULL)
			return (ENOMEM);

		ret = copyin(l->img, image, l->len);
		if (ret) {
			free(image, M_NDIS_WINDRV);
			return (ret);
		}

		name = malloc(l->namelen, M_NDIS_WINDRV, M_NOWAIT|M_ZERO);
		if (name == NULL) {
			free(image, M_NDIS_WINDRV);
			return (ENOMEM);
		}

		ret = copyin(l->name, name, l->namelen);
		if (ret) {
			free(name, M_NDIS_WINDRV);
			free(image, M_NDIS_WINDRV);
			return (ret);
		}

		devlist = malloc(sizeof(struct ndis_device_type), M_NDIS_WINDRV,
		    M_NOWAIT|M_ZERO);
		if (devlist == NULL) {
			free(name, M_NDIS_WINDRV);
			free(image, M_NDIS_WINDRV);
			return (ENOMEM);
		}
		devlist->vendor = l->vendor;
		devlist->device = l->device;
		devlist->name = name;
		ret = windrv_load((vm_offset_t)image, l->len,
		    bustype, devlist, NULL);
		if (ret) {
			free(name, M_NDIS_WINDRV);
			free(image, M_NDIS_WINDRV);
			free(devlist, M_NDIS_WINDRV);
			return (ret);
		}
		mtx_lock(&Giant);
		ret = devclass_add_driver(bus_devclass, driver, __INT_MAX, &ndis_devclass);
		mtx_unlock(&Giant);
		break;
	case NDIS_UNLOAD_DRIVER:
		u = (ndis_unload_driver_args_t *)data;
		ret = windrv_unload((vm_offset_t)u->img);
		break;
	default:
		ret = EINVAL;
		break;
	}
	return (ret);
}

/*
 * Make a new Physical Device Object for a device that was detected/plugged in.
 * For us, the PDO is just a way to get at the device_t.
 */
int32_t
windrv_create_pdo(struct driver_object *drv, device_t bsddev)
{
	struct device_object *dev;
	int32_t ret;

	/*
	 * This is a new physical device object, which technically
	 * is the "top of the stack." Consequently, we don't do
	 * an IoAttachDeviceToDeviceStack() here.
	 */
	mtx_lock(&drvdb_mtx);
	ret = IoCreateDevice(drv, 0, NULL, FILE_DEVICE_UNKNOWN, 0, FALSE, &dev);
	mtx_unlock(&drvdb_mtx);

	if (ret)
		return (ret);
	dev->devext = bsddev;	/* Stash pointer to our BSD device handle. */
	return (NDIS_STATUS_SUCCESS);
}

void
windrv_destroy_pdo(struct driver_object *drv, device_t bsddev)
{
	struct device_object *pdo;

	pdo = windrv_find_pdo(drv, bsddev);
	if (pdo == NULL)
		return;
	pdo->devext = NULL;

	mtx_lock(&drvdb_mtx);
	IoDeleteDevice(pdo);
	mtx_unlock(&drvdb_mtx);
}

/*
 * Given a device_t, find the corresponding PDO in a driver's device list.
 */
struct device_object *
windrv_find_pdo(const struct driver_object *drv, device_t bsddev)
{
	struct device_object *pdo;

	mtx_lock(&drvdb_mtx);
	for (pdo = drv->device_object; pdo != NULL; pdo = pdo->nextdev) {
		if (pdo->devext == bsddev) {
			mtx_unlock(&drvdb_mtx);
			return (pdo);
		}
	}
	mtx_unlock(&drvdb_mtx);

	return (NULL);
}

/*
 * Add an internally emulated driver to the database. We need this
 * to set up an emulated bus driver so that it can receive IRPs.
 */
int
windrv_bus_attach(struct driver_object *drv, const char *name)
{
	struct ansi_string as;
	struct drvdb_ent *new;

	new = malloc(sizeof(struct drvdb_ent), M_NDIS_WINDRV, M_NOWAIT|M_ZERO);
	if (new == NULL)
		return (ENOMEM);

	RtlInitAnsiString(&as, name);
	if (RtlAnsiStringToUnicodeString(&drv->driver_name, &as, TRUE)) {
		free(new, M_NDIS_WINDRV);
		return (ENOMEM);
	}

	/*
	 * Set up a fake image pointer to avoid false matches
	 * in windrv_lookup().
	 */
	drv->driver_start = (void *)0xFFFFFFFF;

	new->windrv_object = drv;
	new->windrv_devlist = NULL;
	new->windrv_regvals = NULL;

	mtx_lock(&drvdb_mtx);
	STAILQ_INSERT_HEAD(&drvdb_head, new, link);
	mtx_unlock(&drvdb_mtx);

	return (0);
}

#ifdef __amd64__
extern void x86_64_wrap(void);
extern void x86_64_wrap_call(void);
extern void x86_64_wrap_end(void);

void
windrv_wrap(funcptr func, funcptr *wrap, uint8_t argcnt,
    enum windrv_wrap_type type)
{
	vm_offset_t *calladdr, wrapstart, wrapend, wrapcall;
	funcptr p;

	wrapstart = (vm_offset_t)&x86_64_wrap;
	wrapend = (vm_offset_t)&x86_64_wrap_end;
	wrapcall = (vm_offset_t)&x86_64_wrap_call;

	/* Allocate a new wrapper instance. */
	p = malloc((wrapend - wrapstart), M_NDIS_WINDRV, M_NOWAIT|M_ZERO);
	if (p == NULL)
		panic("failed to allocate new wrapper instance");

	/* Copy over the code. */
	bcopy((char *)wrapstart, p, (wrapend - wrapstart));

	/* Insert the function address into the new wrapper instance. */
	calladdr = (vm_offset_t *)((char *)p + (wrapcall - wrapstart) + 2);
	*calladdr = (vm_offset_t)func;

	*wrap = p;
}

uint64_t
_x86_64_call1(void *fn, uint64_t a)
{
	struct fpu_kern_ctx fpu_ctx_save;
	uint64_t ret;

	fpu_kern_enter(curthread, &fpu_ctx_save, FPU_KERN_NORMAL);
	ret = x86_64_call1(fn, a);
	fpu_kern_leave(curthread, &fpu_ctx_save);

	return (ret);
}

uint64_t
_x86_64_call2(void *fn, uint64_t a, uint64_t b)
{
	struct fpu_kern_ctx fpu_ctx_save;
	uint64_t ret;

	fpu_kern_enter(curthread, &fpu_ctx_save, FPU_KERN_NORMAL);
	ret = x86_64_call2(fn, a, b);
	fpu_kern_leave(curthread, &fpu_ctx_save);

	return (ret);
}

uint64_t
_x86_64_call3(void *fn, uint64_t a, uint64_t b, uint64_t c)
{
	struct fpu_kern_ctx fpu_ctx_save;
	uint64_t ret;

	fpu_kern_enter(curthread, &fpu_ctx_save, FPU_KERN_NORMAL);
	ret = x86_64_call3(fn, a, b, c);
	fpu_kern_leave(curthread, &fpu_ctx_save);

	return (ret);
}

uint64_t
_x86_64_call4(void *fn, uint64_t a, uint64_t b, uint64_t c, uint64_t d)
{
	struct fpu_kern_ctx fpu_ctx_save;
	uint64_t ret;

	fpu_kern_enter(curthread, &fpu_ctx_save, FPU_KERN_NORMAL);
	ret = x86_64_call4(fn, a, b, c, d);
	fpu_kern_leave(curthread, &fpu_ctx_save);

	return (ret);
}

uint64_t
_x86_64_call5(void *fn, uint64_t a, uint64_t b, uint64_t c, uint64_t d,
    uint64_t e)
{
	struct fpu_kern_ctx fpu_ctx_save;
	uint64_t ret;

	fpu_kern_enter(curthread, &fpu_ctx_save, FPU_KERN_NORMAL);
	ret = x86_64_call5(fn, a, b, c, d, e);
	fpu_kern_leave(curthread, &fpu_ctx_save);

	return (ret);
}

uint64_t
_x86_64_call6(void *fn, uint64_t a, uint64_t b, uint64_t c, uint64_t d,
    uint64_t e, uint64_t f)
{
	struct fpu_kern_ctx fpu_ctx_save;
	uint64_t ret;

	fpu_kern_enter(curthread, &fpu_ctx_save, FPU_KERN_NORMAL);
	ret = x86_64_call6(fn, a, b, c, d, e, f);
	fpu_kern_leave(curthread, &fpu_ctx_save);

	return (ret);
}
#endif /* __amd64__ */
#ifdef __i386__
static void windrv_wrap_fastcall(funcptr, funcptr *, uint8_t);
static void windrv_wrap_stdcall(funcptr, funcptr *, uint8_t);
static void windrv_wrap_regparm(funcptr, funcptr *);

extern void x86_fastcall_wrap(void);
extern void x86_fastcall_wrap_arg(void);
extern void x86_fastcall_wrap_call(void);
extern void x86_fastcall_wrap_end(void);

static void
windrv_wrap_fastcall(funcptr func, funcptr *wrap, uint8_t argcnt)
{
	vm_offset_t *calladdr, wrapstart, wrapend, wrapcall, wraparg;
	funcptr p;
	uint8_t *argaddr;

	wrapstart = (vm_offset_t)&x86_fastcall_wrap;
	wrapend = (vm_offset_t)&x86_fastcall_wrap_end;
	wrapcall = (vm_offset_t)&x86_fastcall_wrap_call;
	wraparg = (vm_offset_t)&x86_fastcall_wrap_arg;

	/* Allocate a new wrapper instance. */
	p = malloc((wrapend - wrapstart), M_NDIS_WINDRV, M_NOWAIT|M_ZERO);
	if (p == NULL)
		panic("failed to allocate new wrapper instance");

	/* Copy over the code. */
	bcopy((char *)wrapstart, p, (wrapend - wrapstart));

	/* Insert the function address into the new wrapper instance. */
	calladdr = (vm_offset_t *)((char *)p + ((wrapcall - wrapstart) + 1));
	*calladdr = (vm_offset_t)func;

	if (argcnt < 3)
		argcnt = 0;
	else
		argcnt -= 2;

	argaddr = (uint8_t *)((char *)p + ((wraparg - wrapstart) + 1));
	*argaddr = argcnt * sizeof(uint32_t);

	*wrap = p;
}

extern void x86_stdcall_wrap(void);
extern void x86_stdcall_wrap_call(void);
extern void x86_stdcall_wrap_arg(void);
extern void x86_stdcall_wrap_end(void);

static void
windrv_wrap_stdcall(funcptr func, funcptr *wrap, uint8_t argcnt)
{
	vm_offset_t *calladdr, wrapstart, wrapend, wrapcall, wraparg;
	funcptr p;
	uint8_t *argaddr;

	wrapstart = (vm_offset_t)&x86_stdcall_wrap;
	wrapend = (vm_offset_t)&x86_stdcall_wrap_end;
	wrapcall = (vm_offset_t)&x86_stdcall_wrap_call;
	wraparg = (vm_offset_t)&x86_stdcall_wrap_arg;

	/* Allocate a new wrapper instance. */
	p = malloc((wrapend - wrapstart), M_NDIS_WINDRV, M_NOWAIT|M_ZERO);
	if (p == NULL)
		panic("failed to allocate new wrapper instance");

	/* Copy over the code. */
	bcopy((char *)wrapstart, p, (wrapend - wrapstart));

	/* Insert the function address into the new wrapper instance. */
	calladdr = (vm_offset_t *)((char *)p + ((wrapcall - wrapstart) + 1));
	*calladdr = (vm_offset_t)func;

	argaddr = (uint8_t *)((char *)p + ((wraparg - wrapstart) + 1));
	*argaddr = argcnt * sizeof(uint32_t);

	*wrap = p;
}

extern void x86_regparm_wrap(void);
extern void x86_regparm_wrap_call(void);
extern void x86_regparm_wrap_end(void);

static void
windrv_wrap_regparm(funcptr func, funcptr *wrap)
{
	funcptr p;
	vm_offset_t *calladdr, wrapstart, wrapend, wrapcall;

	wrapstart = (vm_offset_t)&x86_regparm_wrap;
	wrapend = (vm_offset_t)&x86_regparm_wrap_end;
	wrapcall = (vm_offset_t)&x86_regparm_wrap_call;

	/* Allocate a new wrapper instance. */
	p = malloc((wrapend - wrapstart), M_NDIS_WINDRV, M_NOWAIT|M_ZERO);
	if (p == NULL)
		panic("failed to allocate new wrapper instance");

	/* Copy over the code. */
	bcopy((char *)wrapstart, p, (wrapend - wrapstart));

	/* Insert the function address into the new wrapper instance. */
	calladdr = (vm_offset_t *)((char *)p + ((wrapcall - wrapstart) + 1));
	*calladdr = (vm_offset_t)func;

	*wrap = p;
}

void
windrv_wrap(funcptr func, funcptr *wrap, uint8_t argcnt,
    enum windrv_wrap_type type)
{
	switch (type) {
	case FASTCALL:
		windrv_wrap_fastcall(func, wrap, argcnt);
		break;
	case STDCALL:
		windrv_wrap_stdcall(func, wrap, argcnt);
		break;
	case REGPARM:
		windrv_wrap_regparm(func, wrap);
		break;
	case CDECL:
		windrv_wrap_stdcall(func, wrap, 0);
		break;
	default:
		break;
	}
}
#endif /* __i386__ */

void
windrv_unwrap(funcptr func)
{
	free(func, M_NDIS_WINDRV);
}

void
windrv_wrap_table(struct image_patch_table *table)
{
	struct image_patch_table *p;

	for (p = table; p->func != NULL; p++)
		windrv_wrap(p->func, &p->wrap, p->argcnt, p->ftype);
}

void
windrv_unwrap_table(struct image_patch_table *table)
{
	struct image_patch_table *p;

	for (p = table; p->func != NULL; p++)
		windrv_unwrap(p->wrap);
}
