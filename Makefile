all:
	@echo "targets: attach detach build install clean load unload"
attach:
	@echo "mounting NDISulator code on top of FreeBSD code"
	mount_nullfs src/sys/compat/ndis /usr/src/sys/compat/ndis
	mount_nullfs src/sys/dev/if_ndis /usr/src/sys/dev/if_ndis
	mount_nullfs src/sys/modules/ndis /usr/src/sys/modules/ndis
	mount_nullfs src/sys/modules/if_ndis /usr/src/sys/modules/if_ndis
	mount_nullfs src/usr.sbin/ndiscvt /usr/src/usr.sbin/ndiscvt
detach:
	@echo "umounting NDISulator code"
	umount /usr/src/sys/compat/ndis
	umount /usr/src/sys/dev/if_ndis
	umount /usr/src/sys/modules/ndis
	umount /usr/src/sys/modules/if_ndis
	umount /usr/src/usr.sbin/ndiscvt
build:
	cd /usr/src/sys/modules/ndis && make
	cd /usr/src/sys/modules/if_ndis && make
	cd /usr/src/usr.sbin/ndiscvt && make
install:
	cd /usr/src/sys/modules/ndis && make install
	cd /usr/src/sys/modules/if_ndis && make install
	cd /usr/src/usr.sbin/ndiscvt && make install
clean:
	cd /usr/src/sys/modules/ndis && make clean
	cd /usr/src/sys/modules/if_ndis && make clean
	cd /usr/src/usr.sbin/ndiscvt && make clean
load:
	kldload /usr/src/sys/modules/ndis/ndis.ko
	kldload /usr/src/sys/modules/if_ndis/if_ndis.ko
unload:
	kldunload if_ndis.ko
	kldunload ndis.ko
