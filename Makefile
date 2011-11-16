all:
	cd src/usr.sbin/ndisload && make
	cd src/sys/modules/ndis && make
	cd src/sys/modules/if_ndis && make
install:
	cd src/sys/modules/ndis && make install
	cd src/sys/modules/if_ndis && make install
	cd src/usr.sbin/ndisload && make install
clean:
	cd src/sys/modules/ndis && make clean
	rm src/sys/modules/ndis/@
	rm src/sys/modules/ndis/machine
	rm src/sys/modules/ndis/x86
	cd src/sys/modules/if_ndis && make clean
	rm src/sys/modules/if_ndis/@
	rm src/sys/modules/if_ndis/machine
	rm src/sys/modules/if_ndis/x86
	cd src/usr.sbin/ndisload && make clean
load:
	cd src/sys/modules/ndis && make load
	cd src/sys/modules/if_ndis && make load
unload:
	cd src/sys/modules/ndis && make unload
	cd src/sys/modules/if_ndis && make unload
