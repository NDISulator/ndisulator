all:
	cd src/sys/modules/ndis && make
	cd src/sys/modules/if_ndis && make
	cd src/usr.sbin/ndiscvt && make
install:
	cd src/sys/modules/ndis && make install
	cd src/sys/modules/if_ndis && make install
	cd src/usr.sbin/ndiscvt && make install
clean:
	cd src/sys/modules/ndis && make clean
	cd src/sys/modules/if_ndis && make clean
	cd src/usr.sbin/ndiscvt && make clean
load:
	cd src/sys/modules/ndis && make load
	cd src/sys/modules/if_ndis && make load
unload:
	cd src/sys/modules/ndis && make unload
	cd src/sys/modules/if_ndis && make unload
