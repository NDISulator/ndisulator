## NDISulator
NDISulator is a FreeBSD kernel module + userland tool which make it possible to use MS Windows network card drivers in FreeBSD.
This software has some fixes and improvements comparing to ndis module available in FreeBSD base system.

This software supports NDIS version 5.1 what means it can be used with Windows XP and Windows Server 2000/2003 drivers.

### Requirements
* make sure you use **FreeBSD 10-STABLE** kernel and world (this ndisulator branch last tested at **13 Dec 2014** with **FreeBSD 10.1-STABLE r275746**)
* make sure FreeBSD source tree is available in /usr/src
* make sure you use the same "arch" of MS Windows drivers as your FreeBSD installation (i.e. 64 bit driver for amd64 case; 32 bit driver for i386 case)

### How to use:
* To build NDISulator you have to run:
```
	make
```

* To install NDISulator (**ndis** kernel module + **ndisload** binary) you have to run as root:
```
	make install
```

* To load ndis kernel module you have to run following command as root:
```
	kldload ndis
```

* To load windows miniport driver (.sys file) you have to use **ndisload** binary (there is no need to generate kernel module based on .inf + .sys files like it is necessary for ndis from FreeBSD base system)
```
	ndisload [-p|-u|-P -s <PATH> -n <NAME> -v <VENDOR_ID> -d <DEVICE_ID>]
	ndisload flags:
		-p = PCI device
		-u = USB device
		-P = PCMCIA device
		-s PATH = path to windows miniport driver (.sys file)
		-n NAME = device name (any name you like)
		-v VENDOR_ID = last 4 hex digits of "chip" value in "pciconf" output
		-d DEVICE_ID = first 4 hex digits of "chip" value in "pciconf" output
```
Don't forget to add "0x" prefix if you just copying vendor/device id values from pciconf output

**Example of ndisload use:**
```
	none@pci0:0:3:0: class=0x020000 card=0x11001af4 chip=0x813910ec rev=0x20 hdr=0x00
		vendor = 'Realtek Semiconductor Co., Ltd.'
		device = 'RTL-8139/8139C/8139C+'
		class = network
		subclass = ethernet
```
Correct ndisload command for device above:
```
	ndisload -p -s /root/rl8139/Rtnic64.sys -n test_dev -v 0x10ec -d 0x8139
```

* If all steps completed successfully at this point you should see new interface named **ndis0**


### How to revert to stock ndis:
```
	rm -f /usr/sbin/ndisload /usr/share/man/man8/ndisload.8.gz
	cd /usr/src/sys/modules/ndis && make && make install && make cleandir
	cd /usr/src/sys/modules/if_ndis && make && make install && make cleandir
	cd /usr/src/usr.sbin/ndiscvt && make && make install && make cleandir
```
