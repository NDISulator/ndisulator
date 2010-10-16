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
 *
 * $FreeBSD$
 */

#ifndef _RESOURCE_VAR_H_
#define	_RESOURCE_VAR_H_

struct physaddr {
	uint64_t	quad;
#ifdef notdef
	uint32_t	low;
	uint32_t	high;
#endif
};

enum ndis_interface_type {
	InterfaceTypeUndefined = -1,
	Internal,
	Isa,
	Eisa,
	MicroChannel,
	TurboChannel,
	PCIBus,
	VMEBus,
	NuBus,
	PCMCIABus,
	CBus,
	MPIBus,
	MPSABus,
	ProcessorInternal,
	InternalPowerBus,
	PNPISABus,
	PNPBus,
	MaximumInterfaceType
};

#define	CmResourceTypeNull		0
#define	CmResourceTypePort		1
#define	CmResourceTypeInterrupt		2
#define	CmResourceTypeMemory		3
#define	CmResourceTypeDma		4
#define	CmResourceTypeDeviceSpecific	5
#define	CmResourceTypeBusNumber		6
#define	CmResourceTypeMaximum		7
#define	CmResourceTypeNonArbitrated	128
#define	CmResourceTypeConfigData	128
#define	CmResourceTypeDevicePrivate	129
#define	CmResourceTypePcCardConfig	130

enum cm_share_disposition {
    CM_RESOURCE_SHARE_UNDETERMINED = 0,
    CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
    CM_RESOURCE_SHARE_DRIVER_EXCLUSIVE,
    CM_RESOURCE_SHARE_SHARED
};

/* Define the bit masks for Flags when type is CmResourceTypeInterrupt */
#define	CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE	0
#define	CM_RESOURCE_INTERRUPT_LATCHED		1

/* Define the bit masks for Flags when type is CmResourceTypeMemory */
#define	CM_RESOURCE_MEMORY_READ_WRITE		0x0000
#define	CM_RESOURCE_MEMORY_READ_ONLY		0x0001
#define	CM_RESOURCE_MEMORY_WRITE_ONLY		0x0002
#define	CM_RESOURCE_MEMORY_PREFETCHABLE		0x0004
#define	CM_RESOURCE_MEMORY_COMBINEDWRITE	0x0008
#define	CM_RESOURCE_MEMORY_24			0x0010
#define	CM_RESOURCE_MEMORY_CACHEABLE		0x0020

/* Define the bit masks for Flags when type is CmResourceTypePort */
#define	CM_RESOURCE_PORT_MEMORY			0x0000
#define	CM_RESOURCE_PORT_IO			0x0001
#define	CM_RESOURCE_PORT_10_BIT_DECODE		0x0004
#define	CM_RESOURCE_PORT_12_BIT_DECODE		0x0008
#define	CM_RESOURCE_PORT_16_BIT_DECODE		0x0010
#define	CM_RESOURCE_PORT_POSITIVE_DECODE	0x0020
#define	CM_RESOURCE_PORT_PASSIVE_DECODE		0x0040
#define	CM_RESOURCE_PORT_WINDOW_DECODE		0x0080

/* Define the bit masks for Flags when type is CmResourceTypeDma */
#define	CM_RESOURCE_DMA_8			0x0000
#define	CM_RESOURCE_DMA_16			0x0001
#define	CM_RESOURCE_DMA_32			0x0002
#define	CM_RESOURCE_DMA_8_AND_16		0x0004
#define	CM_RESOURCE_DMA_BUS_MASTER		0x0008
#define	CM_RESOURCE_DMA_TYPE_A			0x0010
#define	CM_RESOURCE_DMA_TYPE_B			0x0020
#define	CM_RESOURCE_DMA_TYPE_F			0x0040

struct cm_partial_resource_desc {
	uint8_t		type;
	uint8_t		sharedisp;
	uint16_t	flags;
	union {
		struct {
			struct physaddr	start;
			uint32_t	len;
		} generic;
		struct {
			struct physaddr	start;
			uint32_t	len;
		} port;
		struct {
			uint32_t	level;
			uint32_t	vector;
			uint32_t	affinity;
		} intr;
		struct {
			struct physaddr	start;
			uint32_t	len;
		} mem;
		struct {
			uint32_t	chan;
			uint32_t	port;
			uint32_t	rsvd;
		} dmachan;
		struct {
			uint32_t	data[3];
		} devpriv;
		struct {
			uint32_t	datasize;
			uint32_t	rsvd1;
			uint32_t	rsvd2;
		} devspec;
	} u __attribute__((packed));
};

struct cm_partial_resource_list {
	uint16_t				version;
	uint16_t				revision;
	uint32_t				count;
	struct cm_partial_resource_desc		partial_descs[1];
};

struct cm_full_resource_list {
	enum ndis_interface_type		type;
	uint32_t				busnum;
	struct cm_partial_resource_desc		partiallist;
};

struct cm_resource_list {
	uint32_t			count;
	struct cm_full_resource_list	rlist;
};

#endif /* _RESOURCE_VAR_H_ */
