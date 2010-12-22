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

#ifndef _NDIS_VAR_H_
#define	_NDIS_VAR_H_

#define NDIS_DEBUG
#ifdef NDIS_DEBUG

enum {
	NDBG_GET	= 0x00000001,
	NDBG_SET	= 0x00000002,
	NDBG_INIT	= 0x00000004,
	NDBG_CFG	= 0x00000008,
	NDBG_PCI	= 0x00000010,
	NDBG_PCMCIA	= 0x00000020,
	NDBG_DMA	= 0x00000040,
	NDBG_MM		= 0x00000080,
	NDBG_INTR	= 0x00000100,
	NDBG_TIMER	= 0x00000200,
	NDBG_EVENT	= 0x00000400,
	NDBG_THREAD	= 0x00000800,
	NDBG_MEM	= 0x00001000,
	NDBG_HAL	= 0x00002000,
	NDBG_RTL	= 0x00004000,
	NDBG_PACKET	= 0x00008000,
	NDBG_ZW		= 0x00010000,
	NDBG_WORK	= 0x00020000,
	NDBG_ANY	= 0xffffffff
};
extern int ndis_debug;
#define	TRACE(m, fmt, ...) do {						\
	if (ndis_debug & (m))						\
		printf("%s:" fmt, __func__, __VA_ARGS__);		\
} while (0)
#else
#define	TRACE(m, fmt, ...)
#endif

/* Forward declarations */
struct ndis_miniport_block;
struct ndis_mdriver_block;
struct ndis_softc;

/*
 * NDIS status codes (there are lots of them). The ones that
 * don't seem to fit the pattern are actually mapped to generic
 * NT status codes.
 */
#define	NDIS_STATUS_SUCCESS				0x00000000
#define	NDIS_STATUS_WAIT_0				0x00000000
#define	NDIS_STATUS_ALERTED				0x00000101
#define	NDIS_STATUS_TIMEOUT				0x00000102
#define	NDIS_STATUS_PENDING				0x00000103
#define	NDIS_STATUS_NOT_RECOGNIZED			0x00010001
#define	NDIS_STATUS_NOT_COPIED				0x00010002
#define	NDIS_STATUS_NOT_ACCEPTED			0x00010003
#define	NDIS_STATUS_CALL_ACTIVE				0x00010007
#define	NDIS_STATUS_ONLINE				0x40010003
#define	NDIS_STATUS_RESET_START				0x40010004
#define	NDIS_STATUS_RESET_END				0x40010005
#define	NDIS_STATUS_RING_STATUS				0x40010006
#define	NDIS_STATUS_CLOSED				0x40010007
#define	NDIS_STATUS_WAN_LINE_UP				0x40010008
#define	NDIS_STATUS_WAN_LINE_DOWN			0x40010009
#define	NDIS_STATUS_WAN_FRAGMENT			0x4001000A
#define	NDIS_STATUS_MEDIA_CONNECT			0x4001000B
#define	NDIS_STATUS_MEDIA_DISCONNECT			0x4001000C
#define	NDIS_STATUS_HARDWARE_LINE_UP			0x4001000D
#define	NDIS_STATUS_HARDWARE_LINE_DOWN			0x4001000E
#define	NDIS_STATUS_INTERFACE_UP			0x4001000F
#define	NDIS_STATUS_INTERFACE_DOWN			0x40010010
#define	NDIS_STATUS_MEDIA_BUSY				0x40010011
#define	NDIS_STATUS_MEDIA_SPECIFIC_INDICATION		0x40010012
#define	NDIS_STATUS_WW_INDICATION 			0x40010012
#define	NDIS_STATUS_LINK_SPEED_CHANGE			0x40010013
#define	NDIS_STATUS_WAN_GET_STATS			0x40010014
#define	NDIS_STATUS_WAN_CO_FRAGMENT			0x40010015
#define	NDIS_STATUS_WAN_CO_LINKPARAMS			0x40010016
#define	NDIS_STATUS_BUFFER_OVERFLOW			0x80000005
#define	NDIS_STATUS_NOT_RESETTABLE			0x80010001
#define	NDIS_STATUS_SOFT_ERRORS				0x80010003
#define	NDIS_STATUS_HARD_ERRORS				0x80010004
#define	NDIS_STATUS_FAILURE				0xC0000001
#define	NDIS_STATUS_NOT_IMPLEMENTED			0xC0000002
#define	NDIS_STATUS_ACCESS_VIOLATION			0xC0000005
#define	NDIS_STATUS_INVALID_PARAMETER			0xC000000D
#define	NDIS_STATUS_INVALID_DEVICE_REQUEST		0xC0000010
#define	NDIS_STATUS_MORE_PROCESSING_REQUIRED		0xC0000016
#define	NDIS_STATUS_NO_MEMORY				0xC0000017
#define	NDIS_STATUS_BUFFER_TOO_SMALL			0xC0000023
#define	NDIS_STATUS_MUTANT_NOT_OWNED			0xC0000046
#define	NDIS_STATUS_RESOURCES				0xC000009A
#define	NDIS_STATUS_DFS_EXIT_PATH_FOUND			0xC000009B
#define	NDIS_STATUS_DEVICE_DATA_ERROR			0xC000009C
#define	NDIS_STATUS_DEVICE_NOT_CONNECTED		0xC000009D
#define	NDIS_STATUS_NOT_SUPPORTED			0xC00000BB
#define	NDIS_STATUS_INVALID_PARAMETER_2			0xC00000F0
#define	NDIS_STATUS_CANCELLED				0xC0000120
#define	NDIS_STATUS_NOT_FOUND				0xC0000225
#define	NDIS_STATUS_NETWORK_UNREACHABLE			0xC000023C
#define	NDIS_STATUS_DEVICE_REMOVED			0xC00002B6
#define	NDIS_STATUS_CLOSING				0xC0010002
#define	NDIS_STATUS_BAD_VERSION				0xC0010004
#define	NDIS_STATUS_BAD_CHARACTERISTICS			0xC0010005
#define	NDIS_STATUS_ADAPTER_NOT_FOUND			0xC0010006
#define	NDIS_STATUS_OPEN_FAILED				0xC0010007
#define	NDIS_STATUS_DEVICE_FAILED			0xC0010008
#define	NDIS_STATUS_MULTICAST_FULL			0xC0010009
#define	NDIS_STATUS_MULTICAST_EXISTS			0xC001000A
#define	NDIS_STATUS_MULTICAST_NOT_FOUND			0xC001000B
#define	NDIS_STATUS_REQUEST_ABORTED			0xC001000C
#define	NDIS_STATUS_RESET_IN_PROGRESS			0xC001000D
#define	NDIS_STATUS_CLOSING_INDICATING			0xC001000E
#define	NDIS_STATUS_INVALID_PACKET			0xC001000F
#define	NDIS_STATUS_OPEN_LIST_FULL			0xC0010010
#define	NDIS_STATUS_ADAPTER_NOT_READY			0xC0010011
#define	NDIS_STATUS_ADAPTER_NOT_OPEN			0xC0010012
#define	NDIS_STATUS_NOT_INDICATING			0xC0010013
#define	NDIS_STATUS_INVALID_LENGTH			0xC0010014
#define	NDIS_STATUS_INVALID_DATA			0xC0010015
#define	NDIS_STATUS_BUFFER_TOO_SHORT			0xC0010016
#define	NDIS_STATUS_INVALID_OID				0xC0010017
#define	NDIS_STATUS_ADAPTER_REMOVED			0xC0010018
#define	NDIS_STATUS_UNSUPPORTED_MEDIA			0xC0010019
#define	NDIS_STATUS_GROUP_ADDRESS_IN_USE		0xC001001A
#define	NDIS_STATUS_FILE_NOT_FOUND			0xC001001B
#define	NDIS_STATUS_ERROR_READING_FILE			0xC001001C
#define	NDIS_STATUS_ALREADY_MAPPED			0xC001001D
#define	NDIS_STATUS_RESOURCE_CONFLICT			0xC001001E
#define	NDIS_STATUS_NO_CABLE				0xC001001F
#define	NDIS_STATUS_INVALID_SAP				0xC0010020
#define	NDIS_STATUS_SAP_IN_USE				0xC0010021
#define	NDIS_STATUS_INVALID_ADDRESS			0xC0010022
#define	NDIS_STATUS_VC_NOT_ACTIVATED			0xC0010023
#define	NDIS_STATUS_DEST_OUT_OF_ORDER			0xC0010024
#define	NDIS_STATUS_VC_NOT_AVAILABLE			0xC0010025
#define	NDIS_STATUS_CELLRATE_NOT_AVAILABLE		0xC0010026
#define	NDIS_STATUS_INCOMPATABLE_QOS			0xC0010027
#define	NDIS_STATUS_AAL_PARAMS_UNSUPPORTED		0xC0010028
#define	NDIS_STATUS_NO_ROUTE_TO_DESTINATION		0xC0010029
#define	NDIS_STATUS_TOKEN_RING_OPEN_ERROR		0xC0011000

/*
 * NDIS event codes. They are usually reported to NdisWriteErrorLogEntry().
 */
#define	EVENT_NDIS_RESOURCE_CONFLICT			0xC0001388
#define	EVENT_NDIS_OUT_OF_RESOURCE			0xC0001389
#define	EVENT_NDIS_HARDWARE_FAILURE			0xC000138A
#define	EVENT_NDIS_ADAPTER_NOT_FOUND			0xC000138B
#define	EVENT_NDIS_INTERRUPT_CONNECT			0xC000138C
#define	EVENT_NDIS_DRIVER_FAILURE			0xC000138D
#define	EVENT_NDIS_BAD_VERSION				0xC000138E
#define	EVENT_NDIS_TIMEOUT				0x8000138F
#define	EVENT_NDIS_NETWORK_ADDRESS			0xC0001390
#define	EVENT_NDIS_UNSUPPORTED_CONFIGURATION		0xC0001391
#define	EVENT_NDIS_INVALID_VALUE_FROM_ADAPTER		0xC0001392
#define	EVENT_NDIS_MISSING_CONFIGURATION_PARAMETER	0xC0001393
#define	EVENT_NDIS_BAD_IO_BASE_ADDRESS			0xC0001394
#define	EVENT_NDIS_RECEIVE_SPACE_SMALL			0x40001395
#define	EVENT_NDIS_ADAPTER_DISABLED			0x80001396
#define	EVENT_NDIS_IO_PORT_CONFLICT			0x80001397
#define	EVENT_NDIS_PORT_OR_DMA_CONFLICT			0x80001398
#define	EVENT_NDIS_MEMORY_CONFLICT			0x80001399
#define	EVENT_NDIS_INTERRUPT_CONFLICT			0x8000139A
#define	EVENT_NDIS_DMA_CONFLICT				0x8000139B
#define	EVENT_NDIS_INVALID_DOWNLOAD_FILE_ERROR		0xC000139C
#define	EVENT_NDIS_MAXRECEIVES_ERROR			0x8000139D
#define	EVENT_NDIS_MAXTRANSMITS_ERROR			0x8000139E
#define	EVENT_NDIS_MAXFRAMESIZE_ERROR			0x8000139F
#define	EVENT_NDIS_MAXINTERNALBUFS_ERROR		0x800013A0
#define	EVENT_NDIS_MAXMULTICAST_ERROR			0x800013A1
#define	EVENT_NDIS_PRODUCTID_ERROR			0x800013A2
#define	EVENT_NDIS_LOBE_FAILUE_ERROR			0x800013A3
#define	EVENT_NDIS_SIGNAL_LOSS_ERROR			0x800013A4
#define	EVENT_NDIS_REMOVE_RECEIVED_ERROR		0x800013A5
#define	EVENT_NDIS_TOKEN_RING_CORRECTION		0x400013A6
#define	EVENT_NDIS_ADAPTER_CHECK_ERROR			0xC00013A7
#define	EVENT_NDIS_RESET_FAILURE_ERROR			0x800013A8
#define	EVENT_NDIS_CABLE_DISCONNECTED_ERROR		0x800013A9
#define	EVENT_NDIS_RESET_FAILURE_CORRECTION		0x800013AA

/*
 * NDIS OIDs used by the query_info/set_info routines.
 * Some are required by all NDIS drivers, some are specific to
 * a particular type of device, and some are purely optional.
 * Unfortunately, one of the purely optional OIDs is the one
 * that lets us set the MAC address of the device.
 */

/* General OIDs */
#define	OID_GEN_SUPPORTED_LIST				0x00010101
#define	OID_GEN_HARDWARE_STATUS				0x00010102
#define	OID_GEN_MEDIA_SUPPORTED				0x00010103
#define	OID_GEN_MEDIA_IN_USE				0x00010104
#define	OID_GEN_MAXIMUM_LOOKAHEAD			0x00010105
#define	OID_GEN_MAXIMUM_FRAME_SIZE			0x00010106
#define	OID_GEN_LINK_SPEED				0x00010107
#define	OID_GEN_TRANSMIT_BUFFER_SPACE			0x00010108
#define	OID_GEN_RECEIVE_BUFFER_SPACE			0x00010109
#define	OID_GEN_TRANSMIT_BLOCK_SIZE			0x0001010A
#define	OID_GEN_RECEIVE_BLOCK_SIZE			0x0001010B
#define	OID_GEN_VENDOR_ID				0x0001010C
#define	OID_GEN_VENDOR_DESCRIPTION			0x0001010D
#define	OID_GEN_CURRENT_PACKET_FILTER			0x0001010E
#define	OID_GEN_CURRENT_LOOKAHEAD			0x0001010F
#define	OID_GEN_DRIVER_VERSION				0x00010110
#define	OID_GEN_MAXIMUM_TOTAL_SIZE			0x00010111
#define	OID_GEN_PROTOCOL_OPTIONS			0x00010112
#define	OID_GEN_MAC_OPTIONS				0x00010113
#define	OID_GEN_MEDIA_CONNECT_STATUS			0x00010114
#define	OID_GEN_MAXIMUM_SEND_PACKETS			0x00010115
#define	OID_GEN_VENDOR_DRIVER_VERSION			0x00010116
#define	OID_GEN_SUPPORTED_GUIDS				0x00010117
#define	OID_GEN_NETWORK_LAYER_ADDRESSES			0x00010118	/* S */
#define	OID_GEN_TRANSPORT_HEADER_OFFSET			0x00010119	/* S */
#define	OID_GEN_MEDIA_CAPABILITIES			0x00010201
#define	OID_GEN_PHYSICAL_MEDIUM				0x00010202
#define	OID_GEN_MACHINE_NAME				0x0001021A
#define	OID_GEN_RNDIS_CONFIG_PARAMETER			0x0001021B	/* S */
#define	OID_GEN_VLAN_ID					0x0001021C

/* Required statistics OIDs */
#define	OID_GEN_XMIT_OK					0x00020101
#define	OID_GEN_RCV_OK					0x00020102
#define	OID_GEN_XMIT_ERROR				0x00020103
#define	OID_GEN_RCV_ERROR				0x00020104
#define	OID_GEN_RCV_NO_BUFFER				0x00020105

/* Optional OID statistics */
#define	OID_GEN_DIRECTED_BYTES_XMIT			0x00020201
#define	OID_GEN_DIRECTED_FRAMES_XMIT			0x00020202
#define	OID_GEN_MULTICAST_BYTES_XMIT			0x00020203
#define	OID_GEN_MULTICAST_FRAMES_XMIT			0x00020204
#define	OID_GEN_BROADCAST_BYTES_XMIT			0x00020205
#define	OID_GEN_BROADCAST_FRAMES_XMIT			0x00020206
#define	OID_GEN_DIRECTED_BYTES_RCV			0x00020207
#define	OID_GEN_DIRECTED_FRAMES_RCV			0x00020208
#define	OID_GEN_MULTICAST_BYTES_RCV			0x00020209
#define	OID_GEN_MULTICAST_FRAMES_RCV			0x0002020A
#define	OID_GEN_BROADCAST_BYTES_RCV			0x0002020B
#define	OID_GEN_BROADCAST_FRAMES_RCV			0x0002020C
#define	OID_GEN_RCV_CRC_ERROR				0x0002020D
#define	OID_GEN_TRANSMIT_QUEUE_LENGTH			0x0002020E
#define	OID_GEN_GET_TIME_CAPS				0x0002020F
#define	OID_GEN_GET_NETCARD_TIME			0x00020210
#define	OID_GEN_NETCARD_LOAD				0x00020211
#define	OID_GEN_DEVICE_PROFILE				0x00020212
#define	OID_GEN_INIT_TIME_MS				0x00020213
#define	OID_GEN_RESET_COUNTS				0x00020214
#define	OID_GEN_MEDIA_SENSE_COUNTS			0x00020215
#define	OID_GEN_FRIENDLY_NAME				0x00020216
#define	OID_GEN_MINIPORT_INFO				0x00020217
#define	OID_GEN_RESET_VERIFY_PARAMETERS			0x00020218

/* 802.3 (ethernet) OIDs */
#define	OID_802_3_PERMANENT_ADDRESS			0x01010101
#define	OID_802_3_CURRENT_ADDRESS			0x01010102
#define	OID_802_3_MULTICAST_LIST			0x01010103
#define	OID_802_3_MAXIMUM_LIST_SIZE			0x01010104
#define	OID_802_3_MAC_OPTIONS				0x01010105
#define	NDIS_802_3_MAC_OPTION_PRIORITY			0x00000001
#define	OID_802_3_RCV_ERROR_ALIGNMENT			0x01020101
#define	OID_802_3_XMIT_ONE_COLLISION			0x01020102
#define	OID_802_3_XMIT_MORE_COLLISIONS			0x01020103
#define	OID_802_3_XMIT_DEFERRED				0x01020201
#define	OID_802_3_XMIT_MAX_COLLISIONS			0x01020202
#define	OID_802_3_RCV_OVERRUN				0x01020203
#define	OID_802_3_XMIT_UNDERRUN				0x01020204
#define	OID_802_3_XMIT_HEARTBEAT_FAILURE		0x01020205
#define	OID_802_3_XMIT_TIMES_CRS_LOST			0x01020206
#define	OID_802_3_XMIT_LATE_COLLISIONS			0x01020207

/*
 * 802.11 OIDs
 *
 * q - query not supported	Q - query supported
 * s - set not supported	S - set supported
 *
 * 2000 & Me			XP and later
 * m - mandatory		M - mandatory
 * r - recommended		R - recommended
 * o - optional			O - optional
 */
#define	OID_802_11_BSSID				0x0D010101 /* QSmM */
#define	OID_802_11_SSID					0x0D010102 /* QSmM */
#define	OID_802_11_INFRASTRUCTURE_MODE			0x0D010108 /* QSrM */
#define	OID_802_11_ADD_WEP				0x0D010113 /* qSmM */
#define	OID_802_11_REMOVE_WEP				0x0D010114 /* qSrM */
#define	OID_802_11_DISASSOCIATE				0x0D010115 /* qSoM */
#define	OID_802_11_AUTHENTICATION_MODE			0x0D010118 /* QSrM */
#define	OID_802_11_PRIVACY_FILTER			0x0D010119 /* QSoO */
#define	OID_802_11_BSSID_LIST_SCAN			0x0D01011A /* qSrM */
#define	OID_802_11_WEP_STATUS				0x0D01011B /* QSrM */
#define	OID_802_11_RELOAD_DEFAULTS			0x0D01011C /* qSrM */
#define	OID_802_11_ADD_KEY				0x0D01011D /* qSoO */
#define	OID_802_11_REMOVE_KEY				0x0D01011E /* qSoO */
#define	OID_802_11_ASSOCIATION_INFORMATION		0x0D01011F /* QsoO */
#define	OID_802_11_TEST					0x0D010120 /* qSoO */
#define	OID_802_11_MEDIA_STREAM_MODE			0x0D010121 /* QSrR */
#define	OID_802_11_CAPABILITY				0x0D010122 /* QsoO */
#define	OID_802_11_PMKID				0x0D010123 /* QSoO */
#define	OID_802_11_NETWORK_TYPES_SUPPORTED		0x0D010203 /* QsrR */
#define	OID_802_11_NETWORK_TYPE_IN_USE			0x0D010204 /* QSoM */
#define	OID_802_11_TX_POWER_LEVEL			0x0D010205 /* QSoO */
#define	OID_802_11_RSSI					0x0D010206 /* QsoM */
#define	OID_802_11_RSSI_TRIGGER				0x0D010207 /* QSoO */
#define	OID_802_11_FRAGMENTATION_THRESHOLD		0x0D010209 /* QSoO */
#define	OID_802_11_RTS_THRESHOLD			0x0D01020A /* QSoO */
#define	OID_802_11_NUMBER_OF_ANTENNAS			0x0D01020B /* QsoO */
#define	OID_802_11_RX_ANTENNA_SELECTED			0x0D01020C /* QSoO */
#define	OID_802_11_TX_ANTENNA_SELECTED			0x0D01020D /* QSoO */
#define	OID_802_11_SUPPORTED_RATES			0x0D01020E /* QsoM */
#define	OID_802_11_DESIRED_RATES			0x0D010210 /* QSoO */
#define	OID_802_11_CONFIGURATION			0x0D010211 /* QSoM */
#define	OID_802_11_STATISTICS				0x0D020212 /* QsrR */
#define	OID_802_11_POWER_MODE				0x0D010216 /* QSrR */
#define	OID_802_11_BSSID_LIST				0x0D010217 /* QsrM */
#define	OID_802_11_ENCRYPTION_STATUS			OID_802_11_WEP_STATUS

#define	OID_TCP_TASK_OFFLOAD				0xFC010201
#define	OID_TCP_TASK_IPSEC_ADD_SA			0xFC010202
#define	OID_TCP_TASK_IPSEC_DELETE_SA			0xFC010203
#define	OID_TCP_SAN_SUPPORT				0xFC010204

/* PnP and power management OIDs */
#define	OID_PNP_CAPABILITIES				0xFD010100
#define	OID_PNP_SET_POWER				0xFD010101
#define	OID_PNP_QUERY_POWER				0xFD010102
#define	OID_PNP_ADD_WAKE_UP_PATTERN			0xFD010103
#define	OID_PNP_REMOVE_WAKE_UP_PATTERN			0xFD010104
#define	OID_PNP_WAKE_UP_PATTERN_LIST			0xFD010105
#define	OID_PNP_ENABLE_WAKE_UP				0xFD010106

/* PnP/PM Statistics (Optional). */
#define	OID_PNP_WAKE_UP_OK				0xFD020200
#define	OID_PNP_WAKE_UP_ERROR				0xFD020201

/* The following bits are defined for OID_PNP_ENABLE_WAKE_UP */
#define	NDIS_PNP_WAKE_UP_MAGIC_PACKET			0x00000001
#define	NDIS_PNP_WAKE_UP_PATTERN_MATCH			0x00000002
#define	NDIS_PNP_WAKE_UP_LINK_CHANGE			0x00000004

enum ndis_80211_authentication_mode {
	NDIS_802_11_AUTH_MODE_OPEN,
	NDIS_802_11_AUTH_MODE_SHARED,
	NDIS_802_11_AUTH_MODE_AUTO,
	NDIS_802_11_AUTH_MODE_WPA,
	NDIS_802_11_AUTH_MODE_WPAPSK,
	NDIS_802_11_AUTH_MODE_WPANONE,
	NDIS_802_11_AUTH_MODE_WPA2,
	NDIS_802_11_AUTH_MODE_WPA2PSK
};

enum ndis_80211_encryption_status {
	NDIS_802_11_WEPSTAT_ENABLED,
	NDIS_802_11_WEPSTAT_ENC1ENABLED = NDIS_802_11_WEPSTAT_ENABLED,
	NDIS_802_11_WEPSTAT_DISABLED,
	NDIS_802_11_WEPSTAT_ENCDISABLED = NDIS_802_11_WEPSTAT_DISABLED,
	NDIS_802_11_WEPSTAT_KEYABSENT,
	NDIS_802_11_WEPSTAT_ENC1KEYABSENT = NDIS_802_11_WEPSTAT_KEYABSENT,
	NDIS_802_11_WEPSTAT_NOTSUPPORTED,
	NDIS_802_11_WEPSTAT_ENCNOTSUPPORTED = NDIS_802_11_WEPSTAT_NOTSUPPORTED,
	NDIS_802_11_WEPSTAT_ENC2ENABLED,
	NDIS_802_11_WEPSTAT_ENC2KEYABSENT,
	NDIS_802_11_WEPSTAT_ENC3ENABLED,
	NDIS_802_11_WEPSTAT_ENC3KEYABSENT
};

enum ndis_80211_network_infrastructure {
	NDIS_802_11_IBSS,
	NDIS_802_11_INFRASTRUCTURE,
	NDIS_802_11_AUTO_UNKNOWN
};

enum ndis_80211_network_type {
	NDIS_802_11_11FH,
	NDIS_802_11_11DS,
	NDIS_802_11_11OFDM5,
	NDIS_802_11_11OFDM24,
	NDIS_802_11_AUTO
};

enum ndis_80211_power_mode {
	NDIS_802_11_POWER_MODE_CAM,
	NDIS_802_11_POWER_MODE_MAX_PSP,
	NDIS_802_11_POWER_MODE_FAST_PSP
};

enum ndis_80211_privacy_filter {
	NDIS_802_11_PRIVFILT_ACCEPTALL,
	NDIS_802_11_PRIVFILT_8021XWEP
};

enum ndis_80211_radio_status {
	NDIS_802_11_RADIO_STATUS_ON,
	NDIS_802_11_RADIO_STATUS_HARDWARE_OFF,
	NDIS_802_11_RADIO_STATUS_SOFTWARE_OFF
};

enum ndis_80211_status_type {
	NDIS_802_11_STATUS_TYPE_AUTHENTICATION,
	NDIS_802_11_STATUS_TYPE_MEDIA_STREAM_MODE,
	NDIS_802_11_STATUS_TYPE_PMKID_CANDIDATE_LIST,
	NDIS_802_11_STATUS_TYPE_RADIO_STATE
};

enum ndis_classid {
	NDIS_CLASS_802_3PRIO,
	NDIS_CLASS_WIRELESSWAN_MBX,
	NDIS_CLASS_IRDA_PACKETINFO,
	NDIS_CLASS_ATM_AAINFO
};

enum ndis_device_pnp_event {
	NDIS_DEVICE_PNP_EVENT_QUERY_REMOVED,
	NDIS_DEVICE_PNP_EVENT_REMOVED,
	NDIS_DEVICE_PNP_EVENT_SURPRISE_REMOVED,
	NDIS_DEVICE_PNP_EVENT_QUERY_STOPPED,
	NDIS_DEVICE_PNP_EVENT_STOPPED,
	NDIS_DEVICE_PNP_EVENT_POWER_PROFILE_CHANGED
};

enum ndis_device_power_state {
	NDIS_DEVICE_STATE_UNSPEC,
	NDIS_DEVICE_STATE_D0,
	NDIS_DEVICE_STATE_D1,
	NDIS_DEVICE_STATE_D2,
	NDIS_DEVICE_STATE_D3
};

enum ndis_hardware_status {
	NDIS_HARDWARE_STATUS_READY,
	NDIS_HARDWARE_STATUS_INITIALIZING,
	NDIS_HARDWARE_STATUS_RESET,
	NDIS_HARDWARE_STATUS_CLOSING,
	NDIS_HARDWARE_STATUS_NOT_READY
};

enum ndis_bus_type {
	NDIS_INTERNAL,
	NDIS_ISA,
	NDIS_EISA,
	NDIS_MCA,
	NDIS_TURBO_CHANNEL,
	NDIS_PCIBUS,
	NDIS_VMEBUS,
	NDIS_NUBUS,
	NDIS_PCMCIABUS,
	NDIS_CBUS,
	NDIS_MPIBUS,
	NDIS_MPSABUS,
	NDIS_PROCESSOR_INTERNAL,
	NDIS_INTERNAL_POWERBUS,
	NDIS_PNPISABUS,
	NDIS_PNPBUS
};

enum ndis_net_if_access_type {
	NDIS_NET_IF_ACCESS_LOOPBACK = 1,
	NDIS_NET_IF_ACCESS_BROADCAST,
	NDIS_NET_IF_ACCESS_POINT_TO_POINT,
	NDIS_NET_IF_ACCESS_POINT_TO_MULTI_POINT,
	NDIS_NET_IF_ACCESS_MAXIMUM
};

enum ndis_net_if_direction_type {
	NDIS_NET_IF_DIRECTION_SENDRECEIVE,
	NDIS_NET_IF_DIRECTION_SENDONLY,
	NDIS_NET_IF_DIRECTION_RECEIVEONLY,
	NDIS_NET_IF_DIRECTION_MAXIMUM
};

enum ndis_net_if_connection_type {
	NDIS_NET_IF_CONNECTION_DEDICATED = 1,
	NDIS_NET_IF_CONNECTION_PASSIVE,
	NDIS_NET_IF_CONNECTION_DEMAND,
	NDIS_NET_IF_CONNECTION_MAXIMUM
};

enum ndis_interrupt_mode {
	NIM_LEVEL,
	NIM_LATCHED
};

enum ndis_media_connect_state {
	NDIS_MEDIA_CONNECT_STATE_UNKNOWN,
	NDIS_MEDIA_CONNECT_STATE_CONNECTED,
	NDIS_MEDIA_CONNECT_STATE_DISCONNECTED
};

enum ndis_media_duplex_state {
	NDIS_MEDIA_DUPLEX_STATE_UNKNOWN,
	NDIS_MEDIA_DUPLEX_STATE_HALF,
	NDIS_MEDIA_DUPLEX_STATE_FULL
};

enum ndis_media_state {
	NDIS_MEDIA_STATE_CONNECTED,
	NDIS_MEDIA_STATE_DISCONNECTED
};

enum ndis_medium {
	NDIS_MEDIUM_802_3,
	NDIS_MEDIUM_802_5,
	NDIS_MEDIUM_FDDI,
	NDIS_MEDIUM_WAN,
	NDIS_MEDIUM_LOCAL_TALK,
	NDIS_MEDIUM_DIX,
	NDIS_MEDIUM_ARCNET_RAW,
	NDIS_MEDIUM_ARCNET_878_2,
	NDIS_MEDIUM_ATM,
	NDIS_MEDIUM_WIRELESS_WAN,
	NDIS_MEDIUM_IRDA,
	NDIS_MEDIUM_BPC,
	NDIS_MEDIUM_COWAN,
	NDIS_MEDIUM_1394,
	NDIS_MEDIUM_MAX
};

enum ndis_parameter_type {
	NDIS_PARAMETER_INTEGER,
	NDIS_PARAMETER_HEX_INTEGER,
	NDIS_PARAMETER_STRING,
	NDIS_PARAMETER_MULTI_STRING,
	NDIS_PARAMETER_BINARY
};

enum ndis_per_packet_info {
	TCP_IP_CHECKSUM_PACKET_INFO,
	IP_SEC_PACKET_INFO,
	TCP_LARGE_SEND_PACKET_INFO,
	CLASSIFICATION_HANDLE_PACKET_INFO,
	RESERVED,
	SCATTER_GATHER_LIST_PACKET_INFO,
	IEEE_8021Q_INFO,
	ORIGINAL_PACKET_INFO,
	PACKET_CANCEL_ID,
	MAX_PER_PACKET_INFO
};

enum ndis_physical_medium {
	NDIS_PHYSICAL_MEDIUM_UNSPECIFIED,
	NDIS_PHYSICAL_MEDIUM_WIRELESS_LAN,
	NDIS_PHYSICAL_MEDIUM_CABLE_MODEM,
	NDIS_PHYSICAL_MEDIUM_PHONE_LINE,
	NDIS_PHYSICAL_MEDIUM_POWER_LINE,
	NDIS_PHYSICAL_MEDIUM_DSL,
	NDIS_PHYSICAL_MEDIUM_FIBRE_CHANNEL,
	NDIS_PHYSICAL_MEDIUM_1394,
	NDIS_PHYSICAL_MEDIUM_WIRELESS_WAN,
	NDIS_PHYSICAL_MEDIUM_NATIVE802_11,
	NDIS_PHYSICAL_MEDIUM_BLUETOOTH,
	NDIS_PHYSICAL_MEDIUM_INFINIBAND,
	NDIS_PHYSICAL_MEDIUM_WIMAX,
	NDIS_PHYSICAL_MEDIUM_UWB,
	NDIS_PHYSICAL_MEDIUM_802_3,
	NDIS_PHYSICAL_MEDIUM_802_5,
	NDIS_PHYSICAL_MEDIUM_IRDA,
	NDIS_PHYSICAL_MEDIUM_WIRED_WAN,
	NDIS_PHYSICAL_MEDIUM_WIRED_COWAN,
	NDIS_PHYSICAL_MEDIUM_OTHER
};

enum ndis_power_profile {
	NDIS_POWER_PROFILE_BATTERY,
	NDIS_POWER_PROFILE_ACONLINE
};

enum net_pnp_event_code {
	NET_EVENT_SET_POWER,
	NET_EVENT_QUERY_POWER,
	NET_EVENT_QUERY_REMOVE_DEVICE,
	NET_EVENT_CANCEL_REMOVE_DEVICE,
	NET_EVENT_RECONFIGURE,
	NET_EVENT_BIND_LIST,
	NET_EVENT_BINDS_COMPLETE,
	NET_EVENT_PNP_CAPABILITIES
};

enum ndis_request_type {
	NDIS_REQUEST_QUERY_INFORMATION,
	NDIS_REQUEST_SET_INFORMATION,
	NDIS_REQUEST_QUERY_STATISTICS,
	NDIS_REQUEST_OPEN,
	NDIS_REQUEST_CLOSE,
	NDIS_REQUEST_SEND,
	NDIS_REQUEST_TRANSFER_DATA,
	NDIS_REQUEST_RESET,
	NDIS_REQUEST_GENERIC_1,
	NDIS_REQUEST_GENERIC_2,
	NDIS_REQUEST_GENERIC_3,
	NDIS_REQUEST_GENERIC_4
};

struct ndis_object_header {
	uint8_t		type;
	uint8_t		revision;
	uint16_t	size;
};

/* NDIS object header types */
#define	NDIS_OBJECT_TYPE_DEFAULT					0x80
#define	NDIS_OBJECT_TYPE_MINIPORT_INIT_PARAMETERS			0x81
#define	NDIS_OBJECT_TYPE_SG_DMA_DESCRIPTION				0x83
#define	NDIS_OBJECT_TYPE_MINIPORT_INTERRUPT				0x84
#define	NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES			0x85
#define	NDIS_OBJECT_TYPE_BIND_PARAMETERS				0x86
#define	NDIS_OBJECT_TYPE_OPEN_PARAMETERS				0x87
#define	NDIS_OBJECT_TYPE_RSS_CAPABILITIES				0x88
#define	NDIS_OBJECT_TYPE_RSS_PARAMETERS					0x89
#define	NDIS_OBJECT_TYPE_MINIPORT_DRIVER_CHARACTERISTICS		0x8A
#define	NDIS_OBJECT_TYPE_FILTER_DRIVER_CHARACTERISTICS			0x8B
#define	NDIS_OBJECT_TYPE_FILTER_PARTIAL_CHARACTERISTICS			0x8C
#define	NDIS_OBJECT_TYPE_FILTER_ATTRIBUTES				0x8D
#define	NDIS_OBJECT_TYPE_CLIENT_CHIMNEY_OFFLOAD_GENERIC_CHARACTERISTICS	0x8E
#define	NDIS_OBJECT_TYPE_PROVIDER_CHIMNEY_OFFLOAD_GENERIC_CHARACTERISTICS 0x8F
#define	NDIS_OBJECT_TYPE_CO_PROTOCOL_CHARACTERISTICS			0x90
#define	NDIS_OBJECT_TYPE_CO_MINIPORT_CHARACTERISTICS			0x91
#define	NDIS_OBJECT_TYPE_MINIPORT_PNP_CHARACTERISTICS			0x92
#define	NDIS_OBJECT_TYPE_CLIENT_CHIMNEY_OFFLOAD_CHARACTERISTICS		0x93
#define	NDIS_OBJECT_TYPE_PROVIDER_CHIMENY_OFFLOAD_CHARACTERISTICS	0x94
#define	NDIS_OBJECT_TYPE_PROTOCOL_DRIVER_CHARACTERISTICS		0x95
#define	NDIS_OBJECT_TYPE_REQUEST_EX					0x96
#define	NDIS_OBJECT_TYPE_OID_REQUEST					0x96
#define	NDIS_OBJECT_TYPE_TIMER_CHARACTERISTICS				0x97
#define	NDIS_OBJECT_TYPE_STATUS_INDICATION				0x98
#define	NDIS_OBJECT_TYPE_FILTER_ATTACH_PARAMETERS			0x99
#define	NDIS_OBJECT_TYPE_FILTER_PAUSE_PARAMETERS			0x9A
#define	NDIS_OBJECT_TYPE_FILTER_RESTART_PARAMETERS			0x9B
#define	NDIS_OBJECT_TYPE_PORT_CHARACTERISTICS				0x9C
#define	NDIS_OBJECT_TYPE_PORT_STATE					0x9D
#define	NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES	0x9E
#define	NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES		0x9F
#define	NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_OFFLOAD_ATTRIBUTES		0xA0
#define	NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_NATIVE_802_11_ATTRIBUTES	0xA1
#define	NDIS_OBJECT_TYPE_RESTART_GENERAL_ATTRIBUTES			0xA2
#define	NDIS_OBJECT_TYPE_PROTOCOL_RESTART_PARAMETERS			0xA3
#define	NDIS_OBJECT_TYPE_MINIPORT_ADD_DEVICE_REGISTRATION_ATTRIBUTES	0xA4
#define	NDIS_OBJECT_TYPE_CO_CALL_MANAGER_OPTIONAL_HANDLERS		0xA5
#define	NDIS_OBJECT_TYPE_CO_CLIENT_OPTIONAL_HANDLERS			0xA6
#define	NDIS_OBJECT_TYPE_OFFLOAD					0xA7
#define	NDIS_OBJECT_TYPE_OFFLOAD_ENCAPSULATION				0xA8
#define	NDIS_OBJECT_TYPE_CONFIGURATION_OBJECT				0xA9
#define	NDIS_OBJECT_TYPE_DRIVER_WRAPPER_OBJECT				0xAA
#define	NDIS_OBJECT_TYPE_HD_SPLIT_ATTRIBUTES				0xAB
#define	NDIS_OBJECT_TYPE_NSI_NETWORK_RW_STRUCT				0xAC
#define	NDIS_OBJECT_TYPE_NSI_COMPARTMENT_RW_STRUCT			0xAD
#define	NDIS_OBJECT_TYPE_NSI_INTERFACE_PERSIST_RW_STRUCT		0xAE
#define	NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_HARDWARE_ASSIST_ATTRIBUTES	0xAF
#define	NDIS_OBJECT_TYPE_SHARED_MEMORY_PROVIDER_CHARACTERISTICS		0xB0
#define	NDIS_OBJECT_TYPE_RSS_PROCESSOR_INFO				0xB1

typedef void (*ndis_timer_function)(void *, void *, void *, void *);

struct ndis_timer_characteristics {
	struct ndis_object_header	header;
	uint32_t			allocation_tag;
	ndis_timer_function		timer_function;
	void				*function_context;
};

union net_luid {
	uint64_t	value;
	struct {
		uint64_t	reserved:24;
		uint64_t	net_luid_index:24;
		uint64_t	iftype:16;
	} info;
};

enum ndis_port_control_state {
	NDIS_PORT_CONTROL_STATE_UNKNOWN,
	NDIS_PORT_CONTROL_STATE_CONTROLLED,
	NDIS_PORT_CONTROL_STATE_UNCONTROLLED
};

enum ndis_port_authorization_state {
	NDIS_PORT_AUTHORIZATION_UNKNOWN,
	NDIS_PORT_AUTHORIZED,
	NDIS_PORT_UNAUTHORIZED,
	NDIS_PORT_REAUTHORIZING
};

struct ndis_port_authentication_parameters {
	struct ndis_object_header		header;
	enum ndis_port_control_state		send_control_state;
	enum ndis_port_control_state		rcv_control_state;
	enum ndis_port_authorization_state	send_authorization_state;
	enum ndis_port_authorization_state	rcv_authorization_state;
};

struct ndis_pci_device_custom_properties {
	struct ndis_object_header	header;
	uint32_t			device_type;
	uint32_t			current_speed_and_mode;
	uint32_t			current_payload_size;
	uint32_t			max_payload_size;
	uint32_t			max_read_request_size;
	uint32_t			current_link_speed;
	uint32_t			current_link_width;
	uint32_t			max_link_speed;
	uint32_t			max_link_width;
	uint32_t			pci_express_version;
	uint32_t			interrupt_type;
	uint32_t			max_interrupt_messages;
};

struct ndis_miniport_init_parameters {
	struct ndis_object_header		header;
	uint32_t				flags;
	struct cm_partial_resource_list		*allocated_resources;
	void					*im_device_instance_context;
	void					*miniport_add_device_context;
	uint32_t				if_index;
	union net_luid				net_luid;
	struct ndis_port_authentication_parameters *default_port_auth_states;
	struct ndis_pci_device_custom_properties *pci_device_custom_properties;
};

struct ndis_miniport_add_device_registration_attributes {
	struct ndis_object_header	header;
	void				*miniport_add_device_context;
	uint32_t			flags;
};

#define NDIS_MINIPORT_ATTRIBUTES_HARDWARE_DEVICE	0x00000001
#define NDIS_MINIPORT_ATTRIBUTES_NDIS_WDM		0x00000002
#define NDIS_MINIPORT_ATTRIBUTES_SURPRISE_REMOVE_OK	0x00000004
#define NDIS_MINIPORT_ATTRIBUTES_NOT_CO_NDIS		0x00000008
#define NDIS_MINIPORT_ATTRIBUTES_DO_NOT_BIND_TO_ALL_CO	0x00000010
#define NDIS_MINIPORT_ATTRIBUTES_NO_HALT_ON_SUSPEND	0x00000020
#define NDIS_MINIPORT_ATTRIBUTES_BUS_MASTER		0x00000040
#define NDIS_MINIPORT_ATTRIBUTES_CONTROLS_DEFAULT_PORT	0x00000080

struct ndis_miniport_adapter_registration_attributes {
	struct ndis_object_header	header;
	void				*miniport_adapter_context;
	uint32_t			attribute_flags;
	uint32_t			check_for_hangsec;
	enum ndis_bus_type		bus_type;
};

struct ndis_receive_scale_capabilities {
	struct ndis_object_header	header;
	uint32_t			flags;
	uint32_t			number_of_interrupt_messages;
	uint32_t			number_of_receive_queues;
};

struct ndis_pm_capabilities {
	struct ndis_object_header	header;
	uint32_t			flags;
	uint32_t			supported_wol_packet_patterns;
	uint32_t			num_total_wol_patterns;
	uint32_t			max_wol_pattern_size;
	uint32_t			max_wol_pattern_offset;
	uint32_t			max_wol_packet_save_buffer;
	uint32_t			supported_protocol_offloads;
	uint32_t			num_arp_offload_ipv4_addresses;
	uint32_t			num_ns_offload_ipv6_addresses;
	enum ndis_device_power_state	min_magic_packet_wake_up;
	enum ndis_device_power_state	min_pattern_wake_up;
	enum ndis_device_power_state	min_link_change_wake_up;
};

struct ndis_miniport_adapter_general_attributes {
	struct ndis_object_header		header;
	uint32_t				flags;
	enum ndis_medium			media_type;
	enum ndis_physical_medium		physical_medium_type;
	uint32_t				mtu_size;
	uint64_t				max_xmit_link_speed;
	uint64_t				xmit_link_speed;
	uint64_t				max_rcv_link_speed;
	uint64_t				rcv_link_speed;
	enum ndis_media_connect_state		media_connect_state;
	enum ndis_media_duplex_state		media_duplex_state;
	uint32_t				lookahead_size;
	struct ndis_pnp_capabilities		*power_management_capabilities;
	uint32_t				mac_options;
	uint32_t				supported_packet_filters;
	uint32_t				max_multicast_list_size;
	uint16_t				mac_address_length;
	uint8_t					permanent_mac_address[32];
	uint8_t					current_mac_address[32];
	struct ndis_receive_scale_capabilities	*recv_scale_capabilities;
	enum ndis_net_if_access_type		access_type;
	enum ndis_net_if_direction_type		direction_type;
	enum ndis_net_if_connection_type	connection_type;
	uint16_t				iftype;
	uint8_t					if_connector_present;
	uint32_t				supported_statistics;
	uint32_t				supported_pause_functions;
	uint32_t				data_back_fill_size;
	uint32_t				context_back_fill_size;
	uint32_t				*supported_oid_list;
	uint32_t				supported_oid_list_length;
	uint32_t				auto_negotiation_flags;
	struct ndis_pm_capabilities		*power_management_capabilities_ex;
};

struct ndis_tcp_ip_checksum_offload {
	struct {
		uint32_t	encapsulation;
		uint32_t	ip_options_supported:2;
		uint32_t	tcp_options_supported:2;
		uint32_t	tcp_checksum:2;
		uint32_t	udp_checksum:2;
		uint32_t	ip_checksum:2;
	} ipv4transmit;
	struct {
		uint32_t	encapsulation;
		uint32_t	ip_options_supported:2;
		uint32_t	tcp_options_supported:2;
		uint32_t	tcp_checksum:2;
		uint32_t	udp_checksum:2;
		uint32_t	ip_checksum:2;
	} ipv4receive;
	struct {
		uint32_t	encapsulation;
		uint32_t	ip_extension_headers_supported:2;
		uint32_t	tcp_options_supported:2;
		uint32_t	tcp_checksum:2;
		uint32_t	udp_checksum:2;
	} ipv6transmit;
	struct {
		uint32_t	encapsulation;
		uint32_t	ip_extension_headers_supported:2;
		uint32_t	tcp_options_supported:2;
		uint32_t	tcp_checksum:2;
		uint32_t	udp_checksum:2;
	} ipv6receive;
};

struct ndis_tcp_large_send_offload_v1 {
	struct {
		uint32_t	encapsulation;
		uint32_t	max_off_load_size;
		uint32_t	min_segment_count;
		uint32_t	tcp_options:2;
		uint32_t	ip_options:2;
	} ipv4;
};

struct ndis_ipsec_offload_v1 {
	struct {
		uint32_t	encapsulation;
		uint32_t	ah_esp_combined;
		uint32_t	transport_tunnel_combined;
		uint32_t	ipv4_options;
		uint32_t	flags;
	} supported;
	struct {
		uint32_t	md5:2;
		uint32_t	sha_1:2;
		uint32_t	transport:2;
		uint32_t	tunnel:2;
		uint32_t	send:2;
		uint32_t	receive:2;
	} ipv4ah;
	struct {
		uint32_t	des:2;
		uint32_t	reserved:2;
		uint32_t	triple_des:2;
		uint32_t	null_esp:2;
		uint32_t	transport:2;
		uint32_t	tunnel:2;
		uint32_t	send:2;
		uint32_t	receive:2;
	} ipv4esp;
};

struct ndis_tcp_large_send_offload_v2 {
	struct {
		uint32_t	encapsulation;
		uint32_t	max_off_load_size;
		uint32_t	min_segment_count;
	} ipv4;
	struct {
		uint32_t	encapsulation;
		uint32_t	max_off_load_size;
		uint32_t	min_segment_count;
		uint32_t	ip_extension_headers_supported:2;
		uint32_t	tcp_options_supported:2;
	} ipv6;
};

struct ndis_ipsec_offload_v2 {
	uint32_t	encapsulation;
	uint8_t		ipv6_supported;
	uint8_t		ipv4_options;
	uint8_t		ipv6_non_ipsec_extension_headers;
	uint8_t		ah;
	uint8_t		esp;
	uint8_t		ah_esp_combined;
	uint8_t		transport;
	uint8_t		tunnel;
	uint8_t		transport_tunnel_combined;
	uint8_t		lso_supported;
	uint8_t		extended_sequence_numbers;
	uint32_t	udp_esp;
	uint32_t	authentication_algorithms;
	uint32_t	encryption_algorithms;
	uint32_t	sa_offload_capacity;
};

struct ndis_offload {
	struct ndis_object_header		header;
	struct ndis_tcp_ip_checksum_offload	checksum;
	struct ndis_tcp_large_send_offload_v1	lsov1;
	struct ndis_ipsec_offload_v1		ipsecv1;
	struct ndis_tcp_large_send_offload_v2	lsov2;
	uint32_t				flags;
	struct ndis_ipsec_offload_v2		ipsecv2;
};

struct ndis_tcp_connection_offload {
	struct ndis_object_header	header;
	uint32_t			encapsulation;
	uint32_t			support_ipv4:2;
	uint32_t			support_ipv6:2;
	uint32_t			support_ipv6_extension_headers:2;
	uint32_t			support_sack:2;
	uint32_t			congestion_algorithm:4;
	uint32_t			tcp_connection_offload_capacity;
	uint32_t			flags;
};

struct ndis_miniport_adapter_offload_attributes {
	struct ndis_object_header		header;
	struct ndis_offload			*def_off_conf;
	struct ndis_offload			*hw_off_cap;
	struct ndis_tcp_connection_offload	*def_tcp_conn_off_conf;
	struct ndis_tcp_connection_offload	*tcp_conn_off_hw_cap;
};

enum dot11_phy_type {
	DOT11_PHY_TYPE_UNKNOWN = 0,
	DOT11_PHY_TYPE_ANY = DOT11_PHY_TYPE_UNKNOWN,
	DOT11_PHY_TYPE_FHSS = 1,
	DOT11_PHY_TYPE_DSSS = 2,
	DOT11_PHY_TYPE_IRBASEBAND = 3,
	DOT11_PHY_TYPE_OFDM = 4,
	DOT11_PHY_TYPE_HRDSSS = 5,
	DOT11_PHY_TYPE_ERP = 6,
	DOT11_PHY_TYPE_HT = 7,
	DOT11_PHY_TYPE_IHV_START = 0x80000000,
	DOT11_PHY_TYPE_IHV_END = 0xffffffff
};

enum dot11_temp_type {
	DOT11_TEMP_TYPE_UNKNOWN,
	DOT11_TEMP_TYPE_1,
	DOT11_TEMP_TYPE_2
};

enum dot11_diversity_support {
	DOT11_DIVERSITY_SUPPORT_UNKNOWN,
	DOT11_DIVERSITY_SUPPORT_FIXEDLIST,
	DOT11_DIVERSITY_SUPPORT_NOTSUPPORTED,
	DOT11_DIVERSITY_SUPPORT_DYNAMIC
};

struct dot11_hrdsss_phy_attributes {
	uint8_t		short_preamble_option_implemented;
	uint8_t		pbcc_option_implemented;
	uint8_t		channel_agility_present;
	uint32_t	hrcca_mode_supported;
};

struct dot11_ofdm_phy_attributes {
	uint32_t	frequency_bands_supported;
};

struct dot11_erp_phy_attributes {
	struct dot11_hrdsss_phy_attributes	HRDSSS_attributes;
	uint8_t			erppbcc_option_implemented;
	uint8_t			dsssofdm_option_implemented;
	uint8_t			short_slot_time_option_implemented;
};

struct dot11_data_rate_mapping_entry {
	uint8_t		data_rate_index;
	uint8_t		data_rate_flag;
	uint16_t	data_rate_value;
};

#define	MAX_NUM_SUPPORTED_RATES_V2	8

struct dot11_supported_data_rates_value_v2 {
	uint8_t		tx[MAX_NUM_SUPPORTED_RATES_V2];
	uint8_t		rx[MAX_NUM_SUPPORTED_RATES_V2];
};

#define	DOT11_RATE_SET_MAX_LENGTH	126

struct dot11_phy_attributes {
	struct ndis_object_header	header;
	enum dot11_phy_type		phy_type;
	uint8_t				hardware_phy_state;
	uint8_t				software_phy_state;
	uint8_t				cfpollable;
	uint32_t			mpdu_max_length;
	enum dot11_temp_type		temp_type;
	enum dot11_diversity_support	diversity_support;
	union {
	struct dot11_hrdsss_phy_attributes	hrdsss_attributes;
	struct dot11_ofdm_phy_attributes	ofdm_attributes;
	struct dot11_erp_phy_attributes		erp_attributes;
	} u;
	uint32_t				num_supported_power_levels;
	uint32_t				tx_power_levels[8];
	uint32_t				num_data_rate_mapping_entries;
	struct dot11_data_rate_mapping_entry	data_rate_mapping_entries[DOT11_RATE_SET_MAX_LENGTH];
	struct dot11_supported_data_rates_value_v2 supported_data_rates_value;
};

enum dot11_auth_algorithm {
	DOT11_AUTH_ALGO_80211_OPEN = 1,
	DOT11_AUTH_ALGO_80211_SHARED_KEY = 2,
	DOT11_AUTH_ALGO_WPA = 3,
	DOT11_AUTH_ALGO_WPA_PSK	= 4,
	DOT11_AUTH_ALGO_WPA_NONE = 5,
	DOT11_AUTH_ALGO_RSNA = 6,
	DOT11_AUTH_ALGO_RSNA_PSK = 7,
	DOT11_AUTH_ALGO_IHV_START = 0x80000000,
	DOT11_AUTH_ALGO_IHV_END = 0xffffffff
};

enum dot11_cipher_algorithm {
	DOT11_CIPHER_ALGO_NONE = 0x00,
	DOT11_CIPHER_ALGO_WEP40	= 0x01,
	DOT11_CIPHER_ALGO_TKIP = 0x02,
	DOT11_CIPHER_ALGO_CCMP = 0x04,
	DOT11_CIPHER_ALGO_WEP104 = 0x05,
	DOT11_CIPHER_ALGO_WPA_USE_GROUP = 0x100,
	DOT11_CIPHER_ALGO_RSN_USE_GROUP = 0x100,
	DOT11_CIPHER_ALGO_WEP = 0x101,
	DOT11_CIPHER_ALGO_IHV_START = 0x80000000,
	DOT11_CIPHER_ALGO_IHV_END = 0xffffffff
};

struct dot11_auth_cipher_pair {
	enum dot11_auth_algorithm	auth_algo_id;
	enum dot11_cipher_algorithm	cipher_algo_id;
};

struct dot11_extsta_attributes {
	struct ndis_object_header	header;
	uint32_t			ScanSSIDListSize;
	uint32_t			DesiredBSSIDListSize;
	uint32_t			DesiredSSIDListSize;
	uint32_t			ExcludedMacAddressListSize;
	uint32_t			PrivacyExemptionListSize;
	uint32_t			KeyMappingTableSize;
	uint32_t			DefaultKeyTableSize;
	uint32_t			WEPKeyValueMaxLength;
	uint32_t			PMKIDCacheSize;
	uint32_t			MaxNumPerSTADefaultKeyTables;
	uint8_t				StrictlyOrderedServiceClassImplemented;
	uint8_t				SupportedQoSProtocolFlags;
	uint8_t				SafeModeImplemented;
	uint32_t			NumSupportedCountryOrRegionStrings;
	uint8_t 			*CountryOrRegionStrings[3];
	uint32_t			InfraNumSupportedUcastAlgoPairs;
	struct dot11_auth_cipher_pair	*InfraSupportedUcastAlgoPairs;
	uint32_t			InfraNumSupportedMcastAlgoPairs;
	struct dot11_auth_cipher_pair	*InfraSupportedMcastAlgoPairs;
	uint32_t			AdhocNumSupportedUcastAlgoPairs;
	struct dot11_auth_cipher_pair	*AdhocSupportedUcastAlgoPairs;
	uint32_t			AdhocNumSupportedMcastAlgoPairs;
	struct dot11_auth_cipher_pair	*AdhocSupportedMcastAlgoPairs;
};

struct dot11_vwifi_combination {
	struct ndis_object_header	header;
	uint32_t			NumInfrastructure;
	uint32_t			NumAdhoc;
	uint32_t			NumSoftAP;
	uint32_t			NumVirtualStation;
};

struct dot11_vwifi_attributes {
	struct ndis_object_header	header;
	uint32_t			total_num_of_entries;
	struct dot11_vwifi_combination	combinations[1];
};

 struct dot11_extap_attributes {
	struct ndis_object_header	header;
	uint32_t			ScanSSIDListSize;
	uint32_t			DesiredSSIDListSize;
	uint32_t			PrivacyExemptionListSize;
	uint32_t			AssociationTableSize;
	uint32_t			DefaultKeyTableSize;
	uint32_t			WEPKeyValueMaxLength;
	uint8_t                         StrictlyOrderedServiceClassImplemented;
	uint32_t			NumSupportedCountryOrRegionStrings;
	uint8_t				*CountryOrRegionStrings[3];
	uint32_t			InfraNumSupportedUcastAlgoPairs;
	struct dot11_auth_cipher_pair	*InfraSupportedUcastAlgoPairs;
	uint32_t                        InfraNumSupportedMcastAlgoPairs;
	struct dot11_auth_cipher_pair	*InfraSupportedMcastAlgoPairs;
};

struct ndis_miniport_adapter_native_802_11_attributes {
	struct ndis_object_header	header;
	uint32_t			op_mode_capability;
	uint32_t			num_of_tx_buffers;
	uint32_t			num_of_rx_buffers;
	uint8_t				multi_domain_capability_implemented;
	uint32_t			num_supported_phys;
	struct dot11_phy_attributes	*supported_phy_attributes;
	struct dot11_extsta_attributes	*extsta_attributes;
	struct dot11_vwifi_attributes	*vwifi_attributes;
	struct dot11_extap_attributes	*extap_attributes;
};

struct ndis_80211_network_type_list {
	uint32_t			items;
	enum ndis_80211_network_type	type[1];
};

struct ndis_transport_header_offset {
	uint16_t	protocol_type;
	uint16_t	header_offset;
};

struct ndis_network_address {
	uint16_t	len;
	uint16_t	type;
	uint8_t		address[1];
};

struct ndis_network_address_list {
	int32_t				count;
	uint16_t			type;
	struct ndis_network_address	address[1];
};

struct ndis_80211_config_fh {
	uint32_t	len;
	uint32_t	hoppatterh;
	uint32_t	hopset;
	uint32_t	dwelltime;
};

struct ndis_80211_config {
	uint32_t			len;
	uint32_t			beaconperiod;
	uint32_t			atimwin;
	uint32_t			dsconfig;
	struct ndis_80211_config_fh	fhconfig;
};

struct ndis_80211_stats {
	uint32_t	len;
	int64_t		txfragcnt;
	int64_t		txmcastcnt;
	int64_t		failedcnt;
	int64_t		retrycnt;
	int64_t		multiretrycnt;
	int64_t		rtssuccesscnt;
	int64_t		rtsfailcnt;
	int64_t		ackfailcnt;
	int64_t		dupeframecnt;
	int64_t		rxfragcnt;
	int64_t		rxmcastcnt;
	int64_t		fcserrcnt;
};

struct ndis_80211_wep {
	uint32_t	len;
	uint32_t	keyidx;
	uint32_t	keylen;
	uint8_t		keydata[32];
};

struct ndis_80211_ssid {
	uint32_t	len;
	uint8_t		ssid[32];
};

struct ndis_wlan_bssid {
	uint32_t			len;
	uint8_t				macaddr[6];
	uint8_t				reserved[2];
	struct ndis_80211_ssid		ssid;
	uint32_t			privacy;
	int32_t				rssi;
	uint32_t			nettype;
	struct ndis_80211_config	config;
	uint32_t			netinfra;
	uint8_t				supportedrates[8];
};

struct ndis_80211_bssid_list {
	uint32_t			items;
	struct ndis_wlan_bssid		bssid[1];
};

struct ndis_wlan_bssid_ex {
	uint32_t			len;
	uint8_t				macaddr[6];
	uint8_t				reserved[2];
	struct ndis_80211_ssid		ssid;
	uint32_t			privacy;
	int32_t				rssi;
	uint32_t			nettype;
	struct ndis_80211_config	config;
	uint32_t			netinfra;
	uint8_t				supportedrates[16];
	uint32_t			ielen;
	uint8_t				ies[1];
};

struct ndis_80211_bssid_list_ex {
	uint32_t			items;
	struct ndis_wlan_bssid_ex	bssid[1];
};

struct ndis_80211_fixed_ies {
	uint8_t		tstamp[8];
	uint16_t	beaconint;
	uint16_t	caps;
};

struct ndis_80211_variable_ies {
	uint8_t		elemid;
	uint8_t		len;
	uint8_t		data[1];
};

struct ndis_80211_status_indication {
	enum ndis_80211_status_type	status_type;
};

struct ndis_80211_radio_status_indication {
	enum ndis_80211_status_type	status_type;
	enum ndis_80211_radio_status	radio_status;
};

#define	NDIS_802_11_AUTH_REQUEST_REAUTH			0x01
#define	NDIS_802_11_AUTH_REQUEST_KEYUPDATE		0x02
#define	NDIS_802_11_AUTH_REQUEST_PAIRWISE_ERROR		0x06
#define	NDIS_802_11_AUTH_REQUEST_GROUP_ERROR		0x0E

struct ndis_80211_auth_request {
	uint32_t		len;
	uint8_t			bssid[6];
	uint32_t		flags;
};

struct ndis_80211_key {
	uint32_t		len;
	uint32_t		keyidx;
	uint32_t		keylen;
	uint8_t			bssid[6];
	uint8_t			pad[6];
	uint64_t		keyrsc;
	uint8_t			keydata[32];
};

struct ndis_80211_remove_key {
	uint32_t		len;
	uint32_t		keyidx;
	uint8_t			bssid[6];
};

#define	NDIS_802_11_AI_REQFI_CAPABILITIES		0x00000001
#define	NDIS_802_11_AI_REQFI_LISTENINTERVAL		0x00000002
#define	NDIS_802_11_AI_REQFI_CURRENTAPADDRESS		0x00000004

#define	NDIS_802_11_AI_RESFI_CAPABILITIES		0x00000001
#define	NDIS_802_11_AI_RESFI_STATUSCODE			0x00000002
#define	NDIS_802_11_AI_RESFI_ASSOCIATIONID		0x00000004

struct ndis_80211_ai_reqfi {
	uint16_t		caps;
	uint16_t		listentint;
	uint8_t			currentapaddr[6];
};

struct ndis_80211_ai_resfi {
	uint16_t	caps;
	uint16_t	statuscode;
	uint16_t	associd;
};

struct ndis_80211_assoc_info {
	uint32_t			len;
	uint16_t			avail_req_fixed_ies;
	struct ndis_80211_ai_reqfi	req_fixed_ies;
	uint32_t			req_ielen;
	uint32_t			offset_req_ies;
	uint16_t			avail_resp_fixed_ies;
	struct ndis_80211_ai_resfi	resp_fixed_iex;
	uint32_t			resp_ielen;
	uint32_t			offset_resp_ies;
};

struct ndis_80211_auth_event {
	struct ndis_80211_status_indication	status;
	struct ndis_80211_auth_request		request[1];
};

struct ndis_80211_test {
	uint32_t	len;
	uint32_t	type;
	union {
		struct ndis_80211_auth_event	authevent;
		uint32_t			rssitrigger;
	} u;
};

struct ndis_80211_auth_encrypt {
	uint32_t	authmode;
	uint32_t	cryptstat;
};

struct ndis_80211_caps {
	uint32_t			len;
	uint32_t			version;
	uint32_t			numpmkids;
	struct ndis_80211_auth_encrypt	authencs[1];
};

struct ndis_80211_bssidinfo {
	uint8_t			bssid[6];
	uint8_t			pmkid[16];
};

struct ndis_80211_pmkid {
	uint32_t			len;
	uint32_t			bssidcnt;
	struct ndis_80211_bssidinfo	bssidinfo[1];
};

struct ndis_80211_pmkid_cand {
	uint8_t			bssid[6];
	uint32_t		flags;
};

#define	NDIS_802_11_PMKID_CANDIDATE_PREAUTH_ENABLED (0x01)

struct ndis_80211_pmkid_candidate_list {
	uint32_t			version;
	uint32_t			numcandidates;
	struct ndis_80211_pmkid_cand	candidatelist[1];
};

struct ndis_80211_enc_indication {
	uint32_t				statustype;
	struct ndis_80211_pmkid_candidate_list	pmkidlist;
};

#define	NDIS_TASK_OFFLOAD_VERSION 1

#define	NDIS_TASK_TCPIP_CSUM			0x00000000
#define	NDIS_TASK_IPSEC				0x00000001
#define	NDIS_TASK_TCP_LARGESEND			0x00000002

#define	NDIS_ENCAP_UNSPEC			0x00000000
#define	NDIS_ENCAP_NULL				0x00000001
#define	NDIS_ENCAP_IEEE802_3			0x00000002
#define	NDIS_ENCAP_IEEE802_5			0x00000003
#define	NDIS_ENCAP_SNAP_ROUTED			0x00000004
#define	NDIS_ENCAP_SNAP_BRIDGED			0x00000005

#define	NDIS_ENCAPFLAG_FIXEDHDRLEN		0x00000001

struct ndis_encapsulation_format {
	uint32_t	encapsulation;
	uint32_t	flags;
	uint32_t	encapsulation_header_size;
};

struct ndis_pm_wake_up_capabilities {
	enum ndis_device_power_state	min_magic_packet;
	enum ndis_device_power_state	min_pattern;
	enum ndis_device_power_state	min_link_change;
};

struct ndis_pnp_capabilities {
	uint32_t				flags;
	struct ndis_pm_wake_up_capabilities	capabilities;
};

struct ndis_task_offload_header {
	uint32_t				version;
	uint32_t				size;
	uint32_t				reserved;
	uint32_t				offset_first_task;
	struct ndis_encapsulation_format	encapsulation_format;
};

struct ndis_task_offload {
	uint32_t	version;
	uint32_t	size;
	uint32_t	task;
	uint32_t	offset_next_task;
	uint32_t	task_buffer_length;
	uint8_t		task_buffer[1];
};

#define	NDIS_TCPSUM_FLAGS_IP_OPTS	0x00000001
#define	NDIS_TCPSUM_FLAGS_TCP_OPTS	0x00000002
#define	NDIS_TCPSUM_FLAGS_TCP_CSUM	0x00000004
#define	NDIS_TCPSUM_FLAGS_UDP_CSUM	0x00000008
#define	NDIS_TCPSUM_FLAGS_IP_CSUM	0x00000010

struct ndis_task_tcpip_csum {
	uint32_t	v4tx;
	uint32_t	v4rx;
	uint32_t	v6tx;
	uint32_t	v6rx;
};

struct ndis_task_tcp_largesend {
	uint32_t	version;
	uint32_t	maxofflen;
	uint32_t	minsegcnt;
	uint8_t		tcpopt;
	uint8_t		ipopt;
};

#define	NDIS_IPSEC_AH_MD5		0x00000001
#define	NDIS_IPSEC_AH_SHA1		0x00000002
#define	NDIS_IPSEC_AH_TRANSPORT		0x00000004
#define	NDIS_IPSEC_AH_TUNNEL		0x00000008
#define	NDIS_IPSEC_AH_SEND		0x00000010
#define	NDIS_IPSEC_AH_RECEIVE		0x00000020

#define	NDIS_IPSEC_ESP_DES		0x00000001
#define	NDIS_IPSEC_ESP_RSVD		0x00000002
#define	NDIS_IPSEC_ESP_3DES		0x00000004
#define	NDIS_IPSEC_ESP_NULL		0x00000008
#define	NDIS_IPSEC_ESP_TRANSPORT	0x00000010
#define	NDIS_IPSEC_ESP_TUNNEL		0x00000020
#define	NDIS_IPSEC_ESP_SEND		0x00000040
#define	NDIS_IPSEC_ESP_RECEIVE		0x00000080

struct ndis_task_ipsec {
	uint32_t	ah_esp_combined;
	uint32_t	ah_transport_tunnel_combined;
	uint32_t	v4_options;
	uint32_t	reserved;
	uint32_t	v4ah;
	uint32_t	v4esp;
};

/*
 * Attribures of NDIS drivers. Not all drivers support all attributes.
 */
#define	NDIS_ATTRIBUTE_IGNORE_PACKET_TIMEOUT		0x00000001
#define	NDIS_ATTRIBUTE_IGNORE_REQUEST_TIMEOUT		0x00000002
#define	NDIS_ATTRIBUTE_IGNORE_TOKEN_RING_ERRORS		0x00000004
#define	NDIS_ATTRIBUTE_BUS_MASTER			0x00000008
#define	NDIS_ATTRIBUTE_INTERMEDIATE_DRIVER		0x00000010
#define	NDIS_ATTRIBUTE_DESERIALIZE			0x00000020
#define	NDIS_ATTRIBUTE_NO_HALT_ON_SUSPEND		0x00000040
#define	NDIS_ATTRIBUTE_SURPRISE_REMOVE_OK		0x00000080
#define	NDIS_ATTRIBUTE_NOT_CO_NDIS			0x00000100
#define	NDIS_ATTRIBUTE_USES_SAFE_BUFFER_APIS		0x00000200

#define	NDIS_SERIALIZED(block)	\
	(((block)->flags & NDIS_ATTRIBUTE_DESERIALIZE) == 0)

/* Ndis Packet Filter Bits (OID_GEN_CURRENT_PACKET_FILTER). */
#define	NDIS_PACKET_TYPE_DIRECTED			0x00000001
#define	NDIS_PACKET_TYPE_MULTICAST			0x00000002
#define	NDIS_PACKET_TYPE_ALL_MULTICAST			0x00000004
#define	NDIS_PACKET_TYPE_BROADCAST			0x00000008
#define	NDIS_PACKET_TYPE_SOURCE_ROUTING			0x00000010
#define	NDIS_PACKET_TYPE_PROMISCUOUS			0x00000020
#define	NDIS_PACKET_TYPE_SMT				0x00000040
#define	NDIS_PACKET_TYPE_ALL_LOCAL			0x00000080
#define	NDIS_PACKET_TYPE_GROUP				0x00001000
#define	NDIS_PACKET_TYPE_ALL_FUNCTIONAL			0x00002000
#define	NDIS_PACKET_TYPE_FUNCTIONAL			0x00004000
#define	NDIS_PACKET_TYPE_MAC_FRAME			0x00008000

/* Ndis MAC option bits (OID_GEN_MAC_OPTIONS). */
#define	NDIS_MAC_OPTION_COPY_LOOKAHEAD_DATA		0x00000001
#define	NDIS_MAC_OPTION_RECEIVE_SERIALIZED		0x00000002
#define	NDIS_MAC_OPTION_TRANSFERS_NOT_PEND		0x00000004
#define	NDIS_MAC_OPTION_NO_LOOPBACK			0x00000008
#define	NDIS_MAC_OPTION_FULL_DUPLEX			0x00000010
#define	NDIS_MAC_OPTION_EOTX_INDICATION			0x00000020
#define	NDIS_MAC_OPTION_8021P_PRIORITY			0x00000040
#define	NDIS_MAC_OPTION_SUPPORTS_MAC_ADDRESS_OVERWRITE	0x00000080
#define	NDIS_MAC_OPTION_RECEIVE_AT_DPC			0x00000100
#define	NDIS_MAC_OPTION_8021Q_VLAN			0x00000200
#define	NDIS_MAC_OPTION_RESERVED			0x80000000

#define	NDIS_DMA_24BITS		0x00
#define	NDIS_DMA_32BITS		0x01
#define	NDIS_DMA_64BITS		0x02

struct ndis_cfg {
	char	*key;
	char	*desc;
	char	*val;
	int	idx;
};

struct ndis_binary_data {
	uint16_t	len;
	void		*buf;
};

struct ndis_configuration_parameter {
	enum ndis_parameter_type	type;
	union {
		uint32_t		integer;
		struct unicode_string	string;
		struct ndis_binary_data	binary;
	} data;
};

struct ndis_parmlist_entry {
	struct list_entry			list;
	struct ndis_configuration_parameter	parm;
};

struct ndis_bind_paths {
	uint32_t		number;
	struct unicode_string	paths[1];
};

struct ndis_event {
	struct nt_kevent	kevent;
};

struct ndis_timer {
	struct nt_ktimer	ktimer;
	struct nt_kdpc		kdpc;
};

struct ndis_miniport_timer {
	struct nt_ktimer		ktimer;
	struct nt_kdpc			kdpc;
	ndis_timer_function		func;
	void				*ctx;
	struct ndis_miniport_block	*block;
	struct ndis_miniport_timer	*nexttimer;
};

struct ndis_spin_lock {
	unsigned long		spinlock;
	uint8_t			kirql;
};

struct ndis_rw_lock {
	union {
		unsigned long	spinlock;
		void		*ctx;
	} u;
	uint8_t		reserved[16];
};

struct ndis_lock_state {
	uint16_t	lockstate;
	uint8_t		oldirql;
};

struct ndis_request {
	uint8_t		macreserved[4 * sizeof(void *)];
	uint32_t	requesttype;
	union _ndis_data {
		struct _ndis_query_information {
			uint32_t	oid;
			void		*infobuf;
			uint32_t	infobuflen;
			uint32_t	written;
			uint32_t	needed;
		} ndis_query_information;
		struct _ndis_set_information {
			uint32_t	oid;
			void		*infobuf;
			uint32_t	infobuflen;
			uint32_t	written;
			uint32_t	needed;
		} ndis_set_information;
	} ndis_data;
	/* NDIS 5.0 extentions */
	uint8_t		ndis_rsvd[9 * sizeof(void *)];
	union {
		uint8_t		callmgr_rsvd[2 * sizeof(void *)];
		uint8_t		protocol_rsvd[2 * sizeof(void *)];
	} u;
	uint8_t		miniport_rsvd[2 * sizeof(void *)];
};

typedef void (*ndis_isr_func)(uint8_t *, uint8_t *, void *);
typedef void (*ndis_interrupt_func)(void *);

struct ndis_miniport_interrupt {
	struct nt_kinterrupt		*interrupt_object;
	unsigned long			dpc_count_lock;
	void				*rsvd;
	ndis_isr_func			isr_func;
	ndis_interrupt_func		dpc_func;
	struct nt_kdpc			interrupt_dpc;
	struct ndis_miniport_block	*block;
	uint8_t				dpc_count;
	uint8_t				filler1;
	struct nt_kevent		dpc_completed_event;
	uint8_t				shared_interrupt;
	uint8_t				isr_requested;
};

struct ndis_work_item;
typedef void (*ndis_proc)(struct ndis_work_item *, void *);

struct ndis_work_item {
	void			*ctx;
	ndis_proc		func;
	struct list_entry	list;
};

struct ndis_sc_element {
	uint64_t	addr;
	uint32_t	len;
	uint32_t	*reserved;
};

#define	NDIS_MAXSEG 32

struct ndis_sc_list {
	uint32_t		frags;
	uint32_t		*reserved;
	struct ndis_sc_element	elements[NDIS_MAXSEG];
};

struct ndis_tcpip_csum {
	union {
		uint32_t	txflags;
		uint32_t	rxflags;
		uint32_t	value;
	} u;
};

#define	NDIS_TXCSUM_DO_IPV4		0x00000001
#define	NDIS_TXCSUM_DO_IPV6		0x00000002
#define	NDIS_TXCSUM_DO_TCP		0x00000004
#define	NDIS_TXCSUM_DO_UDP		0x00000008
#define	NDIS_TXCSUM_DO_IP		0x00000010

#define	NDIS_RXCSUM_TCP_FAILED		0x00000001
#define	NDIS_RXCSUM_UDP_FAILED		0x00000002
#define	NDIS_RXCSUM_IP_FAILED		0x00000004
#define	NDIS_RXCSUM_TCP_PASSED		0x00000008
#define	NDIS_RXCSUM_UDP_PASSED		0x00000010
#define	NDIS_RXCSUM_IP_PASSED		0x00000020
#define	NDIS_RXCSUM_LOOPBACK		0x00000040

struct ndis_vlan {
	union {
		struct {
			uint32_t	userprio:3;
			uint32_t	canformatid:1;
			uint32_t	vlanid:12;
			uint32_t	rsvd:16;
		} taghdr;
	} u;
};

struct ndis_packet_extension {
	void	*info[MAX_PER_PACKET_INFO];
};

struct ndis_packet_private {
	uint32_t	physcnt;
	uint32_t	totlen;
	struct mdl	*head;
	struct mdl	*tail;
	void		*pool;
	uint32_t	count;
	uint32_t	flags;
	uint8_t		validcounts;
	uint8_t		ndispktflags;
	uint16_t	packetooboffset;
};

#define	NDIS_FLAGS_PROTOCOL_ID_MASK		0x0000000F
#define	NDIS_FLAGS_MULTICAST_PACKET		0x00000010
#define	NDIS_FLAGS_RESERVED2			0x00000020
#define	NDIS_FLAGS_RESERVED3			0x00000040
#define	NDIS_FLAGS_DONT_LOOPBACK		0x00000080
#define	NDIS_FLAGS_IS_LOOPBACK_PACKET		0x00000100
#define	NDIS_FLAGS_LOOPBACK_ONLY		0x00000200
#define	NDIS_FLAGS_RESERVED4			0x00000400
#define	NDIS_FLAGS_DOUBLE_BUFFERED		0x00000800
#define	NDIS_FLAGS_SENT_AT_DPC			0x00001000
#define	NDIS_FLAGS_USES_SG_BUFFER_LIST		0x00002000

#define	NDIS_PACKET_WRAPPER_RESERVED			0x3F
#define	NDIS_PACKET_CONTAINS_MEDIA_SPECIFIC_INFO	0x40
#define	NDIS_PACKET_ALLOCATED_BY_NDIS			0x80

#define	NDIS_PROTOCOL_ID_DEFAULT	0x00
#define	NDIS_PROTOCOL_ID_TCP_IP		0x02
#define	NDIS_PROTOCOL_ID_IPX		0x06
#define	NDIS_PROTOCOL_ID_NBF		0x07
#define	NDIS_PROTOCOL_ID_MAX		0x0F
#define	NDIS_PROTOCOL_ID_MASK		0x0F

struct ndis_mediaspecific_info {
	uint32_t		nextentoffset;
	enum ndis_classid	classid;
	uint32_t		size;
	uint8_t			classinfo[1];
};

struct ndis_packet_oob {
	union {
		uint64_t	timetotx;
		uint64_t	timetxed;
	} u;
	uint64_t	timerxed;
	uint32_t	hdrlen;
	uint32_t	mediaspecific_len;
	void		*mediaspecific;
	int32_t		status;
};

/*
 * Our protocol private region for handling ethernet.
 * We need this to stash some of the things returned
 * by NdisMEthIndicateReceive().
 */
struct ndis_ethpriv {
	void	*ctx;	/* packet context */
	long	offset;	/* residual data to transfer */
	void	*pad[2];
};

#define	PROTOCOL_RESERVED_SIZE_IN_PACKET	(4 * sizeof(void *))

struct ndis_packet {
	struct ndis_packet_private	private;
	union {
		/* For connectionless miniports. */
		struct {
			uint8_t	miniport_reserved[2 * sizeof(void *)];
			uint8_t	wrapper_reserved[2 * sizeof(void *)];
		} cl_reserved;
		/* For de-serialized miniports */
		struct {
			uint8_t	miniport_reserved_ex[3 * sizeof(void *)];
			uint8_t	wrapper_reserved_ex[sizeof(void *)];
		} deserialized_reserved;
		struct {
			uint8_t	mac_reserved[4 * sizeof(void *)];
		} mac_reserved;
	} u;
	unsigned long	reserved[2];
	uint8_t		protocol_reserved[PROTOCOL_RESERVED_SIZE_IN_PACKET];

	/*
	 * This next part is probably wrong, but we need some place
	 * to put the out of band data structure...
	 */
	struct ndis_packet_oob		oob;
	struct ndis_packet_extension	ext;
	struct ndis_sc_list		sclist;

	/* BSD-specific stuff which should be invisible to drivers. */
	uint32_t		refcnt;
	void			*softc;
	void			*m0;
	int			txidx;
	struct list_entry	list;
};

struct ndis_packet_pool {
	union slist_header	head;
	struct nt_kevent	event;
	unsigned long		lock;
	uint32_t		cnt;
	uint32_t		len;
	void			*pktmem;
};

struct ndis_filter_dbs {
	void	*ethdb;
	void	*trdb;
	void	*fddidb;
	void	*arcdb;
};

struct ndis_paddr_unit {
	uint64_t	physaddr;
	uint32_t	len;
};

struct ndis_map_arg {
	struct ndis_paddr_unit	*fraglist;
	int			cnt;
	int			max;
};

typedef uint8_t (*ndis_check_hang_func)(void *);
typedef void (*ndis_disable_interrupts_func)(void *);
typedef void (*ndis_enable_interrupts_func)(void *);
typedef void (*ndis_halt_func)(void *);
typedef int32_t (*ndis_init_func)(int32_t *, uint32_t *, enum ndis_medium *,
    uint32_t, void *, void *);
typedef int32_t (*ndis_query_info_func)(void *, uint32_t, void *, uint32_t,
    uint32_t *, uint32_t *);
typedef int32_t (*ndis_reset_func)(uint8_t *, void *);
typedef int32_t (*ndis_send_func)(void *, struct ndis_packet *, uint32_t);
typedef int32_t (*ndis_set_info_func)(void *, uint32_t, void *,
    uint32_t, uint32_t *, uint32_t *);
typedef int32_t (*ndis_transfer_data_func)(void *, uint32_t *, void *, void *,
    uint32_t, uint32_t);
typedef void (*ndis_return_packet_func)(void *, struct ndis_packet *);
typedef void (*ndis_send_packets_func)(void *, struct ndis_packet **,
    uint32_t);
typedef void (*ndis_allocate_complete_func)(void *, void *, uint64_t *,
    uint32_t, void *);
typedef void (*ndis_pnp_event_notify_func)(void *, int, void *, uint32_t);
typedef void (*ndis_shutdown_func)(void *);
/*
 * Miniport characteristics were originally defined in the NDIS 3.0
 * spec and then extended twice, in NDIS 4.0 and 5.0.
 */
struct ndis_miniport_characteristics {
	/* NDIS 3.0 */
	uint8_t					version_major;
	uint8_t					version_minor;
	uint16_t				pad;
	uint32_t				rsvd;
	ndis_check_hang_func			check_hang_func;
	ndis_disable_interrupts_func		disable_interrupts_func;
	ndis_enable_interrupts_func		enable_interrupts_func;
	ndis_halt_func				halt_func;
	ndis_interrupt_func			interrupt_func;
	ndis_init_func				init_func;
	ndis_isr_func				isr_func;
	ndis_query_info_func			query_info_func;
	void *					reconfig_func;
	ndis_reset_func				reset_func;
	ndis_send_func				send_func;
	ndis_set_info_func			set_info_func;
	ndis_transfer_data_func			transfer_data_func;

	/* NDIS 4.0 extentions */
	ndis_return_packet_func			return_packet_func;
	ndis_send_packets_func			send_packets_func;
	ndis_allocate_complete_func		allocate_complete_func;

	/* NDIS 5.0 extensions */
	void *					co_create_vc_func;
	void *					co_delete_vc_func;
	void *					co_activate_vc_func;
	void *					co_deactivate_vc_func;
	void *					co_send_packets_func;
	void *					co_request_func;

	/* NDIS 5.1 extentions */
	void *					cancel_send_packets_func;
	ndis_pnp_event_notify_func		pnp_event_notify_func;
	ndis_shutdown_func			shutdown_func;
	void *					reserved0;
	void *					reserved1;
	void *					reserved2;
	void *					reserved3;
};

/* NDIS 6.20 */
struct ndis_miniport_driver_characteristics {
	struct ndis_object_header	header;
	uint8_t				major_ndis_version;
	uint8_t				minor_ndis_version;
	uint8_t				major_driver_version;
	uint8_t				minor_driver_version;
	uint32_t			flags;
	void *				set_options_func;
	void *				initialize_func;
	void *				halt_func;
	void *				unload_func;
	void *				pause_func;
	void *				restart_func;
	void *				oid_request_func;
	void *				send_net_buffer_list_func;
	void *				return_net_buffer_list_func;
	void *				cancel_send_func;
	void *				check_for_hang_func;
	void *				reset_func;
	void *				device_pnp_event_notify_func;
	void *				shutdown_func;
	void *				cancel_oid_request_func;
	void *				direct_oid_request_func;
	void *				cancel_direct_oid_request_func;
};

struct ndis_reference {
	unsigned long	spinlock;
	uint16_t	refcnt;
	uint8_t		closing;
};

struct ndis_timer_entry {
	struct callout			ch;
	struct ndis_miniport_timer	*timer;
	TAILQ_ENTRY(ndis_timer_entry)	link;
};

TAILQ_HEAD(nte_head, ndis_timer_entry);

#define	NDIS_FILE_HANDLE_TYPE_VFS 0
#define	NDIS_FILE_HANDLE_TYPE_MODULE 1

struct ndis_file_handle {
	uint8_t		type;
	char		*name;
	void		*vp;
	void		*map;
	uint32_t	maplen;
};

typedef void (*ndis_send_done_func)(void *, struct ndis_packet *, int32_t);
typedef void (*ndis_status_func)(void *, int32_t, void *, uint32_t);
typedef void (*ndis_status_done_func)(void *);

/*
 * The miniport block is basically the internal NDIS handle. We need
 * to define this because, unfortunately, it is not entirely opaque
 * to NDIS drivers. For one thing, it contains the function pointer
 * to the NDIS packet receive handler, which is invoked out of the
 * NDIS block via a macro rather than a function pointer. (The
 * NdisMIndicateReceivePacket() routine is a macro rather than
 * a function.) For another, the driver maintains a pointer to the
 * miniport block and passes it as a handle to various NDIS functions.
 *
 * The miniport block has two parts: the first part contains fields
 * that must never change, since they are referenced by driver
 * binaries through macros. The second part is ignored by the driver,
 * but contains various things used internaly by NDIS.SYS. In our
 * case, we define the first 'immutable' part exactly as it appears
 * in Windows, but don't bother duplicating the Windows definitions
 * for the second part. Instead, we replace them with a few BSD-specific
 * things.
 */
struct ndis_miniport_block {
	/*
	 * Windows-specific portion -- DO NOT MODIFY OR NDIS
	 * DRIVERS WILL NOT WORK.
	 */
	void				*signature;	/* magic number */
	struct ndis_miniport_block	*next_miniport;
	struct ndis_mdriver_block	*driver_handle;
	void				*miniport_adapter_ctx;
	struct unicode_string		miniport_name;
	struct ndis_bind_paths		*bind_paths;
	void				*open_queue;
	struct ndis_reference		short_ref;
	void				*device_ctx;
	uint8_t				padding;
	uint8_t				lock_acquired;
	uint8_t				pmode_opens;
	uint8_t				assigned_processor;
	unsigned long			lock;
	struct ndis_request		*media_request;
	struct ndis_miniport_interrupt	*interrupt;
	uint32_t			flags;
	uint32_t			pnp_flags;
	struct list_entry		packet_list;
	struct ndis_packet		*first_pending_tx_packet;
	struct ndis_packet		*return_packet_queue;
	uint32_t			request_buffer;
	void				*set_mcast_buffer;
	struct ndis_miniport_block	*primary_miniport;
	void				*wrapper_ctx;
	void				*bus_data_ctx;
	uint32_t			pnp_caps;
	struct cm_resource_list		*resources;
	struct ndis_timer		wakekup_dpc_timer;
	struct unicode_string		base_name;
	struct unicode_string		symbolic_link_name;
	uint32_t			check_for_hang_secs;
	uint16_t			check_for_hang_ticks;
	uint16_t			check_for_hang_current_tick;
	int32_t				reset_status;
	void				*reset_open;
	struct ndis_filter_dbs		filter_dbs;
	void				*packet_indicate_func;
	ndis_send_done_func		send_done_func;
	void				*send_rsrc_func;
	void				*reset_done_func;
	enum ndis_medium		media_type;
	uint32_t			bus_number;
	enum ndis_bus_type		bus_type;
	uint32_t			adapter_type;
	struct device_object		*deviceobj; /* Functional device */
	struct device_object		*physdeviceobj; /* Physical device */
	struct device_object		*nextdeviceobj; /* Next dev in stack */
	void				*map_registers;
	void				*callmgraflist;
	void				*miniport_thread;
	void				*set_info_buf;
	uint16_t			set_info_buf_len;
	uint16_t			max_send_packets;
	int32_t				fake_status;
	void				*lock_handler;
	struct unicode_string		*adapter_instance_name;
	void				*timer_queue;
	uint32_t			mac_options;
	struct ndis_request		*pending_request;
	uint32_t			maximum_long_address;
	uint32_t			maximum_short_address;
	uint32_t			current_lookahead;
	uint32_t			maximum_lookahead;
	void				*interrupt_func;
	void				*disable_interrupt_func;
	void				*enable_interrupt_func;
	void				*send_pkts_func;
	void				*deferred_send_func;
	void				*ethrx_indicate_func;
	void				*txrx_indicate_func;
	void				*fddirx_indicate_func;
	void				*ethrx_done_func;
	void				*txrx_done_func;
	void				*fddirxcond_func;
	ndis_status_func		status_func;
	ndis_status_done_func		status_done_func;
	void				*tdcond_func;
	void				*query_done_func;
	void				*set_done_func;
	void				*wantx_done_func;
	void				*wanrx_func;
	void				*wanrx_done_func;

	/*
	 * End of windows-specific portion of miniport block.
	 * Everything below is BSD-specific.
	 */
	struct list_entry		parmlist;
	struct cm_partial_resource_list	*rlist;
	int32_t				getstat;
	struct nt_kevent		getevent;
	int32_t				setstat;
	struct nt_kevent		setevent;
	int32_t				resetstat;
	struct nt_kevent		resetevent;
	struct io_workitem		*returnitem;
	struct ndis_packet_pool		*rxpool;
	struct list_entry		returnlist;
	unsigned long			returnlock;
	TAILQ_ENTRY(ndis_miniport_block)	link;
};
TAILQ_HEAD(nd_head, ndis_miniport_block);

struct ndis_pci_type {
	uint16_t	vendor;
	uint16_t	device;
	uint32_t	subsys;
	char		*name;
};

struct ndis_pccard_type {
	const char	*vendor;
	const char	*device;
	char		*name;
};

struct ndis_usb_type {
	uint16_t	vendor;
	uint16_t	device;
	char		*name;
};

typedef int32_t (*driver_entry)(struct driver_object *, struct unicode_string *);
extern struct image_patch_table ndis_functbl[];

void	ndis_libinit(void);
void	ndis_libfini(void);
int32_t	ndis_load_driver(struct driver_object *, struct device_object *);
void	ndis_unload_driver(struct ndis_softc *);
int	ndis_mtop(struct mbuf *, struct ndis_packet **);
int	ndis_ptom(struct mbuf **, struct ndis_packet *);
int	ndis_get(struct ndis_softc *, uint32_t, void *, uint32_t);
int	ndis_get_int(struct ndis_softc *, uint32_t, uint32_t *);
int	ndis_get_info(struct ndis_softc *, uint32_t, void *, uint32_t,
	    uint32_t *, uint32_t *);
void	*ndis_get_routine_address(struct image_patch_table *, char *);
int	ndis_set(struct ndis_softc *, uint32_t, void *, uint32_t);
int	ndis_set_int(struct ndis_softc *, uint32_t, uint32_t);
int	ndis_set_info(struct ndis_softc *, uint32_t, void *, uint32_t,
	    uint32_t *, uint32_t *);
void	ndis_send_packets(struct ndis_softc *, struct ndis_packet **, uint32_t);
int32_t	ndis_send_packet(struct ndis_softc *, struct ndis_packet *);
int	ndis_convert_res(struct ndis_softc *);
void	ndis_free_packet(struct ndis_packet *);
int32_t	ndis_reset_nic(struct ndis_softc *);
void	ndis_disable_interrupts_nic(struct ndis_softc *);
void	ndis_enable_interrupts_nic(struct ndis_softc *);
void	ndis_halt_nic(struct ndis_softc *);
void	ndis_shutdown_nic(struct ndis_softc *);
void	ndis_pnp_event_nic(struct ndis_softc *, uint32_t, uint32_t);
uint8_t	ndis_check_for_hang_nic(struct ndis_softc *);
int32_t	ndis_init_nic(struct ndis_softc *);
void	ndis_return_packet(void *, void *);
int	ndis_init_dma(struct ndis_softc *);
void	ndis_destroy_dma(struct ndis_softc *);
int	ndis_add_sysctl(struct ndis_softc *, char *, char *, char *, int);
void	NdisAllocatePacketPool(int32_t *, struct ndis_packet_pool **,
	    uint32_t, uint32_t);
void	NdisAllocatePacketPoolEx(int32_t *, struct ndis_packet_pool **,
	    uint32_t, uint32_t, uint32_t);
void	NdisFreePacketPool(struct ndis_packet_pool *);
void	NdisAllocatePacket(int32_t *, struct ndis_packet **,
	    struct ndis_packet_pool *);
void	NdisFreePacket(struct ndis_packet *);

#endif /* _NDIS_VAR_H_ */
