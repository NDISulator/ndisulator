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

/* Forward declarations */
struct ndis_miniport_block;
struct ndis_mdriver_block;

/* Base types */
typedef int32_t ndis_status;
typedef void *ndis_handle;
typedef uint32_t ndis_oid;
typedef uint32_t ndis_error_code;
typedef register_t ndis_kspin_lock;
typedef uint8_t ndis_kirql;

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
#define	NDIS_STATUS_INSUFFICIENT_RESOURCES		0xC000009A
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

enum ndis_hardware_status {
	NDIS_HARDWARE_STATUS_READY,
	NDIS_HARDWARE_STATUS_INITIALIZING,
	NDIS_HARDWARE_STATUS_RESET,
	NDIS_HARDWARE_STATUS_CLOSING,
	NDIS_HARDWARE_STATUS_NOT_READY
};

enum ndis_device_power_state {
	NDIS_DEVICE_STATE_UNSPEC,
	NDIS_DEVICE_STATE_D0,
	NDIS_DEVICE_STATE_D1,
	NDIS_DEVICE_STATE_D2,
	NDIS_DEVICE_STATE_D3
};

enum ndis_power_profile {
	NDIS_POWER_PROFILE_BATTERY,
	NDIS_POWER_PROFILE_ACONLINE
};

enum ndis_device_pnp_event {
	NDIS_DEVICE_PNP_EVENT_QUERY_REMOVED,
	NDIS_DEVICE_PNP_EVENT_REMOVED,
	NDIS_DEVICE_PNP_EVENT_SURPRISE_REMOVED,
	NDIS_DEVICE_PNP_EVENT_QUERY_STOPPED,
	NDIS_DEVICE_PNP_EVENT_STOPPED,
	NDIS_DEVICE_PNP_EVENT_POWER_PROFILE_CHANGED
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

enum ndis_80211_network_type {
	NDIS_802_11_11FH,
	NDIS_802_11_11DS,
	NDIS_802_11_11OFDM5,
	NDIS_802_11_11OFDM24,
	NDIS_802_11_AUTO
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

enum ndis_80211_power_mode {
	NDIS_802_11_POWER_MODE_CAM,
	NDIS_802_11_POWER_MODE_MAX_PSP,
	NDIS_802_11_POWER_MODE_FAST_PSP
};

typedef uint32_t ndis_80211_power;	/* Power in milliwatts */
typedef int32_t ndis_80211_rssi;	/* Signal strength in dBm */

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

enum ndis_80211_network_infrastructure {
	NDIS_802_11_IBSS,
	NDIS_802_11_INFRASTRUCTURE,
	NDIS_802_11_AUTO_UNKNOWN
};

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

typedef uint8_t ndis_80211_rates[8];
typedef uint8_t ndis_80211_rates_ex[16];
typedef uint8_t ndis_80211_macaddr[6];

struct ndis_80211_ssid {
	uint32_t	len;
	uint8_t		ssid[32];
};

struct ndis_wlan_bssid {
	uint32_t			len;
	ndis_80211_macaddr		macaddr;
	uint8_t				reserved[2];
	struct ndis_80211_ssid		ssid;
	uint32_t			privacy;
	ndis_80211_rssi			rssi;
	uint32_t			nettype;
	struct ndis_80211_config	config;
	uint32_t			netinfra;
	ndis_80211_rates		supportedrates;
};

struct ndis_80211_bssid_list {
	uint32_t			items;
	struct ndis_wlan_bssid		bssid[1];
};

struct ndis_wlan_bssid_ex {
	uint32_t			len;
	ndis_80211_macaddr		macaddr;
	uint8_t				reserved[2];
	struct ndis_80211_ssid		ssid;
	uint32_t			privacy;
	ndis_80211_rssi			rssi;
	uint32_t			nettype;
	struct ndis_80211_config	config;
	uint32_t			netinfra;
	ndis_80211_rates_ex		supportedrates;
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

typedef uint32_t ndis_80211_fragthresh;
typedef uint32_t ndis_80211_rtsthresh;
typedef uint32_t ndis_80211_antenna;

enum ndis_80211_privacy_filter {
	NDIS_802_11_PRIVFILT_ACCEPTALL,
	NDIS_802_11_PRIVFILT_8021XWEP
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

#define	NDIS_802_11_RELOADDEFAULT_WEP		0x00000000

enum ndis_80211_status_type {
	NDIS_802_11_STATUS_TYPE_AUTHENTICATION,
	NDIS_802_11_STATUS_TYPE_MEDIA_STREAM_MODE,
	NDIS_802_11_STATUS_TYPE_PMKID_CANDIDATE_LIST,
	NDIS_802_11_STATUS_TYPE_RADIO_STATE
};

struct ndis_80211_status_indication {
	uint32_t	type;
};

enum ndis_80211_radio_status {
	NDIS_802_11_RADIO_STATUS_ON,
	NDIS_802_11_RADIO_STATUS_HARDWARE_OFF,
	NDIS_802_11_RADIO_STATUS_SOFTWARE_OFF
};

#define	NDIS_802_11_AUTH_REQUEST_REAUTH			0x01
#define	NDIS_802_11_AUTH_REQUEST_KEYUPDATE		0x02
#define	NDIS_802_11_AUTH_REQUEST_PAIRWISE_ERROR		0x06
#define	NDIS_802_11_AUTH_REQUEST_GROUP_ERROR		0x0E

struct ndis_80211_auth_request {
	uint32_t		len;
	ndis_80211_macaddr	bssid;
	uint32_t		flags;
};

struct ndis_80211_key {
	uint32_t		len;
	uint32_t		keyidx;
	uint32_t		keylen;
	ndis_80211_macaddr	bssid;
	uint8_t			pad[6];
	uint64_t		keyrsc;
	uint8_t			keydata[32];
};

struct ndis_80211_remove_key {
	uint32_t		len;
	uint32_t		keyidx;
	ndis_80211_macaddr	bssid;
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
	ndis_80211_macaddr	currentapaddr;
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
	ndis_80211_macaddr	bssid;
	uint8_t			pmkid[16];
};

struct ndis_80211_pmkid {
	uint32_t			len;
	uint32_t			bssidcnt;
	struct ndis_80211_bssidinfo	bssidinfo[1];
};

struct ndis_80211_pmkid_cand {
	ndis_80211_macaddr	bssid;
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

struct ndis_encap_fmt {
	uint32_t	encap;
	uint32_t	flags;
	uint32_t	encaphdrlen;
};

struct ndis_pm_wake_up_capabilities {
	enum ndis_device_power_state	min_magic_packet_wake_up;
	enum ndis_device_power_state	min_pattern_wake_up;
	enum ndis_device_power_state	min_link_change_wake_up;
};

struct ndis_pnp_capabilities {
	uint32_t				flags;
	struct ndis_pm_wake_up_capabilities	wake_up_capabilities;
};

struct ndis_task_offload_hdr {
	uint32_t		vers;
	uint32_t		len;
	uint32_t		reserved;
	uint32_t		offset_firsttask;
	struct ndis_encap_fmt	encapfmt;
};

struct ndis_task_offload {
	uint32_t	vers;
	uint32_t	len;
	uint32_t	task;
	uint32_t	offset_nexttask;
	uint32_t	taskbuflen;
	uint8_t		taskbuf[1];
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

enum ndis_media_state {
	NDIS_MEDIA_STATE_CONNECTED,
	NDIS_MEDIA_STATE_DISCONNECTED
};

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

enum ndis_parameter_type {
	NDIS_PARAMETER_INTEGER,
	NDIS_PARAMETER_HEX_INTEGER,
	NDIS_PARAMETER_STRING,
	NDIS_PARAMETER_MULTI_STRING,
	NDIS_PARAMETER_BINARY
};

struct ndis_binary_data {
	uint16_t	len;
	void		*buf;
};

/*
 * Not part of Windows NDIS spec; we uses this to keep a
 * list of ndis_config_parm structures that we've allocated.
 */
struct ndis_config_parm {
	enum ndis_parameter_type	type;
	union {
		uint32_t		intdata;
		unicode_string		stringdata;
		struct ndis_binary_data	binarydata;
	} parmdata;
};

struct ndis_parmlist_entry {
	list_entry		list;
	struct ndis_config_parm	parm;
};

struct ndis_bind_paths {
	uint32_t	number;
	unicode_string	paths[1];
};

#define	dispatch_header nt_dispatch_header

struct ndis_ktimer {
	struct dispatch_header	nk_header;
	uint64_t		nk_duetime;
	list_entry		nk_timerlistentry;
	void			*nk_dpc;
	uint32_t		nk_period;
};

struct ndis_kevent {
	struct dispatch_header	nk_header;
};

struct ndis_event {
	struct nt_kevent	ne_event;
};

/* Kernel defered procedure call (i.e. timer callback) */
struct ndis_kdpc;
typedef void (*ndis_kdpc_func)(struct ndis_kdpc *, void *, void *, void *);

struct ndis_kdpc {
	uint16_t	nk_type;
	uint8_t		nk_num;
	uint8_t		nk_importance;
	list_entry	nk_dpclistentry;
	ndis_kdpc_func	nk_deferedfunc;
	void		*nk_deferredctx;
	void		*nk_sysarg1;
	void		*nk_sysarg2;
	uint32_t	*nk_lock;
};

struct ndis_timer {
	struct ktimer	nt_ktimer;
	struct kdpc	nt_kdpc;
};

typedef void (*ndis_timer_function)(void *, void *, void *, void *);

struct ndis_miniport_timer {
	struct ktimer			nmt_ktimer;
	struct kdpc			nmt_kdpc;
	ndis_timer_function		nmt_timerfunc;
	void				*nmt_timerctx;
	struct ndis_miniport_block	*nmt_block;
	struct ndis_miniport_timer	*nmt_nexttimer;
};

struct ndis_spin_lock {
	ndis_kspin_lock		nsl_spinlock;
	ndis_kirql		nsl_kirql;
};

struct ndis_rw_lock {
	union {
		kspin_lock	spinlock;
		void		*ctx;
	} u;
	uint8_t		reserved[16];
};

struct ndis_lock_state {
	uint16_t	lockstate;
	ndis_kirql	oldirql;
};

struct ndis_request {
	uint8_t		macreserved[4 * sizeof(void *)];
	uint32_t	requesttype;
	union _ndis_data {
		struct _ndis_query_information {
			ndis_oid	oid;
			void		*infobuf;
			uint32_t	infobuflen;
			uint32_t	written;
			uint32_t	needed;
		} ndis_query_information;
		struct _ndis_set_information {
			ndis_oid	oid;
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

struct ndis_miniport_interrupt {
	kinterrupt			*interrupt_object;
	ndis_kspin_lock			dpc_count_lock;
	void				*rsvd;
	void				*isr_func;
	void				*dpc_func;
	kdpc				interrupt_dpc;
	struct ndis_miniport_block	*block;
	uint8_t				dpc_count;
	uint8_t				filler1;
	struct nt_kevent		dpcs_completed_event;
	uint8_t				shared_interrupt;
	uint8_t				isr_requested;
};

enum ndis_interrupt_mode {
	NIM_LEVEL,
	NIM_LATCHED
};

#define	NUMBER_OF_SINGLE_WORK_ITEMS 6

struct ndis_work_item;

typedef void (*ndis_proc)(struct ndis_work_item *, void *);

struct ndis_work_item {
	void		*nwi_ctx;
	ndis_proc	nwi_func;
	uint8_t		nwi_wraprsvd[sizeof(void *) * 8];
};

#define	NdisInitializeWorkItem(w, f, c)	\
	do {				\
		(w)->nwi_ctx = c;	\
		(w)->nwi_func = f;	\
	} while (0)

struct ndis_sc_element {
	struct physaddr	addr;
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

enum ndis_perpkt_info {
	NDIS_TCPIPCSUM_INFO,
	NDIS_IPSEC_INFO,
	NDIS_LARGESEND_INFO,
	NDIS_CLASSHANDLE_INFO,
	NDIS_RSVD,
	NDIS_SCLIST_INFO,
	NDIS_IEEE8021Q_INFO,
	NDIS_ORIGINALPKT_INFO,
	NDIS_PACKETCANCELID,
	NDIS_MAXPKT_INFO
};

struct ndis_packet_extension {
	void	*info[NDIS_MAXPKT_INFO];
};

struct ndis_packet_private {
	uint32_t	physcnt;
	uint32_t	totlen;
	ndis_buffer	*head;
	ndis_buffer	*tail;
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

enum ndis_classid {
	ndis_class_802_3prio,
	ndis_class_wirelesswan_mbx,
	ndis_class_irda_packetinfo,
	ndis_class_atm_aainfo
};

struct ndis_mediaspecific_info {
	uint32_t		nextentoffset;
	enum ndis_classid	classid;
	uint32_t		size;
	uint8_t			classinfo[1];
};

struct ndis_packet_oob {
	union {
		uint64_t	npo_timetotx;
		uint64_t	npo_timetxed;
	} u;
	uint64_t	npo_timerxed;
	uint32_t	npo_hdrlen;
	uint32_t	npo_mediaspecific_len;
	void		*npo_mediaspecific;
	ndis_status	npo_status;
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
			uint8_t		miniport_rsvd[2 * sizeof(void *)];
			uint8_t		wrapper_rsvd[2 * sizeof(void *)];
		} clrsvd;
		/* For de-serialized miniports */
		struct {
			uint8_t		miniport_rsvdex[3 * sizeof(void *)];
			uint8_t		wrapper_rsvdex[sizeof(void *)];
		} dsrsvd;
		struct {
			uint8_t		mac_rsvd[4 * sizeof(void *)];
		} macrsvd;
	} u;
	uint32_t	*rsvd[2];
	uint8_t		protocolreserved[PROTOCOL_RESERVED_SIZE_IN_PACKET];

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
	list_entry		list;
};

struct ndis_packet_pool {
	slist_header	head;
#ifdef NDIS_DEBUG_PACKETS
	uint32_t	dead;
#endif
	nt_kevent	event;
	kspin_lock	lock;
	uint32_t	cnt;
	uint32_t	len;
	void		*pktmem;
};

/* mbuf ext type for NDIS */
#define	EXT_NDIS EXT_NET_DRV

struct ndis_filter_dbs {
	union {
		void	*ethdb;
		void	*nulldb;
	} u;
	void	*trdb;
	void	*fddidb;
	void	*arcdb;
};

#define	ethdb u.ethdb

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

struct ndis_paddr_unit {
	struct physaddr	physaddr;
	uint32_t	len;
};

struct ndis_map_arg {
	struct ndis_paddr_unit	*fraglist;
	int			cnt;
	int			max;
};

/*
 * Miniport characteristics were originally defined in the NDIS 3.0
 * spec and then extended twice, in NDIS 4.0 and 5.0.
 */
struct ndis_miniport_driver_characteristics {
	/* NDIS 3.0 */
	uint8_t		version_major;
	uint8_t		version_minor;
	uint16_t	pad;
	uint32_t	rsvd;
	void *		check_hang_func;
	void *		disable_interrupts_func;
	void *		enable_interrupts_func;
	void *		halt_func;
	void *		interrupt_func;
	void *		init_func;
	void *		isr_func;
	void *		query_info_func;
	void *		reconfig_func;
	void *		reset_func;
	void *		send_func;
	void *		set_info_func;
	void *		transfer_data_func;

	/* NDIS 4.0 extentions */
	void *		return_packet_func;
	void *		send_packets_func;
	void *		allocate_complete_func;

	/* NDIS 5.0 extensions */
	void *		co_create_vc_func;
	void *		co_delete_vc_func;
	void *		co_activate_vc_func;
	void *		co_deactivate_vc_func;
	void *		co_send_packets_func;
	void *		co_request_func;

	/* NDIS 5.1 extentions */
	void *		cancel_send_packets_func;
	void *		pnp_event_notify_func;
	void *		shutdown_func;
	void *		reserved0;
	void *		reserved1;
	void *		reserved2;
	void *		reserved3;
};

struct ndis_reference {
	ndis_kspin_lock	spinlock;
	uint16_t	refcnt;
	uint8_t		closing;
};

struct ndis_timer_entry {
	struct callout			ch;
	struct ndis_miniport_timer	*timer;
	TAILQ_ENTRY(ndis_timer_entry)	link;
};

TAILQ_HEAD(nte_head, ndis_timer_entry);

#define	NDIS_FH_TYPE_VFS 0
#define	NDIS_FH_TYPE_MODULE 1

struct ndis_fh {
	int		type;
	char		*name;
	void		*vp;
	void		*map;
	uint32_t	maplen;
};

/*
 * The miniport block is basically the internal NDIS handle. We need
 * to define this because, unfortunately, it is not entirely opaque
 * to NDIS drivers. For one thing, it contains the function pointer
 * to the NDIS packet receive handler, which is invoked out of the
 * NDIS block via a macro rather than a function pointer. (The
 * NdisMIndicateReceivePacket() routine is a macro rather than
 * a function.) For another, the driver maintains a pointer to the
 * miniport block and passes it as a handle to various NDIS functions.
 * (The driver never really knows this because it's hidden behind
 * an ndis_handle though.)
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
	ndis_handle			miniport_adapter_ctx;
	unicode_string			name;
	struct ndis_bind_paths		*bindpaths;
	ndis_handle			openqueue;
	struct ndis_reference		ref;
	ndis_handle			device_ctx;
	uint8_t				padding;
	uint8_t				lock_acquired;
	uint8_t				pmode_opens;
	uint8_t				assigned_cpu;
	ndis_kspin_lock			lock;
	struct ndis_request		*media_request;
	struct ndis_miniport_interrupt	*interrupt;
	uint32_t			flags;
	uint32_t			pnp_flags;
	list_entry			packet_list;
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
	unicode_string			base_name;
	unicode_string			symlink_name;
	uint32_t			check_for_hang_secs;
	uint16_t			check_for_hang_ticks;
	uint16_t			check_for_hang_current_tick;
	ndis_status			reset_status;
	ndis_handle			reset_open;
	struct ndis_filter_dbs		filter_dbs;
	void				*pkt_indicate_func;
	void				*send_done_func;
	void				*send_rsrc_func;
	void				*reset_done_func;
	enum ndis_medium		medium;
	uint32_t			bus_num;
	uint32_t			bus_type;
	uint32_t			adapter_type;
	device_object			*deviceobj; /* Functional device */
	device_object			*physdeviceobj; /* Physical device */
	device_object			*nextdeviceobj; /* Next dev in stack */
	void				*mapreg;
	void				*callmgraflist;
	void				*miniport_thread;
	void				*set_infobuf;
	uint16_t			set_infobuflen;
	uint16_t			max_send_pkts;
	ndis_status			fake_status;
	void				*lock_handler;
	unicode_string			*adapter_instance_name;
	void				*timer_queue;
	uint32_t			mact_options;
	struct ndis_request		*pending_request;
	uint32_t			max_long_address;
	uint32_t			max_short_address;
	uint32_t			current_lookahead;
	uint32_t			max_lookahead;
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
	void				*status_func;
	void				*status_done_func;
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
	list_entry			parmlist;
	struct cm_partial_resource_list	*rlist;
	ndis_status			getstat;
	nt_kevent			getevent;
	ndis_status			setstat;
	nt_kevent			setevent;
	ndis_status			resetstat;
	nt_kevent			resetevent;
	io_workitem			*returnitem;
	ndis_handle			rxpool;
	list_entry			returnlist;
	kspin_lock			returnlock;
	TAILQ_ENTRY(ndis_miniport_block)	link;
};

TAILQ_HEAD(nd_head, ndis_miniport_block);

typedef ndis_status (*driver_entry)(void *, unicode_string *);
typedef uint8_t (*ndis_checkforhang_func)(ndis_handle);
typedef void (*ndis_disable_interrupts_func)(ndis_handle);
typedef void (*ndis_enable_interrupts_func)(ndis_handle);
typedef void (*ndis_halt_func)(ndis_handle);
typedef void (*ndis_interrupt_func)(ndis_handle);
typedef ndis_status (*ndis_init_func)(ndis_status *, uint32_t *,
    enum ndis_medium *, uint32_t, ndis_handle, ndis_handle);
typedef void (*ndis_isr_func)(uint8_t *, uint8_t *, ndis_handle);
typedef ndis_status (*ndis_query_info_func)(ndis_handle, ndis_oid, void *,
    uint32_t, uint32_t *, uint32_t *);
typedef int (*ndis_reset_func)(uint8_t *, ndis_handle);
typedef ndis_status (*ndis_send_func)(ndis_handle, struct ndis_packet *,
    uint32_t);
typedef ndis_status (*ndis_set_info_func)(ndis_handle, ndis_oid, void *,
    uint32_t, uint32_t *, uint32_t *);
typedef ndis_status (*ndis_transfer_data_func)(ndis_handle,
    struct ndis_packet *, uint32_t *, uint32_t);
typedef void (*ndis_return_func)(ndis_handle, struct ndis_packet *);
typedef void (*ndis_send_packets_func)(ndis_handle, struct ndis_packet **,
    uint32_t);
typedef void (*ndis_allocate_complete_func)(ndis_handle, void *,
    struct physaddr *, uint32_t, void *);
typedef void (*ndis_pnp_event_notify_func)(void *, int, void *, uint32_t);
typedef void (*ndis_shutdown_func)(void *);
extern struct image_patch_table ndis_functbl[];

void	ndis_libinit(void);
void	ndis_libfini(void);
void	ndis_unload_driver(void *);
int	ndis_mtop(struct mbuf *, struct ndis_packet **);
int	ndis_ptom(struct mbuf **, struct ndis_packet *);
int	ndis_get(void *, ndis_oid, void *, uint32_t);
int	ndis_get_int(void *, ndis_oid, uint32_t *);
int	ndis_get_info(void *, ndis_oid, void *, uint32_t, uint32_t *,
	    uint32_t *);
int	ndis_set(void *, ndis_oid, void *, uint32_t);
int	ndis_set_int(void *, ndis_oid, uint32_t);
int	ndis_set_info(void *, ndis_oid, void *, uint32_t, uint32_t *,
	    uint32_t *);
void	ndis_send_packets(void *, struct ndis_packet **, int);
int32_t	ndis_send_packet(void *, struct ndis_packet *);
int	ndis_convert_res(void *);
void	ndis_free_packet(struct ndis_packet *);
void	ndis_free_bufs(ndis_buffer *);
int32_t	ndis_reset_nic(void *);
void	ndis_disable_interrupts_nic(void *);
void	ndis_enable_interrupts_nic(void *);
void	ndis_halt_nic(void *);
void	ndis_shutdown_nic(void *);
void	ndis_pnp_event_nic(void *, uint32_t, uint32_t);
uint8_t	ndis_check_for_hang_nic(void *);
int32_t	ndis_init_nic(void *);
void	ndis_return_packet(void *, void *);
int	ndis_init_dma(void *);
void	ndis_destroy_dma(void *);
void	ndis_create_sysctls(void *);
void	ndis_flush_sysctls(void *);
int	ndis_add_sysctl(void *, char *, char *, char *, int);
int32_t	NdisAddDevice(driver_object *, device_object *);
void	NdisAllocatePacketPool(ndis_status *, ndis_handle *, uint32_t,
	    uint32_t);
void	NdisAllocatePacketPoolEx(ndis_status *, ndis_handle *, uint32_t,
	    uint32_t, uint32_t);
uint32_t	NdisPacketPoolUsage(ndis_handle);
void	NdisFreePacketPool(ndis_handle);
void	NdisAllocatePacket(ndis_status *, struct ndis_packet **, ndis_handle);
void	NdisFreePacket(struct ndis_packet *);

#endif /* _NDIS_VAR_H_ */
