import struct
import typing as typ
import zigpy.types as t

# ---------------------------------------------------------------------------
# Helper types
# ---------------------------------------------------------------------------

class Bytes(bytes):
    def serialize(self):
        return self

    @classmethod
    def deserialize(cls, data):
        return cls(data), b""


class RawUint16List(t.List[t.uint16_t]):
    """A list of ``uint16_t`` values written *without* a length prefix.

    The BLZ NCP expects the cluster list to be transmitted exactly
    ``count × 16‑bit LE`` bytes – the length (*inputClusterCount* or
    *outputClusterCount*) is sent separately.  The standard ``zigpy.types
    List`` prepends its own 16‑bit length; using that would shift the data by
    two bytes.  This helper omits the prefix and serialises every element
    little‑endian, matching what *blz_handle_add_endpoint()* reads with
    ``blz_utils_fetch_bytes()``.
    """

    def serialize(self):
        # Join each uint16 in little‑endian order ("<H")
        return b"".join(struct.pack("<H", int(v) & 0xFFFF) for v in self)
    
    @classmethod
    def deserialize(cls, data: bytes, count: int):
        byte_len = count * 2
        if len(data) < byte_len:
            raise ValueError("Not enough data to deserialize RawUint16List")
        values = [t.uint16_t(struct.unpack("<H", data[i:i + 2])[0])
                  for i in range(0, byte_len, 2)]
        return cls(values), data[byte_len:]


# ---------------------------------------------------------------------------
# Frame‑level types
# ---------------------------------------------------------------------------

class FrameId(t.uint16_t):
    """Frame IDs based on BLZ documentation."""

    # Control Frames
    ACK = 0x0001
    ERROR = 0x0002
    RESET = 0x0003
    RESET_ACK = 0x0004

    # Value Frames
    GET_VALUE = 0x0010
    SET_VALUE = 0x0011
    GET_NODE_ID_BY_EUI64 = 0x0012
    GET_EUI64_BY_NODE_ID = 0x0013
    GET_NEXT_ZDP_SEQUENCE_NUM = 0x0014
    ADD_ENDPOINT = 0x0015

    # Networking Frames
    GET_NETWORK_STATE = 0x0020
    START_SCAN = 0x0021
    ENERGY_SCAN_RESULT_CALLBACK = 0x0022
    NETWORK_SCAN_RESULT_CALLBACK = 0x0023
    SCAN_COMPLETE_CALLBACK = 0x0024
    STOP_SCAN = 0x0025
    FORM_NETWORK = 0x0026
    JOIN_NETWORK = 0x0027
    LEAVE_NETWORK = 0x0028
    PERMIT_JOINING = 0x0029
    ENERGY_SCAN_REQUEST = 0x002A
    GET_NETWORK_PARAMETERS = 0x002B
    GET_RADIO_PARAMETERS = 0x002C
    GET_NEIGHBOR_TABLE_COUNT = 0x002D
    GET_NEIGHBOR_TABLE_ENTRY = 0x002E
    GET_SOURCE_ROUTE_TABLE_COUNT = 0x002F
    GET_SOURCE_ROUTE_TABLE_ENTRY = 0x0030
    GET_ROUTE_TABLE_COUNT = 0x0031
    GET_ROUTE_TABLE_ENTRY = 0x0032
    SET_CONCENTRATOR = 0x0033
    NETWORK_INIT = 0x0034
    STACK_STATUS_CALLBACK = 0x0035
    DEVICE_JOIN_CALLBACK = 0x0036
    GET_NWK_PAYLOAD_LIMIT = 0x0037
    NWK_STATUS_CALLBACK = 0x0038

    # Security Frames
    GET_NWK_SECURITY_INFOS = 0x0050
    SET_NWK_SECURITY_INFOS = 0x0051
    GET_GLOBAL_TC_LINK_KEY = 0x0052
    SET_GLOBAL_TC_LINK_KEY = 0x0053
    GET_UNIQUE_TC_LINK_KEY = 0x0054
    SET_UNIQUE_TC_LINK_KEY = 0x0055

    # List Management Frames
    ADD_WHITE_LIST = 0x0056
    CLEAR_WHITE_LIST = 0x0057
    GET_WHITE_LIST_COUNT = 0x0058
    GET_WHITE_LIST_ENTRY = 0x0059
    ADD_BLACK_LIST = 0x005A
    CLEAR_BLACK_LIST = 0x005B
    GET_BLACK_LIST_COUNT = 0x005C
    GET_BLACK_LIST_ENTRY = 0x005D
    DEL_WHITE_LIST = 0x005E
    DEL_BLACK_LIST = 0x005F

    # APS Data Frames
    SEND_APS_DATA = 0x0080
    APS_DATA_CONFIRM = 0x0081
    APS_DATA_INDICATION = 0x0082

    # Boot Management Frames
    SET_BOOT_ENTRY = 0x0090


class Frame(t.Struct):
    frmCtrl: t.uint8_t
    seq: t.uint8_t
    frame_id: FrameId
    payload: Bytes


class BlzTransmitOptions(t.bitmap8):
    NONE = 0x00
    SECURITY_ENABLED = 0x01
    ACK_ENABLED = 0x04


class BlzMsgType(t.uint8_t):
    BLZ_MSG_TYPE_UNICAST = t.uint8_t(0x01)
    BLZ_MSG_TYPE_MULTICAST = t.uint8_t(0x02)
    BLZ_MSG_TYPE_BROADCAST = t.uint8_t(0x03)


class BLZDeviceRole(t.uint8_t):
    COORDINATOR = 0x00
    ROUTER = 0x01
    NONSLEEPY_ENDDEVICE = 0x02  # rx on when idle=true
    LOWPOWER_ROUTER = 0x81
    SLEEPY_ENDDEVICE = 0x82
    INVALID = 0xff


class Status(t.enum8):
    SUCCESS = 0
    FAILURE = 1
    TIMEOUT = 2


class FirmwareVersion(t.IntStruct, t.uint32_t):
    reserved: t.uint8_t
    patch: t.uint8_t
    minor: t.uint8_t
    major: t.uint8_t


class NetworkState(t.enum8):
    OFFLINE = 0
    CONNECTED = 1


class BlzValueId(t.uint8_t):
    """
    BLZ Value ID enumeration.
    """

    # BLZ version
    BLZ_VALUE_ID_BLZ_VERSION = t.uint8_t(0x00)
    # Stack version
    BLZ_VALUE_ID_STACK_VERSION = t.uint8_t(0x01)
    # Neighbor table size
    BLZ_VALUE_ID_NEIGHBOR_TABLE_SIZE = t.uint8_t(0x02)
    # Source route table size
    BLZ_VALUE_ID_SOURCE_ROUTE_TABLE_SIZE = t.uint8_t(0x03)
    # Routing table size
    BLZ_VALUE_ID_ROUTE_TABLE_SIZE = t.uint8_t(0x04)
    # Route discovery table size
    BLZ_VALUE_ID_DISCOVERY_TABLE_SIZE = t.uint8_t(0x05)
    # Address map table size
    BLZ_VALUE_ID_ADDRESS_TABLE_SIZE = t.uint8_t(0x06)
    # Group table size
    BLZ_VALUE_ID_MULTICAST_TABLE_SIZE = t.uint8_t(0x07)
    # Broadcast table size
    BLZ_VALUE_ID_BROADCAST_TABLE_SIZE = t.uint8_t(0x08)
    # Binding table size
    BLZ_VALUE_ID_BINDING_TABLE_SIZE = t.uint8_t(0x09)
    # Max end device supported
    BLZ_VALUE_ID_MAX_END_DEVICE_CHILDREN = t.uint8_t(0x0A)
    # Indirect message timeout value
    BLZ_VALUE_ID_INDIRECT_TRANSMISSION_TIMEOUT = t.uint8_t(0x0B)
    # End device timeout value
    BLZ_VALUE_ID_END_DEVICE_BIND_TIMEOUT = t.uint8_t(0x0C)
    # Device Unique TC Link key table size
    BLZ_VALUE_ID_UNIQUE_TC_LINK_KEY_TABLE_SIZE = t.uint8_t(0x0D)
    # Trust center address
    BLZ_VALUE_ID_TRUST_CENTER_ADDRESS = t.uint8_t(0x0F)
    # MAC address of NCP
    BLZ_VALUE_ID_MAC_ADDRESS = t.uint8_t(0x20)
    BLZ_VALUE_ID_APP_VERSION = t.uint8_t(0x21)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def deserialize_dict(data: bytes, schema):
    """Deserialize *data* according to *schema* into a dict.

    Each entry in *schema* is ``name -> type``; the function returns
    ``(result_dict, remaining_bytes)``.
    """
    result = {}
    for name, type_ in schema.items():
        try:
            result[name], data = type_.deserialize(data)
        except ValueError:
            if data:
                raise
            result[name] = None
    return result, data