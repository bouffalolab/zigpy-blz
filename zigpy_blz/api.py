"""Bouffalo Lab Zigbee (BLZ) API."""

from __future__ import annotations
import asyncio
import collections
import logging
from typing import Any, Callable

from zigpy.config import CONF_DEVICE_PATH
import zigpy.types as t

from zigpy_blz.exception import APIException, CommandError, MismatchedResponseError
from zigpy_blz.blz.types import *
import zigpy_blz.uart
from zigpy_blz.blz.frame import *
from async_timeout import timeout as asyncio_timeout


LOGGER = logging.getLogger(__name__)

RETRANSMISSION_LIMIT = 3
ACK_TIMEOUT = 3.0


class Blz:
    """
    Bouffalo Lab Zigbee API class.

    Handles communication with the Zigbee network co-processor (NCP).
    """

    FRAME_CTRL_NORMAL_MODE = 0x00
    FRAME_CTRL_DEBUG_MODE = 0x80
    FRAME_CTRL_RETX_MODE = 0x01

    def __init__(self, app: Callable, device_config: dict[str, Any]):
        """Initialize the API instance."""
        self._app = app
        self._config = device_config
        self._device_state = NetworkState.OFFLINE
        self._firmware_version = FirmwareVersion(0)
        self._uart: zigpy_blz.uart.BlzUartGateway | None = None
        self._tx_seq = 0  # Sequence number for outgoing frames
        self._rx_seq = 0  # Sequence number for incoming frames
        self._awaiting = collections.defaultdict(list)
        self._command_lock = asyncio.Lock()

    @property
    def firmware_version(self) -> FirmwareVersion:
        """Return the device firmware version."""
        return self._firmware_version

    @property
    def network_state(self) -> NetworkState:
        """Return the current network state."""
        return self._device_state

    async def connect(self) -> None:
        """
        Establish connection to the NCP.

        Connects to the Zigbee network co-processor and initializes the network state.
        """

        if self._uart is None:
            self._uart = await zigpy_blz.uart.connect(self._config, self)
        # await self.reset()
        # LOGGER.debug("Reset the NCP")
        # await asyncio.sleep(1)
        # LOGGER.debug("After wait for one seconds")
        await self.network_init()
        await asyncio.sleep(1)
        # wait for 1 second to make sure the network is ready
        LOGGER.info("Connected to NCP")
        self._device_state = NetworkState.CONNECTED

    def connection_lost(self, exc: Exception) -> None:
        """Lost serial connection."""
        LOGGER.debug(
            "Serial %r connection lost unexpectedly: %r",
            self._config[CONF_DEVICE_PATH],
            exc,
        )

        if self._app is not None:
            self._app.connection_lost(exc)

    async def send_frame(self, frame_id, **kwargs) -> Any:
        """Send a frame to the NCP."""
        reTx = False
        for attempt in range(RETRANSMISSION_LIMIT):
            if attempt != 0:
                reTx = True
            try:
                return await self._frame(frame_id, reTx, attempt, **kwargs)
            except MismatchedResponseError as exc:
                LOGGER.debug("Firmware responded incorrectly (%s), retrying", exc)

    async def _frame(self, frame_id, reTx, attempt, **kwargs):
        """Internal method to handle frame sending."""
        payload = []
        tx_schema, _ = FRAME_SCHEMAS[frame_id]

        for name, param_type in tx_schema.items():
            if name in kwargs:
                payload.append(kwargs[name].serialize())
            else:
                payload.append(param_type.serialize())

        frmCtrl = self.FRAME_CTRL_NORMAL_MODE | self.FRAME_CTRL_RETX_MODE if reTx else self.FRAME_CTRL_NORMAL_MODE

        async with self._command_lock:
            frame = Frame(
                frmCtrl=frmCtrl,
                seq=(self._tx_seq << 4) | self._rx_seq,  # Combined sequence byte
                frame_id=frame_id,
                payload=b"".join(payload),
            )

            self._uart.send(frame.serialize())
            self._tx_seq = (self._tx_seq + 1) % 16  # Increment and wrap around the Tx sequence

            if frame_id == FrameId.RESET:
                return
            
            fut = asyncio.Future()
            LOGGER.debug("Creating future for frame_id=%#x, seq=%d, future=%s", frame_id, self._tx_seq, fut)
            self._awaiting[frame_id].append(fut)
            
            try:
                async with asyncio_timeout(ACK_TIMEOUT):
                    LOGGER.debug("Awaiting response for frame_id=%#x, seq=%d", frame_id, self._tx_seq)
                    result = await fut
                    LOGGER.debug("Received response for frame_id=%#x, seq=%d, result=%s", frame_id, self._tx_seq, result)
                    return result
            except asyncio.TimeoutError:
                LOGGER.warning("Timeout waiting for frame_id=%#x, seq=%d, attempt=%d, future=%s", frame_id, self._tx_seq, attempt + 1, fut)
                if attempt == RETRANSMISSION_LIMIT - 1:
                    # sending timeout error
                    raise CommandError(Status.TIMEOUT, f"Frame {frame_id} timed out")
            finally:
                if fut in self._awaiting[frame_id]:
                    self._awaiting[frame_id].remove(fut)
                    LOGGER.debug("Removed future for frame_id=%#x, seq=%d, future=%s", frame_id, self._tx_seq, fut)
                else:
                    LOGGER.warning("Future already removed for frame_id=%#x, seq=%d, future=%s", frame_id, self._tx_seq, fut)

    def data_received(self, data: bytes) -> None:
        """Handle data received from the NCP."""
        frame, _ = Frame.deserialize(data)
        LOGGER.debug("Frame received: %s", frame)

        if frame.frame_id not in FRAME_SCHEMAS:
            LOGGER.warning("Unknown frame received: %s", frame)
            return

        self._rx_seq = frame.seq & 0x0F  # Extract the Rx sequence from the received frame

        try:
            LOGGER.debug("Deserializing payload for frame_id=%#x", frame.frame_id)
            params, _ = deserialize_dict(frame.payload, FRAME_SCHEMAS[frame.frame_id][1])
        except Exception as exc:
            LOGGER.warning("Failed to parse frame %s: %s", frame, exc)
            return
        
        if frame.frame_id in [FrameId.APS_DATA_CONFIRM, FrameId.RESET_ACK]:
            return
        if frame.frame_id in [FrameId.APS_DATA_INDICATION, FrameId.DEVICE_JOIN_CALLBACK, FrameId.STACK_STATUS_CALLBACK]:
            self._app.blz_callback_handler(frame.frame_id, params)
            return

        fut = None
        try:
            fut = self._awaiting[frame.frame_id][0]  # Match on Tx sequence
            LOGGER.debug("Matched future for frame_id=%#x, seq=%d, future=%s", frame.frame_id, self._rx_seq, fut)
        except IndexError:
            LOGGER.warning("Unsolicited frame received: %s", frame)
            return

        if fut is not None and not fut.done():
            fut.set_result(params)
            LOGGER.debug("Set result for future frame_id=%#x, seq=%d, future=%s", frame.frame_id, self._rx_seq, fut)
        else:
            LOGGER.warning("Future already completed or canceled for frame_id=%#x, seq=%d, future=%s", frame.frame_id, self._rx_seq, fut)

    async def network_init(self) -> Status:
        """Initialize the network."""
        LOGGER.debug("Attempting to initialize the network.")
        rsp = await self.send_frame(FrameId.NETWORK_INIT)
        LOGGER.debug("Network init response: %s", rsp)
        return rsp.get("status", Status.FAILURE)

    async def form_network(self, ext_pan_id: t.uint64_t = t.uint64_t(0), pan_id: t.uint16_t = t.uint16_t(0), channel: t.uint8_t = t.uint8_t(11)) -> Status:
        """Form a Zigbee network."""
        LOGGER.debug("Forming network with ext_pan_id=%s, pan_id=%s, channel=%s", ext_pan_id, pan_id, channel)
        rsp = await self.send_frame(FrameId.FORM_NETWORK, ext_pan_id=ext_pan_id, pan_id=pan_id, channel=channel)
        LOGGER.debug("Form network response: %s", rsp)
        return rsp.get("status", Status.FAILURE)

    async def leave_network(self) -> Status:
        """Leave a Zigbee network."""
        LOGGER.debug("Requesting to leave the network.")
        rsp = await self.send_frame(FrameId.LEAVE_NETWORK)
        LOGGER.debug("Leave network response: %s", rsp)
        return rsp.get("status", Status.FAILURE)

    async def permit_joining(self, duration: t.uint8_t = t.uint8_t(60)) -> Status:
        """Permit devices to join the network."""
        LOGGER.debug("Permitting joining for duration=%s seconds", duration)
        rsp = await self.send_frame(FrameId.PERMIT_JOINING, duration=duration)
        LOGGER.debug("Permit joining response: %s", rsp)
        return rsp.get("status", Status.FAILURE)

    async def reset(self) -> Status:
        LOGGER.debug("Resetting the NCP device.")
        await self.send_frame(FrameId.RESET)
        LOGGER.debug("Reset command sent.")

    def close(self):
        """Close the connection to the NCP."""
        LOGGER.debug("Closing UART connection.")
        if self._uart:
            self._uart.close()
            self._uart = None
        LOGGER.debug("UART connection closed.")

    async def get_network_info(self) -> t.Dict[str, Any]:
        """Retrieve current network parameters."""
        LOGGER.debug("Fetching network information.")
        rsp = await self.send_frame(FrameId.GET_NETWORK_PARAMETERS)
        LOGGER.debug("Network info response: %s", rsp)
        return {
            "node_type": rsp["node_type"],
            "ext_pan_id": rsp["ext_pan_id"],
            "pan_id": rsp["pan_id"],
            "tx_power": rsp["tx_power"],
            "channel": rsp["channel"],
            "nwk_manager": rsp["nwk_manager"],
            "nwk_update_id": rsp["nwk_update_id"],
            "channel_mask": rsp["channel_mask"],
        }

    async def get_value(self, value_id: t.uint8_t) -> Any:
        """Get a value from NCP."""
        LOGGER.debug("Getting value with ID=%#x", value_id)
        rsp = await self.send_frame(FrameId.GET_VALUE, value_id=value_id)
        LOGGER.debug("Get value response for ID=%#x: %s", value_id, rsp)
        return rsp

    async def set_value(self, value_id: t.uint8_t, value: bytes) -> Status:
        """Set a value in NCP."""
        LOGGER.debug("Setting value for ID=%#x, Length=%s", value_id, len(value))
        rsp = await self.send_frame(FrameId.SET_VALUE, value_id=value_id, value_length=len(value), value=value)
        LOGGER.debug("Set value response for ID=%#x: %s", value_id, rsp)
        return rsp["status"]
    
    async def get_global_tc_link_key(self) -> t.Dict[str, Any]:
        """Get the global Trust Center link key."""
        LOGGER.debug("Requesting global Trust Center link key.")
        rsp = await self.send_frame(FrameId.GET_GLOBAL_TC_LINK_KEY)
        LOGGER.debug("Global TC link key response: %s", rsp)
        return {
            "link_key": rsp["link_key"],
            "outgoing_frame_counter": rsp["outgoing_frame_counter"],
            "trust_center_address": rsp["trust_center_address"]
        }

    async def set_global_tc_link_key(self, link_key: t.KeyData, outgoing_frame_counter: t.uint32_t) -> Status:
        """Set the global Trust Center link key."""
        LOGGER.debug("Setting global TC link key with frame counter %s", outgoing_frame_counter)
        rsp = await self.send_frame(FrameId.SET_GLOBAL_TC_LINK_KEY, link_key=link_key, outgoing_frame_counter=outgoing_frame_counter)
        LOGGER.debug("Set global TC link key response: %s", rsp)
        return rsp["status"]

    async def get_unique_tc_link_key(self, index: t.uint16_t) -> t.Dict[str, Any]:
        """Get a unique Trust Center link key by index."""
        LOGGER.debug("Fetching unique TC link key for index %s", index)
        rsp = await self.send_frame(FrameId.GET_UNIQUE_TC_LINK_KEY, index=index)
        LOGGER.debug("Unique TC link key response: %s", rsp)
        return {
            "link_key": rsp["link_key"],
            "outgoing_frame_counter": rsp["outgoing_frame_counter"],
            "device_ieee_address": rsp["device_ieee_address"]
        }

    async def set_unique_tc_link_key(self, ieee_address: t.EUI64, unique_tc_link_key: t.KeyData) -> Status:
        """Set a unique Trust Center link key."""
        LOGGER.debug("Setting unique TC link key for device %s", ieee_address)
        rsp = await self.send_frame(FrameId.SET_UNIQUE_TC_LINK_KEY, eui64=ieee_address, unique_tc_link_key=unique_tc_link_key)
        LOGGER.debug("Set unique TC link key response: %s", rsp)
        return rsp["status"]

    async def add_endpoint(self, endpoint: t.uint8_t, profile_id: t.uint16_t, device_id: t.uint16_t, app_flags: t.uint8_t, input_clusters: t.List[t.uint16_t], output_clusters: t.List[t.uint16_t]) -> Status:
        """Add an endpoint to NCP."""
        LOGGER.debug("Adding endpoint %s, profile ID %s, device ID %s", endpoint, profile_id, device_id)
        input_cluster_count = t.uint8_t(len(input_clusters))
        output_cluster_count = t.uint8_t(len(output_clusters))
        rsp = await self.send_frame(FrameId.ADD_ENDPOINT, endpoint=endpoint, profile_id=profile_id, device_id=device_id, app_flags=app_flags, input_cluster_count=input_cluster_count, output_cluster_count=output_cluster_count, input_cluster_list=input_clusters, output_cluster_list=output_clusters)
        LOGGER.debug("Add endpoint response: %s", rsp)
        return rsp.get("status", Status.FAILURE)

    async def get_network_payload_limit(self, dst_addr: t.uint16_t) -> t.uint8_t:
        """Get the network payload limit for a given destination."""
        LOGGER.debug("Getting network payload limit for destination address %s", dst_addr)
        rsp = await self.send_frame(FrameId.GET_NWK_PAYLOAD_LIMIT, dst_addr=dst_addr)
        LOGGER.debug("Network payload limit response: %s", rsp)
        return rsp["payload_limit"]

    async def get_node_id_by_EUI64(self, ieee_addr: t.uint64_t) -> t.uint16_t:
        """Get the node ID by IEEE address."""
        LOGGER.debug("Fetching node ID by IEEE address %s", ieee_addr)
        rsp = await self.send_frame(FrameId.GET_NODE_ID_BY_IEEE, ieee_addr=ieee_addr)
        LOGGER.debug("Get node ID by IEEE response: %s", rsp)
        return rsp["node_id"]

    async def get_EUI64_by_node_id(self, node_id: t.uint16_t) -> t.uint64_t:
        """Get the IEEE address by node ID."""
        LOGGER.debug("Fetching IEEE address by node ID %s", node_id)
        rsp = await self.send_frame(FrameId.GET_IEEE_BY_NODE_ID, node_id=node_id)
        LOGGER.debug("Get IEEE by node ID response: %s", rsp)
        return rsp["eui64"]

    async def send_aps_data(self, msg_type: t.uint8_t, dst_short_addr: t.uint16_t, profile_id: t.uint16_t, cluster_id: t.uint16_t, src_ep: t.uint8_t, dst_ep: t.uint8_t, tx_options: t.uint8_t, radius: t.uint8_t, asdu: bytes) -> Status:
        """Send an APS data request."""
        LOGGER.debug("Sending APS data: msg_type %s, dst_short_addr %s, profile_id %s, cluster_id %s, src_ep %s, dst_ep %s, tx_options %s, radius %s", msg_type, dst_short_addr, profile_id, cluster_id, src_ep, dst_ep, tx_options, radius)
        rsp = await self.send_frame(FrameId.SEND_APS_DATA, msg_type=msg_type, dst_short_addr=dst_short_addr, profile_id=profile_id, cluster_id=cluster_id, src_ep=src_ep, dst_ep=dst_ep, tx_options=tx_options, radius=radius, message_tag=t.uint32_t(0), payload_len=t.uint8_t(len(asdu)), payload=asdu)
        LOGGER.debug("Send APS data response: %s", rsp)
        return rsp.get("status", Status.FAILURE)

    async def get_security_infos(self) -> t.Dict[str, Any]:
        """Retrieve network security information."""
        LOGGER.debug("Retrieving network security information.")
        rsp = await self.send_frame(FrameId.GET_NWK_SECURITY_INFOS)
        LOGGER.debug("Get network security info response: %s", rsp)
        return rsp

    async def set_security_infos(self, nwk_key: t.KeyData, outgoing_frame_counter: t.uint32_t, nwk_key_seq_num: t.uint8_t) -> Status:
        """Set network security information."""
        LOGGER.debug("Setting network security info with key %s, frame counter %s, key sequence number %s", nwk_key, outgoing_frame_counter, nwk_key_seq_num)
        rsp = await self.send_frame(FrameId.SET_NWK_SECURITY_INFOS, nwk_key=nwk_key, outgoing_frame_counter=outgoing_frame_counter, nwk_key_seq_num=nwk_key_seq_num)
        LOGGER.debug("Set security info response: %s", rsp)
        return rsp.get("status", Status.FAILURE)

    async def set_mac_address(self, ieee_addr: t.uint64_t) -> Status:
        """Set the MAC address of the NCP."""
        LOGGER.debug("Setting MAC address to %s", ieee_addr)
        rsp = await self.send_frame(FrameId.SET_VALUE, value_id=BlzValueId.BLZ_VALUE_ID_MAC_ADDRESS, ieee_addr=ieee_addr)
        LOGGER.debug("Set MAC address response: %s", rsp)
        return rsp["status"]

    async def manage_blacklist(self, action: str, mac_addr: t.uint64_t = None) -> Status:
        """Add, remove, or clear the blacklist."""
        LOGGER.debug("Managing blacklist with action: %s, MAC address: %s", action, mac_addr)
        if action == "add":
            rsp = await self.send_frame(FrameId.ADD_BLACK_LIST, mac_addr=mac_addr)
        elif action == "delete":
            rsp = await self.send_frame(FrameId.DEL_BLACK_LIST, mac_addr=mac_addr)
        elif action == "clear":
            rsp = await self.send_frame(FrameId.CLEAR_BLACK_LIST)
        else:
            raise ValueError(f"Unknown action '{action}' for blacklist management.")
        LOGGER.debug("Manage blacklist response: %s", rsp)
        return rsp["status"]

    async def manage_whitelist(self, action: str, mac_addr: t.uint64_t = None) -> Status:
        """Add, remove, or clear the whitelist."""
        LOGGER.debug("Managing whitelist with action: %s, MAC address: %s", action, mac_addr)
        if action == "add":
            rsp = await self.send_frame(FrameId.ADD_WHITE_LIST, mac_addr=mac_addr)
        elif action == "delete":
            rsp = await self.send_frame(FrameId.DEL_WHITE_LIST, mac_addr=mac_addr)
        elif action == "clear":
            rsp = await self.send_frame(FrameId.CLEAR_WHITE_LIST)
        else:
            raise ValueError(f"Unknown action '{action}' for whitelist management.")
        LOGGER.debug("Manage whitelist response: %s", rsp)
        return rsp["status"]

    async def get_blz_version(self) -> str:
        """Get the BLZ version."""
        LOGGER.debug("Requesting BLZ version.")
        rsp = await self.get_value(BlzValueId.BLZ_VALUE_ID_BLZ_VERSION)
        if rsp["status"] == Status.SUCCESS:
            version = t.uint8_t(int.from_bytes(rsp["value"], byteorder='little'))
            LOGGER.debug("Received BLZ version: %s", version)
            return version
        else:
            LOGGER.error("Failed to get BLZ version: %s", rsp["status"])
            raise Exception(f"Failed to get BLZ version: {rsp['status']}")

    async def get_stack_version(self) -> dict:
        """Get the Zigbee stack version."""
        LOGGER.debug("Requesting Zigbee stack version.")
        rsp = await self.get_value(BlzValueId.BLZ_VALUE_ID_STACK_VERSION)
        if rsp["status"] == Status.SUCCESS:
            value = rsp["value"]
            stack_version = {
                "build": (value[1] << 8) | value[0],  # Combine two bytes for build number
                "major": value[2],
                "minor": value[3],
                "patch": value[4]
            }
            LOGGER.debug("Received stack version: %s", stack_version)
            return stack_version
        else:
            LOGGER.error("Failed to get stack version: %s", rsp["status"])
            raise Exception(f"Failed to get stack version: {rsp['status']}")

    async def get_neighbor_table_size(self) -> int:
        """Get the size of the neighbor table."""
        LOGGER.debug("Requesting neighbor table size.")
        rsp = await self.get_value(BlzValueId.BLZ_VALUE_ID_NEIGHBOR_TABLE_SIZE)
        if rsp["status"] == Status.SUCCESS:
            size = t.uint8_t.deserialize(rsp["value"])[0]
            LOGGER.debug("Neighbor table size: %s", size)
            return size
        else:
            LOGGER.error("Failed to get neighbor table size: %s", rsp["status"])
            raise Exception(f"Failed to get neighbor table size: {rsp['status']}")

    async def get_source_route_table_size(self) -> int:
        """Get the size of the source route table."""
        LOGGER.debug("Requesting source route table size.")
        rsp = await self.get_value(BlzValueId.BLZ_VALUE_ID_SOURCE_ROUTE_TABLE_SIZE)
        if rsp["status"] == Status.SUCCESS:
            size = t.uint8_t(int.from_bytes(rsp["value"], "little"))
            LOGGER.debug("Source route table size: %s", size)
            return size
        else:
            LOGGER.error("Failed to get source route table size: %s", rsp["status"])
            raise Exception(f"Failed to get source route table size: {rsp['status']}")

    async def get_route_table_size(self) -> int:
        """Get the size of the routing table."""
        LOGGER.debug("Requesting routing table size.")
        rsp = await self.get_value(BlzValueId.BLZ_VALUE_ID_ROUTE_TABLE_SIZE)
        if rsp["status"] == Status.SUCCESS:
            size = t.uint8_t(int.from_bytes(rsp["value"], "little"))
            LOGGER.debug("Routing table size: %s", size)
            return size
        else:
            LOGGER.error("Failed to get routing table size: %s", rsp["status"])
            raise Exception(f"Failed to get routing table size: {rsp['status']}")

    async def get_address_table_size(self) -> int:
        """Get the size of the address map table."""
        LOGGER.debug("Requesting address map table size.")
        rsp = await self.get_value(BlzValueId.BLZ_VALUE_ID_ADDRESS_TABLE_SIZE)
        if rsp["status"] == Status.SUCCESS:
            size = t.uint8_t(int.from_bytes(rsp["value"], "little"))
            LOGGER.debug("Address map table size: %s", size)
            return size
        else:
            LOGGER.error("Failed to get address map table size: %s", rsp["status"])
            raise Exception(f"Failed to get address map table size: {rsp['status']}")

    async def get_broadcast_table_size(self) -> int:
        """Get the size of the broadcast table."""
        LOGGER.debug("Requesting broadcast table size.")
        rsp = await self.get_value(BlzValueId.BLZ_VALUE_ID_BROADCAST_TABLE_SIZE)
        if rsp["status"] == Status.SUCCESS:
            size = t.uint8_t(int.from_bytes(rsp["value"], "little"))
            LOGGER.debug("Broadcast table size: %s", size)
            return size
        else:
            LOGGER.error("Failed to get broadcast table size: %s", rsp["status"])
            raise Exception(f"Failed to get broadcast table size: {rsp['status']}")

    async def get_trust_center_address(self) -> t.EUI64:
        """Get the trust center address."""
        LOGGER.debug("Requesting trust center address.")
        rsp = await self.get_value(BlzValueId.BLZ_VALUE_ID_TRUST_CENTER_ADDRESS)
        if rsp["status"] == Status.SUCCESS:
            address = t.EUI64.deserialize(rsp["value"])[0]
            LOGGER.debug("Trust center address: %s", address)
            return address
        else:
            LOGGER.error("Failed to get trust center address: %s", rsp["status"])
            raise Exception(f"Failed to get trust center address: {rsp['status']}")

    async def get_unique_tc_link_key_table_size(self) -> int:
        """Get the size of the unique TC link key table."""
        LOGGER.debug("Requesting unique TC link key table size.")
        rsp = await self.get_value(BlzValueId.BLZ_VALUE_ID_UNIQUE_TC_LINK_KEY_TABLE_SIZE)
        if rsp["status"] == Status.SUCCESS:
            size = t.uint8_t(int.from_bytes(rsp["value"], "little"))
            LOGGER.debug("Unique TC link key table size: %s", size)
            return size
        else:
            LOGGER.error("Failed to get unique TC link key table size: %s", rsp["status"])
            raise Exception(f"Failed to get unique TC link key table size: {rsp['status']}")

    async def get_mac_address(self) -> t.EUI64:
        """Get the MAC address of the NCP."""
        LOGGER.debug("Requesting MAC address of the NCP.")
        rsp = await self.get_value(BlzValueId.BLZ_VALUE_ID_MAC_ADDRESS)
        if rsp["status"] == Status.SUCCESS:
            mac_address = t.EUI64.deserialize(rsp["value"])[0]
            LOGGER.debug("MAC address: %s", mac_address)
            return mac_address
        else:
            LOGGER.error("Failed to get MAC address: %s", rsp["status"])
            raise Exception(f"Failed to get MAC address: {rsp['status']}")

    async def get_app_version(self) -> str:
        """Get the application version of the NCP."""
        LOGGER.debug("Requesting application version of the NCP.")
        rsp = await self.get_value(BlzValueId.BLZ_VALUE_ID_APP_VERSION)
        if rsp["status"] == Status.SUCCESS:
            version = rsp["value"].decode("utf-8")
            LOGGER.debug("Application version: %s", version)
            return version
        else:
            LOGGER.error("Failed to get application version: %s", rsp["status"])
            raise Exception(f"Failed to get application version: {rsp['status']}")


