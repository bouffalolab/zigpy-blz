from __future__ import annotations

import logging
from typing import Any

import zigpy.application
import zigpy.config
import zigpy.device
import zigpy.state
import zigpy.exceptions
import zigpy.types as t
import zigpy.zdo.types as zdo_t
import zigpy.util
import importlib.metadata

from zigpy_blz.api import Blz
from zigpy_blz.blz.types import BlzTransmitOptions, BlzMsgType, FrameId, Bytes, BLZDeviceRole, Status
import zigpy_blz.exception
import asyncio

LOGGER = logging.getLogger(__name__)


class ControllerApplication(zigpy.application.ControllerApplication):
    """ControllerApplication for BouffaloLab BLZ protocol based adapters."""
    _probe_config_variants = [
        {zigpy.config.CONF_DEVICE_BAUDRATE: 2000000},
    ]

    def __init__(self, config: dict[str, Any]):
        """Initialize instance."""
        super().__init__(config)
        self._api = None

    async def connect(self):
        api = Blz(self, self._config[zigpy.config.CONF_DEVICE])
        try:
            await api.connect()
        except Exception:
            await api.reset()
            api.close()
            raise
        self._api = api


    async def disconnect(self):
        if self._api is not None:
            self._api.close()
            self._api = None

    async def permit_with_link_key(self, node: t.EUI64, link_key: t.KeyData, time_s=60):
        await self._api.set_unique_tc_link_key(
            node, link_key
        )
        await self.permit(time_s)

    async def start_network(self):
        await self.register_endpoints()
        await self.load_network_info(load_devices=False)
        coordinator = await BlzDevice.new(
            self,
            self.state.node_info.ieee,
            self.state.node_info.nwk,
            self.state.node_info.model,
        )
        self.devices[self.state.node_info.ieee] = coordinator

    async def reset_network_info(self):
        await self._api.leave_network()

    async def write_network_info(self, *, network_info, node_info):
        """Set network info to NCP"""
        LOGGER.info("Set network info to NCP")
        await self.reset_network_info()
        # set the network information after leave the network
        await self._api.set_security_infos(nwk_key=network_info.network_key.key, outgoing_frame_counter=t.uint32_t.deserialize(t.uint32_t(network_info.network_key.tx_counter).serialize())[0], nwk_key_seq_num=t.uint8_t.deserialize(t.uint8_t(network_info.network_key.seq).serialize())[0])
        await self._api.set_global_tc_link_key(network_info.tc_link_key.key, outgoing_frame_counter=t.uint32_t.deserialize(t.uint32_t(network_info.tc_link_key.tx_counter).serialize())[0])
        # await self._api.set_unique_tc_link_key(node_info.ieee, network_info.tc_link_key.key)
        epid, _ = zigpy.types.uint64_t.deserialize(
            network_info.extended_pan_id.serialize()
        )
        try:
            await self._api.form_network(ext_pan_id=epid, pan_id=t.uint16_t(network_info.pan_id), channel=t.uint8_t(network_info.channel))
        except:
            raise zigpy.exceptions.FormationFailure(
                f"Unexpected error form network"
            )
        await asyncio.sleep(3)
        LOGGER.debug("wait for three seconds for new network has been ready")

    async def load_network_info(self, *, load_devices=False):
        """Load network info from NCP"""
        LOGGER.info("Load network info from NCP")
        network_info = self.state.network_info
        node_info = self.state.node_info
        ieee = await self._api.get_mac_address()
        node_info.ieee = t.EUI64(ieee)
        await self._api.network_init() #TODO：make sure the stack is on
        nwk_info = await self._api.get_network_info()
        if nwk_info["node_type"] == BLZDeviceRole.COORDINATOR:
            node_info.logical_type = zdo_t.LogicalType.Coordinator
            node_info.nwk = t.NWK(0x0000)
        else:
            node_info.logical_type = zdo_t.LogicalType.Router

        node_info.manufacturer = "Bouffalo Lab"

        node_info.model = "BL706"

        node_info.version = f"{int(self._api.firmware_version):#010x}"

        network_info.source = f"zigpy_blz@{importlib.metadata.version('zigpy_blz')}"
        network_info.metadata = {
            "blz": {
                "version": node_info.version,
            }
        }

        network_info.pan_id = t.PanId(nwk_info["pan_id"])
        network_info.extended_pan_id = t.ExtendedPanId.deserialize(
            t.uint64_t(nwk_info["ext_pan_id"]).serialize()
        )[0]
        network_info.channel = nwk_info["channel"]
        network_info.channel_mask = t.Channels(nwk_info["channel_mask"])
        network_info.nwk_update_id = nwk_info["nwk_update_id"]

        if network_info.channel == 0:
            LOGGER.error("Network channel is zero")
            raise zigpy.exceptions.NetworkNotFormed("Network channel is zero")

        security_info = await self._api.get_security_infos()

        network_info.network_key = zigpy.state.Key()
        network_info.network_key.key = security_info["nwk_key"]
        network_info.network_key.seq = security_info["nwk_key_seq_num"]
        network_info.network_key.tx_counter = security_info["outgoing_frame_counter"]


        network_info.tc_link_key = zigpy.state.Key()
        network_info.tc_link_key.partner_ieee = await self._api.get_trust_center_address()

        # link_key = await self._api.get_unique_tc_link_key(
        #     network_info.tc_link_key.partner_ieee,
        # )
        link_key = await self._api.get_global_tc_link_key()
        network_info.tc_link_key.key = link_key['link_key']
        network_info.tc_link_key.tx_counter = link_key['outgoing_frame_counter']


    async def force_remove(self, dev):
        LOGGER.warning(
            "Blz doesn't support forcely remove a device"
        )

    async def energy_scan(
        self, channels: t.Channels, duration_exp: int, count: int
    ) -> dict[int, float]:
        results = await super().energy_scan(
            channels=channels, duration_exp=duration_exp, count=count
        )

        return {c: v * 3 for c, v in results.items()}

    async def add_endpoint(self, descriptor: zdo_t.SimpleDescriptor) -> None:
        """Register a new endpoint on the device."""
        LOGGER.debug(
            "Register a new endpoint on the device"
        )
        await self._api.add_endpoint(
            endpoint=descriptor.endpoint,
            profile_id=descriptor.profile,
            device_id=descriptor.device_type,
            app_flags=descriptor.device_version,
            input_clusters=descriptor.input_clusters,
            output_clusters=descriptor.output_clusters,
        )

    async def send_packet(self, packet):
        LOGGER.debug("Sending packet: %r", packet)

        # Map packet.dst.addr_mode to msg_type and addresses
        if packet.dst.addr_mode == t.AddrMode.NWK:
            msg_type = BlzMsgType.BLZ_MSG_TYPE_UNICAST
            dst_short_addr = packet.dst.address  # 16-bit network address
        elif packet.dst.addr_mode == t.AddrMode.Group:
            msg_type = BlzMsgType.BLZ_MSG_TYPE_MULTICAST
            dst_short_addr = packet.dst.address  # 16-bit group address
        elif packet.dst.addr_mode == t.AddrMode.Broadcast:
            msg_type = BlzMsgType.BLZ_MSG_TYPE_BROADCAST
            dst_short_addr = packet.dst.address  # 16-bit broadcast address
        elif packet.dst.addr_mode == t.AddrMode.IEEE:
            # Resolve EUI64 to network address (node ID)
            eui64 = packet.dst.address  # Should be an instance of EUI64
            dst_short_addr = await self._api.get_node_id_by_EUI64(eui64)
            if dst_short_addr is None:
                raise ValueError(f"Cannot resolve EUI64 address: {eui64}")
            msg_type = BlzMsgType.BLZ_MSG_TYPE_UNICAST
        else:
            raise ValueError(f"Unsupported address mode: {packet.dst.addr_mode}")

        # Set transmission options
        tx_options = BlzTransmitOptions.NONE

        if t.TransmitOptions.ACK in packet.tx_options:
            tx_options |= BlzTransmitOptions.ACK_ENABLED

        if t.TransmitOptions.APS_Encryption in packet.tx_options:
            tx_options |= BlzTransmitOptions.SECURITY_ENABLED
        
        # Extract the payload (ASDU)
        asdu = packet.data.serialize()

        # Call the send_aps_data API
        async with self._limit_concurrency():
            await self._api.send_aps_data(
                msg_type=msg_type,
                dst_short_addr=dst_short_addr,
                profile_id=t.uint16_t(packet.profile_id),
                cluster_id=t.uint16_t(packet.cluster_id),
                src_ep=t.uint8_t(packet.src_ep),
                dst_ep=t.uint8_t(packet.dst_ep),
                radius=t.uint8_t(packet.radius),
                tx_options=tx_options,
                asdu=Bytes(asdu)
            )
            LOGGER.debug(f"Sending APS data: msg_type={msg_type}, dst={dst_short_addr}")

    async def permit_ncp(self, time_s=60):
        assert 0 <= time_s <= 254
        await self._api.permit_joining(t.uint8_t(time_s))

    def blz_callback_handler(self, frame_id, response):
            """Handle BLZ callbacks."""
            LOGGER.debug("Callback handler invoked: frame_id: %#x, response: %s", frame_id, response)
            if frame_id == FrameId.APS_DATA_INDICATION:
                # Handle incoming Zigbee APS data indication
                self._handle_aps_data_indication(response)
            elif frame_id == FrameId.DEVICE_JOIN_CALLBACK:
                # Handle device join event
                self._handle_device_join(response)
            elif frame_id == FrameId.STACK_STATUS_CALLBACK:
                # Handle stack status event
                self._handle_stack_status(response)
            else:
                LOGGER.warning("Other frame is in callback:, frame_id: %#x, response: %s", frame_id, response)

    def _handle_aps_data_indication(self, response):
        """Process APS data indication."""
        LOGGER.debug("APS data indication handler invoked: %s", response)

        # Create source and destination addresses
        src_address = t.AddrModeAddress(
            addr_mode=t.AddrMode.NWK,
            address=response["src_short_addr"]
        )

        dst_address = t.AddrModeAddress(
            addr_mode=self._get_addrmode_by_msg_type(response["msg_type"]),
            address=response["dst_short_addr"]
        )
        
        # Create the ZigbeePacket instance
        packet = t.ZigbeePacket(
            src=src_address,
            src_ep=response["src_ep"],
            dst=dst_address,
            dst_ep=response["dst_ep"],
            profile_id=response["profile_id"],
            cluster_id=response["cluster_id"],
            data=t.SerializableBytes(response["message"]),
            lqi=response["lqi"]  # Optional field
        )
        self.packet_received(packet)

    def _get_addrmode_by_msg_type(self, msgType):
        if msgType == BlzMsgType.BLZ_MSG_TYPE_BROADCAST:
            return t.AddrMode.Broadcast
        elif msgType == BlzMsgType.BLZ_MSG_TYPE_MULTICAST:
            return t.AddrMode.Group
        else:
            return t.AddrMode.NWK

    def _handle_device_join(self, response):
        """Handle a device join callback."""
        LOGGER.debug("Device join handler invoked: %s", response)
        nwk = response["node_id"]
        ieee = t.EUI64(response["eui64"])
        LOGGER.info(f"Device joined: IEEE={ieee}, NWK={nwk}")
        self.handle_join(nwk, ieee, 0)
    
    def _handle_stack_status(self, response):
        if response['status'] != Status.SUCCESS:
            LOGGER.error("Stack status is incorrect: %s", response)
            # await self._api.reset()
            # LOGGER.info("NCP is reset due to stack error")


class BlzDevice(zigpy.device.Device):
    """Zigpy Device representing Coordinator."""

    def __init__(self, model: str, *args):
        """Initialize instance."""

        super().__init__(*args)
        self._model = model

    async def add_to_group(self, grp_id: int, name: str = None) -> None:
        group = self.application.groups.add_group(grp_id, name)

        for epid in self.endpoints:
            if not epid:
                continue  # skip ZDO
            group.add_member(self.endpoints[epid])
        return [0]

    async def remove_from_group(self, grp_id: int) -> None:
        for epid in self.endpoints:
            if not epid:
                continue  # skip ZDO
            self.application.groups[grp_id].remove_member(self.endpoints[epid])
        return [0]

    @property
    def manufacturer(self):
        return "Bouffalo Lab"

    @property
    def model(self):
        return self._model

    @classmethod
    async def new(cls, application, ieee, nwk, model: str):
        """Create or replace zigpy device."""
        dev = cls(model, application, ieee, nwk)

        if ieee in application.devices:
            from_dev = application.get_device(ieee=ieee)
            dev.status = from_dev.status
            dev.node_desc = from_dev.node_desc
            for ep_id, from_ep in from_dev.endpoints.items():
                if not ep_id:
                    continue  # Skip ZDO
                ep = dev.add_endpoint(ep_id)
                ep.profile_id = from_ep.profile_id
                ep.device_type = from_ep.device_type
                ep.status = from_ep.status
                ep.in_clusters = from_ep.in_clusters
                ep.out_clusters = from_ep.out_clusters
        else:
            application.devices[ieee] = dev
            await dev.initialize()

        return dev
