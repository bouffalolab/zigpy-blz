"""Host-side handling of NCP failures: GP traffic, command timeouts, unexpected NCP resets, join/leave."""

import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import zigpy.config
import zigpy.exceptions
import zigpy.types as t

import zigpy_blz.api as blz_api
from zigpy_blz.api import Blz
from zigpy_blz.blz.types import Bytes, Frame, FrameId, NetworkState, Status
from zigpy_blz.exception import CommandError
from zigpy_blz.uart import BlzUartGateway
from zigpy_blz.zigbee.application import ControllerApplication

DEVICE_CONFIG = {
    zigpy.config.CONF_DEVICE_PATH: "/dev/null",
    zigpy.config.CONF_DEVICE_BAUDRATE: 2000000,
}
BULB_IEEE = t.EUI64.convert("7c:b9:4c:76:d9:23:00:00")


def make_app():
    app = ControllerApplication({zigpy.config.CONF_DEVICE: DEVICE_CONFIG})
    app._api = MagicMock()
    app._api.send_aps_data = AsyncMock(return_value=Status.SUCCESS)
    return app


def make_packet(dst_ep, profile_id, cluster_id, data):
    return t.ZigbeePacket(
        src=t.AddrModeAddress(addr_mode=t.AddrMode.NWK, address=0x0000),
        src_ep=dst_ep,
        dst=t.AddrModeAddress(
            addr_mode=t.AddrMode.Broadcast, address=t.BroadcastAddress.RX_ON_WHEN_IDLE
        ),
        dst_ep=dst_ep,
        tsn=1,
        profile_id=profile_id,
        cluster_id=cluster_id,
        data=t.SerializableBytes(data),
        tx_options=t.TransmitOptions.NONE,
        radius=0,
    )


def frame_bytes(frame_id, payload=b"\x00"):
    return Frame(frmCtrl=0, seq=0x10, frame_id=frame_id, payload=Bytes(payload)).serialize()


def make_connected_api():
    app = MagicMock()
    api = Blz(app, DEVICE_CONFIG)
    api._uart = MagicMock()
    api._device_state = NetworkState.CONNECTED
    return app, api


@pytest.mark.asyncio
async def test_send_packet_drops_green_power_frames():
    app = make_app()
    gp_commissioning = make_packet(242, 0xA1E0, 0x0021, b"\x19\x09\x02\x0b\xfe\x00")

    await app.send_packet(gp_commissioning)

    app._api.send_aps_data.assert_not_called()


@pytest.mark.asyncio
async def test_send_packet_forwards_non_gp_frames():
    app = make_app()
    zdo_permit = make_packet(0, 0x0000, 0x0036, b"\x0a\xfe\x00")

    await app.send_packet(zdo_permit)

    app._api.send_aps_data.assert_awaited_once()


@pytest.mark.asyncio
async def test_send_packet_raises_delivery_error_on_ncp_failure_status():
    app = make_app()
    app._api.send_aps_data.return_value = Status.FAILURE

    with pytest.raises(zigpy.exceptions.DeliveryError):
        await app.send_packet(make_packet(1, 0x0104, 0x0006, b"\x01\x02\x01"))


@pytest.mark.asyncio
async def test_send_packet_raises_delivery_error_on_ncp_timeout():
    app = make_app()
    app._api.send_aps_data.side_effect = CommandError(Status.TIMEOUT, "timed out")

    with pytest.raises(zigpy.exceptions.DeliveryError):
        await app.send_packet(make_packet(1, 0x0104, 0x0006, b"\x01\x02\x01"))


@pytest.mark.asyncio
async def test_command_timeout_raises_instead_of_returning_none(monkeypatch):
    monkeypatch.setattr(blz_api, "ACK_TIMEOUT", 0.05)
    _, api = make_connected_api()

    with pytest.raises(CommandError):
        await api.get_network_info()

    # The NCP executes frames flagged as retransmissions again, so a timed-out
    # command must not be resent automatically.
    assert api._uart.send.call_count == 1


@pytest.mark.asyncio
async def test_unexpected_reset_ack_reports_connection_lost():
    app, api = make_connected_api()

    api.data_received(frame_bytes(FrameId.RESET_ACK))

    app.connection_lost.assert_called_once()


@pytest.mark.asyncio
async def test_reset_ack_after_requested_reset_is_not_an_error():
    app, api = make_connected_api()

    await api.reset()
    api.data_received(frame_bytes(FrameId.RESET_ACK))

    app.connection_lost.assert_not_called()


@pytest.mark.asyncio
async def test_reset_ack_while_connecting_is_not_an_error():
    app, api = make_connected_api()
    api._device_state = NetworkState.OFFLINE

    api.data_received(frame_bytes(FrameId.RESET_ACK))

    app.connection_lost.assert_not_called()


def test_nwk_status_callback_is_not_logged_as_unsolicited(caplog):
    app, api = make_connected_api()

    with caplog.at_level(logging.WARNING):
        api.data_received(frame_bytes(FrameId.NWK_STATUS_CALLBACK, b"\xf0\x00"))

    assert "Unsolicited" not in caplog.text


@pytest.mark.parametrize("status", [0x00, 0x01])
def test_join_and_rejoin_callbacks_call_handle_join(status):
    app = make_app()
    with patch.object(app, "handle_join") as join, patch.object(app, "handle_leave") as leave:
        app.blz_callback_handler(
            FrameId.DEVICE_JOIN_CALLBACK,
            {"eui64": BULB_IEEE, "node_id": 0x6BAE, "status": status},
        )

    join.assert_called_once_with(0x6BAE, BULB_IEEE, 0)
    leave.assert_not_called()


def test_leave_callback_calls_handle_leave():
    app = make_app()
    with patch.object(app, "handle_join") as join, patch.object(app, "handle_leave") as leave:
        app.blz_callback_handler(
            FrameId.DEVICE_JOIN_CALLBACK,
            {"eui64": BULB_IEEE, "node_id": 0x6BAE, "status": 0x03},
        )

    leave.assert_called_once_with(0x6BAE, BULB_IEEE)
    join.assert_not_called()


def _encode(gateway, data):
    crc = gateway._compute_crc(data)
    return gateway.START_BYTE + gateway._escape_frame(data + crc) + gateway.STOP_BYTE


def test_uart_stray_stop_byte_before_frame_does_not_block_parser():
    api = MagicMock()
    gateway = BlzUartGateway(api)
    gateway._transport = MagicMock()
    data = b"\x00\x00\x05\x00"

    gateway.data_received(gateway.STOP_BYTE + _encode(gateway, data))

    api.data_received.assert_called_once_with(data)


def test_uart_trailing_escape_byte_is_dropped_not_raised():
    api = MagicMock()
    gateway = BlzUartGateway(api)
    gateway._transport = MagicMock()
    data = b"\x00\x00\x05\x00"

    gateway.data_received(gateway.START_BYTE + b"\x01" + gateway.ESCAPE_BYTE + gateway.STOP_BYTE)
    gateway.data_received(_encode(gateway, data))

    api.data_received.assert_called_once_with(data)


@pytest.mark.asyncio
async def test_unexpected_network_down_reports_connection_lost():
    app, api = make_connected_api()

    api.data_received(frame_bytes(FrameId.STACK_STATUS_CALLBACK, b"\xff"))

    app.connection_lost.assert_called_once()


@pytest.mark.asyncio
async def test_network_down_after_requested_leave_is_expected():
    app, api = make_connected_api()
    api.send_frame = AsyncMock(return_value={"status": Status.SUCCESS})

    await api.leave_network()
    api.data_received(frame_bytes(FrameId.STACK_STATUS_CALLBACK, b"\xff"))
    api.data_received(frame_bytes(FrameId.STACK_STATUS_CALLBACK, b"\x00"))
    api.data_received(frame_bytes(FrameId.STACK_STATUS_CALLBACK, b"\xff"))

    # Only the second network-down, after the stack came back up, is unexpected.
    app.connection_lost.assert_called_once()


def test_intentional_close_does_not_report_connection_lost():
    app, api = make_connected_api()

    api.close()
    api.connection_lost(None)

    app.connection_lost.assert_not_called()


@pytest.mark.asyncio
async def test_load_network_info_does_not_restart_the_stack():
    app = make_app()
    api = app._api
    api.get_mac_address = AsyncMock(return_value=t.EUI64.convert("b8:3d:fb:08:56:de:00:00"))
    api.network_init = AsyncMock(return_value=Status.SUCCESS)
    api.get_network_info = AsyncMock(return_value={
        "node_type": 0, "ext_pan_id": 0x6DEB93F411B32983, "pan_id": 0xE920, "tx_power": 14,
        "channel": 25, "nwk_manager": 0, "nwk_update_id": 0, "channel_mask": 1 << 25,
    })
    api.get_app_version = AsyncMock(return_value="3R_BL702_20250823_1")
    api.get_security_infos = AsyncMock(return_value={
        "status": Status.SUCCESS, "nwk_key": t.KeyData([1] * 16),
        "outgoing_frame_counter": 0, "nwk_key_seq_num": 0,
    })
    api.get_trust_center_address = AsyncMock(return_value=t.EUI64.convert("b8:3d:fb:08:56:de:00:00"))
    api.get_global_tc_link_key = AsyncMock(return_value={
        "link_key": t.KeyData(b"ZigBeeAlliance09"), "outgoing_frame_counter": 0,
        "trust_center_address": t.EUI64.convert("b8:3d:fb:08:56:de:00:00"),
    })

    await app.load_network_info()

    api.network_init.assert_not_awaited()
    assert app.state.network_info.channel == 25
