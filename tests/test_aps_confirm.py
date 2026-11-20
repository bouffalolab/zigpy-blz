"""Unicasts wait for the NCP's APS_DATA_CONFIRM and are sent again after a retryable delivery failure."""

import asyncio
from unittest.mock import AsyncMock, patch

import pytest
import zigpy.config
import zigpy.exceptions
import zigpy.types as t

import zigpy_blz.zigbee.application as blz_app
from zigpy_blz.api import Blz
from zigpy_blz.blz.types import Status
from zigpy_blz.zigbee.application import ControllerApplication

DEVICE_CONFIG = {
    zigpy.config.CONF_DEVICE_PATH: "/dev/null",
    zigpy.config.CONF_DEVICE_BAUDRATE: 2000000,
}
BULB = 0x518B
ROUTE_ERROR = 0xD1
NWK_INVALID_REQUEST = 0xC2


def make_app(confirms, echo_tag=True):
    """App whose NCP accepts every frame and then confirms unicasts with the given statuses (None = no confirm)."""
    app = ControllerApplication({zigpy.config.CONF_DEVICE: DEVICE_CONFIG})
    api = Blz(app, DEVICE_CONFIG)
    statuses = list(confirms)
    sent = []

    async def send_aps_data(**kw):
        sent.append(kw)
        status = statuses.pop(0) if statuses else 0
        if status is not None:
            params = {
                "profile_id": kw["profile_id"], "cluster_id": kw["cluster_id"], "dst_short_addr": kw["dst_short_addr"],
                "src_ep": kw["src_ep"], "dst_ep": kw["dst_ep"], "msg_type": kw["msg_type"], "status": status,
                "message_tag": kw["message_tag"] if echo_tag else 0,
            }
            asyncio.get_running_loop().call_later(0.01, api._handle_aps_confirm, params)
        return Status.SUCCESS

    api.send_aps_data = AsyncMock(side_effect=send_aps_data)
    app._api = api
    return app, sent


def packet(dst=BULB, mode=t.AddrMode.NWK):
    return t.ZigbeePacket(
        src=t.AddrModeAddress(addr_mode=t.AddrMode.NWK, address=0x0000), src_ep=1,
        dst=t.AddrModeAddress(addr_mode=mode, address=dst), dst_ep=1,
        tsn=1, profile_id=0x0104, cluster_id=0x0006, data=t.SerializableBytes(b"\x01\x01\x01"),
        tx_options=t.TransmitOptions.NONE, radius=0,
    )


@pytest.fixture(autouse=True)
def fast_retries():
    with patch.object(blz_app, "APS_RETRY_DELAY_S", 0), patch.object(blz_app, "APS_CONFIRM_TIMEOUT_S", 0.2):
        yield


@pytest.mark.asyncio
async def test_unicast_succeeds_on_confirm():
    app, sent = make_app([0])
    await app.send_packet(packet())
    assert len(sent) == 1
    assert sent[0]["message_tag"] != 0
    assert app._aps_confirms_supported is True
    assert app._api._aps_confirms == {}


@pytest.mark.asyncio
async def test_route_error_is_sent_again():
    # the first unicast after the NCP starts fails route discovery; the same frame then gets through
    app, sent = make_app([ROUTE_ERROR, 0])
    await app.send_packet(packet())
    assert len(sent) == 2
    assert sent[0]["message_tag"] != sent[1]["message_tag"]


@pytest.mark.asyncio
async def test_gives_up_after_retries():
    app, sent = make_app([ROUTE_ERROR] * 5)
    with pytest.raises(zigpy.exceptions.DeliveryError, match="status 0xd1"):
        await app.send_packet(packet())
    assert len(sent) == blz_app.APS_RETRIES + 1


@pytest.mark.asyncio
async def test_non_retryable_failure_raises_at_once():
    app, sent = make_app([NWK_INVALID_REQUEST])
    with pytest.raises(zigpy.exceptions.DeliveryError, match="status 0xc2"):
        await app.send_packet(packet())
    assert len(sent) == 1


@pytest.mark.asyncio
async def test_confirm_without_tag_matches_by_target():
    app, sent = make_app([ROUTE_ERROR, 0], echo_tag=False)
    await app.send_packet(packet())
    assert len(sent) == 2


@pytest.mark.asyncio
async def test_firmware_without_confirms_stops_waiting():
    app, sent = make_app([None, None])
    await app.send_packet(packet())  # waits once, then gives up quietly
    assert app._aps_confirms_supported is False
    await app.send_packet(packet())
    assert sent[1]["message_tag"] == 0  # no longer tracked
    assert app._api._aps_confirms == {}


@pytest.mark.asyncio
async def test_broadcast_does_not_wait_for_confirm():
    app, sent = make_app([None])
    await asyncio.wait_for(app.send_packet(packet(dst=0xFFFC, mode=t.AddrMode.Broadcast)), 0.1)
    assert sent[0]["message_tag"] == 0
    assert app._aps_confirms_supported is None
