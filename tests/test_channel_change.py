"""Channel change: the NCP must move with the devices, or the change must be refused before any broadcast."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import zigpy.application
import zigpy.config
import zigpy.exceptions
import zigpy.types as t

import zigpy_blz.zigbee.application as blz_app
from zigpy_blz.blz.frame import FRAME_SCHEMAS
from zigpy_blz.blz.types import FrameId, Status
from zigpy_blz.zigbee.application import ControllerApplication

DEVICE_CONFIG = {
    zigpy.config.CONF_DEVICE_PATH: "/dev/null",
    zigpy.config.CONF_DEVICE_BAUDRATE: 2000000,
}
UNSUPPORTED_FRAME = Status(0x31)
INVALID_VALUE = Status(0x33)


def make_app(ncp_channel=25, nwk_update_id=0):
    app = ControllerApplication({zigpy.config.CONF_DEVICE: DEVICE_CONFIG})
    app.state.network_info.channel = ncp_channel
    app.state.network_info.nwk_update_id = nwk_update_id
    app.state.node_info.version = "test-fw"

    api = MagicMock()
    ncp = {"channel": ncp_channel, "nwk_update_id": nwk_update_id}

    async def change_channel(channel, nwk_update_id):
        if not 11 <= channel <= 26:
            return INVALID_VALUE
        ncp.update(channel=channel, nwk_update_id=nwk_update_id)
        return Status.SUCCESS

    api.change_channel = AsyncMock(side_effect=change_channel)
    api.get_network_info = AsyncMock(side_effect=lambda: {
        "node_type": 0, "ext_pan_id": 0x6DEB93F411B32983, "pan_id": 0xE920, "tx_power": 14,
        "channel": ncp["channel"], "nwk_manager": 0, "nwk_update_id": ncp["nwk_update_id"],
        "channel_mask": 1 << ncp["channel"],
    })
    api.get_mac_address = AsyncMock(return_value=t.EUI64.convert("b8:3d:fb:08:56:de:00:00"))
    api.get_app_version = AsyncMock(return_value="test-fw")
    api.get_security_infos = AsyncMock(return_value={
        "status": Status.SUCCESS, "nwk_key": t.KeyData([1] * 16),
        "outgoing_frame_counter": 0, "nwk_key_seq_num": 0,
    })
    api.get_trust_center_address = AsyncMock(return_value=t.EUI64.convert("b8:3d:fb:08:56:de:00:00"))
    api.get_global_tc_link_key = AsyncMock(return_value={
        "link_key": t.KeyData(b"ZigBeeAlliance09"), "outgoing_frame_counter": 0,
        "trust_center_address": t.EUI64.convert("b8:3d:fb:08:56:de:00:00"),
    })
    app._api = api
    return app, api, ncp


@pytest.fixture(autouse=True)
def fast_channel_change(monkeypatch):
    monkeypatch.setattr(zigpy.application, "CHANNEL_CHANGE_BROADCAST_DELAY_S", 0, raising=False)
    monkeypatch.setattr(zigpy.application, "CHANNEL_CHANGE_SETTINGS_RELOAD_DELAY_S", 0, raising=False)
    monkeypatch.setattr(blz_app, "CHANNEL_CHANGE_POLL_INTERVAL_S", 0)


def test_change_channel_frame_carries_channel_and_nwk_update_id():
    request, response = FRAME_SCHEMAS[FrameId.CHANGE_CHANNEL]

    assert FrameId.CHANGE_CHANNEL == 0x0039
    assert list(request) == ["channel", "nwk_update_id"]
    assert list(response) == ["status"]


@pytest.mark.asyncio
async def test_channel_change_refused_before_broadcast_without_ncp_support():
    app, api, ncp = make_app()
    api.change_channel = AsyncMock(return_value=UNSUPPORTED_FRAME)

    with patch("zigpy.zdo.broadcast", new=AsyncMock()) as broadcast, \
            patch.object(app.backups, "create_backup", new=AsyncMock()):
        with pytest.raises(zigpy.exceptions.ControllerException):
            await app.move_network_to_channel(15)

    broadcast.assert_not_awaited()
    assert ncp["channel"] == 25


@pytest.mark.asyncio
async def test_channel_change_moves_ncp_with_the_broadcast_nwk_update_id():
    app, api, ncp = make_app(ncp_channel=25, nwk_update_id=3)

    with patch("zigpy.zdo.broadcast", new=AsyncMock()) as broadcast, \
            patch.object(app.backups, "create_backup", new=AsyncMock()) as backup:
        await app.move_network_to_channel(15)

    assert broadcast.await_count >= 1
    api.change_channel.assert_any_await(15, 4)
    assert ncp == {"channel": 15, "nwk_update_id": 4}
    assert app.state.network_info.channel == 15
    assert app.state.network_info.nwk_update_id == 4
    backup.assert_awaited_once()


@pytest.mark.asyncio
async def test_channel_change_fails_if_ncp_reports_an_error():
    app, api, ncp = make_app()
    statuses = iter([INVALID_VALUE, Status(0x30)])  # probe, then the real request
    api.change_channel = AsyncMock(side_effect=lambda *a: next(statuses))

    with patch("zigpy.zdo.broadcast", new=AsyncMock()), \
            patch.object(app.backups, "create_backup", new=AsyncMock()):
        with pytest.raises(zigpy.exceptions.ControllerException):
            await app.move_network_to_channel(15)


@pytest.mark.asyncio
async def test_channel_change_times_out_if_ncp_stays_on_old_channel(monkeypatch):
    monkeypatch.setattr(blz_app, "CHANNEL_CHANGE_TIMEOUT_S", 0.05)
    app, api, ncp = make_app()
    statuses = iter([INVALID_VALUE, Status.SUCCESS])  # probe, then a request that never takes effect
    api.change_channel = AsyncMock(side_effect=lambda *a: next(statuses))

    with patch("zigpy.zdo.broadcast", new=AsyncMock()), \
            patch.object(app.backups, "create_backup", new=AsyncMock()):
        with pytest.raises(zigpy.exceptions.ControllerException):
            await app.move_network_to_channel(15)
