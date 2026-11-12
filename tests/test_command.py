import asyncio
import pytest
import os
import pytest_asyncio
# These tests use and can reform the real dongle network. Opt in explicitly.
pytestmark = pytest.mark.skipif(os.environ.get("BLZ_HARDWARE_TESTS") != "1", reason="Requires isolated BLZ hardware test network")
from zigpy_blz.api import Blz
from zigpy_blz.blz.types import BlzValueId
from zigpy_blz.blz.types import NetworkState, Status, Bytes
from zigpy_blz.zigbee.application import ControllerApplication
from zigpy.config import CONF_DEVICE_PATH
import zigpy.config
import zigpy.types as t
import logging

@pytest_asyncio.fixture
async def blz_instance():
    device_config = {zigpy.config.CONF_DEVICE: {zigpy.config.CONF_DEVICE_PATH: '/dev/ttyUSB0', zigpy.config.CONF_DEVICE_BAUDRATE: 2000000}}
    app = ControllerApplication(device_config)
    blz = Blz(app, device_config[zigpy.config.CONF_DEVICE])
    await blz.connect()
    try:
        yield blz
    finally:
        blz.close()
        await asyncio.sleep(0.2)

@pytest.mark.asyncio
async def test_connect_to_ncp(blz_instance):
    blz = blz_instance
    assert blz.network_state != NetworkState.OFFLINE

@pytest.mark.asyncio
async def test_form_zigbee_network(blz_instance):
    blz = blz_instance
    status = await blz.form_network(ext_pan_id=t.uint64_t(1311768467294899695), pan_id=t.uint16_t(4660), channel=t.uint8_t(15))
    assert status == Status.SUCCESS

@pytest.mark.asyncio
async def test_permit_joining(blz_instance):
    blz = blz_instance
    status = await blz.permit_joining(duration=t.uint8_t(60))
    asyncio.sleep(60)
    assert status == Status.SUCCESS

@pytest.mark.asyncio
async def test_send_aps_data(blz_instance):
    blz = blz_instance
    await blz.form_network(ext_pan_id=t.uint64_t(1311768467294899695), pan_id=t.uint16_t(4660), channel=t.uint8_t(15))
    status = await blz.send_aps_data(msg_type=t.uint8_t(0), dst_short_addr=t.uint16_t(22136), profile_id=t.uint16_t(260), cluster_id=t.uint16_t(6), src_ep=t.uint8_t(1), dst_ep=t.uint8_t(1), tx_options=t.uint8_t(2), radius=t.uint8_t(2), asdu=Bytes(b'\x01\x02\x03'))
    assert status == Status.SUCCESS

@pytest.mark.asyncio
async def test_leave_network(blz_instance):
    blz = blz_instance
    await blz.form_network(ext_pan_id=t.uint64_t(1311768467294899695), pan_id=t.uint16_t(4660), channel=t.uint8_t(15))
    status = await blz.leave_network()
    assert status == Status.SUCCESS

@pytest.mark.asyncio
async def test_get_blz_version(blz_instance):
    """Test getting the BLZ version."""
    blz = blz_instance
    version = await blz.get_blz_version()
    assert version == 1

@pytest.mark.asyncio
async def test_get_stack_version(blz_instance):
    """Test getting the Zigbee stack version."""
    blz = blz_instance
    stack_version = await blz.get_stack_version()
    assert stack_version['major'] >= 0
    assert stack_version['minor'] >= 0
    assert stack_version['patch'] >= 0
    assert stack_version['build'] >= 0

@pytest.mark.asyncio
async def test_get_neighbor_table_size(blz_instance):
    """Test getting the neighbor table size."""
    blz = blz_instance
    neighbor_table_size = await blz.get_neighbor_table_size()
    assert neighbor_table_size > 0

@pytest.mark.asyncio
async def test_get_source_route_table_size(blz_instance):
    """Test getting the source route table size."""
    blz = blz_instance
    source_route_table_size = await blz.get_source_route_table_size()
    assert source_route_table_size > 0

@pytest.mark.asyncio
async def test_get_route_table_size(blz_instance):
    """Test getting the routing table size."""
    blz = blz_instance
    route_table_size = await blz.get_route_table_size()
    assert route_table_size > 0

@pytest.mark.asyncio
async def test_get_address_table_size(blz_instance):
    """Test getting the address map table size."""
    blz = blz_instance
    address_table_size = await blz.get_address_table_size()
    assert address_table_size > 0

@pytest.mark.asyncio
async def test_get_broadcast_table_size(blz_instance):
    """Test getting the broadcast table size."""
    blz = blz_instance
    broadcast_table_size = await blz.get_broadcast_table_size()
    assert broadcast_table_size > 0

@pytest.mark.asyncio
async def test_get_trust_center_address(blz_instance):
    """Test getting the Trust Center address."""
    blz = blz_instance
    trust_center_address = await blz.get_trust_center_address()
    assert trust_center_address is not None
    assert isinstance(trust_center_address, t.EUI64)

@pytest.mark.asyncio
async def test_get_unique_tc_link_key_table_size(blz_instance):
    """Test getting the unique TC link key table size."""
    blz = blz_instance
    tc_link_key_table_size = await blz.get_unique_tc_link_key_table_size()
    assert tc_link_key_table_size == 0

@pytest.mark.asyncio
async def test_get_mac_address(blz_instance):
    """Test getting the MAC address of the NCP."""
    blz = blz_instance
    mac_address = await blz.get_mac_address()
    assert mac_address is not None
    assert isinstance(mac_address, t.EUI64)

@pytest.mark.asyncio
async def test_get_app_version(blz_instance):
    """Test getting the application version of the NCP."""
    blz = blz_instance
    app_version = await blz.get_app_version()
    assert app_version is not None
    assert isinstance(app_version, str)

@pytest.mark.asyncio
async def test_get_network_payload_limit(blz_instance):
    blz = blz_instance
    payload_limit = await blz.get_network_payload_limit(t.uint16_t(22136))
    assert payload_limit > 0

@pytest.mark.asyncio
async def test_get_network_security_infos(blz_instance):
    blz = blz_instance
    security_info = await blz.get_security_infos()
    assert security_info['nwk_key'] is not None

@pytest.mark.asyncio
async def test_get_network_info(blz_instance):
    blz = blz_instance
    status = await blz.leave_network()
    status = await blz.form_network(ext_pan_id=t.uint64_t(1311768467294899695), pan_id=t.uint16_t(4660), channel=t.uint8_t(15))
    await asyncio.sleep(5)
    network_info = await blz.get_network_info()
    assert network_info['pan_id'] == 4660
    assert network_info['channel'] == 15
if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    asyncio.run(pytest.main(['-s', __file__]))
