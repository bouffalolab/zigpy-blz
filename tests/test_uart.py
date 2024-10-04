import asyncio
import binascii
import pytest
from unittest.mock import MagicMock
from zigpy_blz.uart import BlzUartGateway
from zigpy_blz.blz.types import FrameId
import logging

@pytest.mark.asyncio
async def test_send():
    api = MagicMock()
    uart_gateway = BlzUartGateway(api)

    uart_gateway._transport = MagicMock()
    test_data = b"Hello Zigbee"

    uart_gateway.send(test_data)

    expected_crc = uart_gateway._compute_crc(test_data)
    expected_frame = uart_gateway.START_BYTE + uart_gateway._escape_frame(test_data) + expected_crc + uart_gateway.STOP_BYTE

    uart_gateway._transport.write.assert_called_once_with(expected_frame)

@pytest.mark.asyncio
async def test_data_received_with_valid_crc(caplog):
    api = MagicMock()
    uart_gateway = BlzUartGateway(api)

    valid_data = b"\x00\x00\x05\x00"
    crc = uart_gateway._compute_crc(valid_data)
    frame = uart_gateway.START_BYTE + uart_gateway._escape_frame(valid_data) + crc + uart_gateway.STOP_BYTE

    with caplog.at_level(logging.DEBUG):
        try:
            uart_gateway.data_received(frame)
        except:
            pass

    assert "Frame received:" in caplog.text

@pytest.mark.asyncio
async def test_data_received_with_invalid_crc(caplog):
    api = MagicMock()
    uart_gateway = BlzUartGateway(api)

    valid_data = b"\x00\x00\x05\x00"
    invalid_crc = b"\x00\x00"
    frame = uart_gateway.START_BYTE + uart_gateway._escape_frame(valid_data) + invalid_crc + uart_gateway.STOP_BYTE

    with caplog.at_level(logging.WARNING):
        uart_gateway.data_received(frame)

    assert "CRC mismatch" in caplog.text
    api.data_received.assert_not_called()

def test_escape_and_unescape_frame():
    api = MagicMock()
    uart_gateway = BlzUartGateway(api)

    test_data = b"\x42\x4C\x07Hello"  # Contains start, stop, and escape bytes
    escaped_data = uart_gateway._escape_frame(test_data)
    unescaped_data = uart_gateway._unescape_frame(escaped_data)

    assert unescaped_data == test_data

def test_close():
    api = MagicMock()
    uart_gateway = BlzUartGateway(api)

    transport_mock = MagicMock()
    uart_gateway._transport = transport_mock

    uart_gateway.close()
    transport_mock.close.assert_called_once()

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    asyncio.run(pytest.main(["-s", __file__]))