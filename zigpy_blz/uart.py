import asyncio
import binascii
import logging
from typing import Callable, Dict
from zigpy_blz.blz.types import FrameId
import zigpy.config
import zigpy.serial

LOGGER = logging.getLogger(__name__)


class BlzUartGateway(asyncio.Protocol):
    START_BYTE = b"\x42"
    STOP_BYTE = b"\x4C"
    ESCAPE_BYTE = b"\x07"
    ESCAPE_MASK = 0x10

    def __init__(self, api, connected_future=None):
        """Initialize the UART gateway for BLZ."""
        self._api = api
        self._buffer = b""
        self._connected_future = connected_future
        self._transport = None

    def connection_lost(self, exc) -> None:
        """Handle connection loss."""
        if exc:
            LOGGER.warning("Connection lost: %r", exc, exc_info=exc)
        self._api.connection_lost(exc)

    def connection_made(self, transport):
        """Handle connection establishment."""
        LOGGER.debug("Connection established")
        self._transport = transport
        if self._connected_future and not self._connected_future.done():
            self._connected_future.set_result(True)

    def close(self):
        self._transport.close()

    def send(self, data):
        """Send data after framing and escaping."""
        LOGGER.debug("Sending: %s", binascii.hexlify(data).decode())
        crc = self._compute_crc(data)
        frame = self.START_BYTE + self._escape_frame(data + crc) + self.STOP_BYTE
        self._transport.write(frame)
        LOGGER.debug("Sending with CRC: %s", binascii.hexlify(frame).decode())

    def send_ack(self, rx_frame):
        """Send an ACK frame."""
        tx_seq = rx_frame[1] & 0x07
        rx_seq = tx_seq << 4
        ack_frame = bytes([rx_frame[0] & 0xF0]) + bytes([rx_seq]) + FrameId.ACK.to_bytes(2, 'little')
        LOGGER.debug("Sending ACK for frame %s", ack_frame)
        self.send(ack_frame)

    def data_received(self, data):
        """Process incoming data from UART."""
        self._buffer += data
        while self._buffer:
            start = self._buffer.find(self.START_BYTE)
            stop = self._buffer.find(self.STOP_BYTE)
            if start < 0 or stop < 0 or stop < start:
                return

            frame = self._buffer[start + 1:stop]
            self._buffer = self._buffer[stop + 1:]

            frame = self._unescape_frame(frame)
            if len(frame) < 3:
                continue

            frm_ctrl = frame[0]
            crc = frame[-2:]
            frame = frame[:-2]
            if frm_ctrl & 0x80 == 0:  # If top bit is not set, perform CRC check
                if crc != self._compute_crc(frame):
                    LOGGER.warning("CRC mismatch: %s", binascii.hexlify(frame).decode())
                    continue
            else:
                LOGGER.debug("Skipping CRC check for frame with frmCtrl: 0x%02X", frm_ctrl)

            LOGGER.debug("Frame received: %s", binascii.hexlify(frame).decode())

            if len(frame) > 2:
                # If data section is included in the frame
                self.send_ack(frame)

            try:
                self._api.data_received(frame)
            except Exception as exc:
                LOGGER.error("Error handling frame", exc_info=exc)

    def _escape_frame(self, data):
        """Escape special bytes in the frame."""
        escaped = bytearray()
        for byte in data:
            if byte in (self.START_BYTE[0], self.STOP_BYTE[0], self.ESCAPE_BYTE[0]):
                escaped.append(self.ESCAPE_BYTE[0])
                escaped.append(byte ^ self.ESCAPE_MASK)
            else:
                escaped.append(byte)
        return bytes(escaped)

    def _unescape_frame(self, data):
        """Unescape special bytes in the frame."""
        unescaped = bytearray()
        it = iter(data)
        for byte in it:
            if byte == self.ESCAPE_BYTE[0]:
                unescaped.append(next(it) ^ self.ESCAPE_MASK)
            else:
                unescaped.append(byte)
        return bytes(unescaped)

    def _compute_crc(self, data):
        """Compute the CRC for the given data."""
        def calc_crc16(new_byte, prev_result):
            prev_result = ((prev_result >> 8) | (prev_result << 8)) & 0xFFFF
            prev_result ^= new_byte  # XOR with new byte
            prev_result ^= (prev_result & 0xFF) >> 4  # XOR the lower 4 bits of result
            prev_result ^= ((prev_result << 8) << 4) & 0xFFFF  # XOR result shifted left
            prev_result ^= (((prev_result & 0xFF) << 5) | ((prev_result & 0xFF) >> 3) << 8) & 0xFFFF  # Final XOR

            return prev_result

        crc16 = 0xFFFF  # Initial CRC value as in the C code
        for byte in data:
            crc16 = calc_crc16(byte, crc16)  # Update CRC with each byte

        # Return CRC as bytes in big-endian format
        return bytes([(crc16 >> 8) & 0xFF, crc16 & 0xFF])


async def connect(config: Dict[str, any], api: Callable) -> BlzUartGateway:
    loop = asyncio.get_running_loop()
    connected_future = loop.create_future()
    protocol = BlzUartGateway(api, connected_future)

    LOGGER.debug("Connecting to %s", config[zigpy.config.CONF_DEVICE_PATH])

    _, protocol = await zigpy.serial.create_serial_connection(
        loop=loop,
        protocol_factory=lambda: protocol,
        url=config[zigpy.config.CONF_DEVICE_PATH],
        baudrate=config[zigpy.config.CONF_DEVICE_BAUDRATE],
        xonxoff=False,
    )

    await connected_future

    LOGGER.debug("Connected to %s", config[zigpy.config.CONF_DEVICE_PATH])

    return protocol
