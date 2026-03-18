# zigpy-blz

**zigpy-blz** is a Python library that adds support for Bouffalo Lab Zigbee (BLZ) radios to [zigpy](https://github.com/zigpy/), a Python Zigbee stack project.

It is designed to interface with Bouffalo Lab Zigbee (BLZ) radios, enabling users to communicate with Zigbee devices using zigpy and compatible home automation platforms, such as Home Assistant's [ZHA (Zigbee Home Automation) integration component](https://www.home-assistant.io/integrations/zha/).

## Installation

### Via the BLZ Custom ZHA Component (Recommended)

The easiest way to use zigpy-blz with Home Assistant is to install the
[BLZ Custom ZHA Component](https://github.com/bouffalolab/haos_custom_zha_blz),
which automatically pulls in zigpy-blz as a dependency. See that repository for
HACS and manual install instructions.

### Python Module

Install the Python module in your virtual environment:

```bash
$ python3 -m venv venv                                                     # if you don't already have one
$ source venv/bin/activate
(venv) $ pip install git+https://github.com/bouffalolab/zigpy-blz.git@main # latest commit from Git
(venv) $ pip install zigpy-blz                                             # or, latest stable from PyPI
```

### Home Assistant Core (manual)

Upgrade the package within your virtual environment (requires `git`):

```bash
(venv) $ pip install git+https://github.com/bouffalolab/zigpy-blz.git@main
```

### Hardware Support

zigpy-blz is compatible with Bouffalo Lab's BLZ radios, which use the Bouffalo Zigbee Serial Protocol (BZSP). Ensure your firmware version matches the protocol version supported by this library.

Supported hardware includes:
- [Bouffalo Lab BL702](https://en.bouffalolab.com/product/?type=detail&id=8)
- [Bouffalo Lab BL706](https://en.bouffalolab.com/product/?type=detail&id=25)
- [ThirdReality Zigbee 3.0 USB Dongle](https://github.com/thirdreality/ThirdReality-Zigbee-3.0-USB-dongle)

## Developer References

For more details on the protocol used by Bouffalo Lab radios, see:

- [UG100 Bouffalo Lab Zigbee (BLZ) Protocol](docs/UG100%20Bouffalo%20Lab%20Zigbee%20(BLZ)%20Protocol.pdf) (included in this repo)

## How to Contribute

We welcome contributions! If you'd like to contribute to this project, please follow the steps in the following guides:
- [First Contributions](https://github.com/firstcontributions/first-contributions/blob/master/README.md)
- [GitHub Desktop Tutorial](https://github.com/firstcontributions/first-contributions/blob/master/github-desktop-tutorial.md)

## Testing

Unit tests are available to verify the implementation. To run the tests, use:

```bash
pytest tests/
```

## Releases via PyPI

Tagged versions of `zigpy-blz` are released via [PyPI](https://pypi.org/project/zigpy-blz/).
Push a `v*` tag to trigger the release workflow.

## Related Projects

- **[zigpy](https://github.com/zigpy/zigpy)**: The core Python Zigbee stack project that integrates with ZHA in Home Assistant.
- **[BLZ Custom ZHA](https://github.com/bouffalolab/haos_custom_zha_blz)**: Custom ZHA component with BLZ radio support for Home Assistant.
- **[Home Assistant ZHA](https://www.home-assistant.io/integrations/zha/)**: Zigbee Home Automation integration component in Home Assistant.
