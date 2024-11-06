# zigpy-blz


**zigpy-blz** is a Python library that adds support for Bouffalo Lab Zigbee (BLZ) radios to [zigpy](https://github.com/zigpy/), a Python Zigbee stack project.

It is designed to interface with Bouffalo Lab Zigbee (BLZ) radios, enabling users to communicate with Zigbee devices using zigpy and compatible home automation platforms, such as Home Assistant’s [ZHA (Zigbee Home Automation) integration component](https://www.home-assistant.io/integrations/zha/).

## Installation

### Python Module

Install the Python module in your virtual environment:

```bash
$ virtualenv -p python3.12 venv                                # if you don't already have one
$ source venv/bin/activate
(venv) $ pip install git+https://github.com/bouffalolab/zigpy-blz/  # latest commit from Git
(venv) $ pip install zigpy-blz                                # or, latest stable from PyPI
```

### Home Assistant

Stable releases of `zigpy-blz` will be automatically installed when you install the ZHA component in Home Assistant.

### Testing `dev` with Home Assistant Core

Upgrade the package within your virtual environment (requires `git`):

```bash
(venv) $ pip install git+https://github.com/bouffalolab/zigpy-blz/
```

### Testing `dev` with Home Assistant OS

- Add https://github.com/home-assistant/hassio-addons-development as an addon repository.
- Install the "Custom deps deployment" addon.
- Add the following to your `configuration.yaml` file:
   ```yaml
   apk: []
   pypi:
     - git+https://github.com/bouffalolab/zigpy-blz/
   ```

### Hardware Support

zigpy-blz is compatible with Bouffalo Lab’s BLZ radios, which use the Bouffalo Lab Zigbee (BLZ) Serial Protocol. Ensure your firmware version matches the protocol version supported by this library.

Supported hardware includes:
- [Bouffalo Lab BL702](https://en.bouffalolab.com/product/?type=detail&id=8)

## Developer References

For more details on the protocol used by Bouffalo Lab radios, see the Bouffalo Lab Zigbee (BLZ) documentation:

- [Bouffalo Lab BLZ Protocol](https://github.com/bouffalolab/zigpy-blz/blob/main/docs/BLZ_User_Guide.pdf)
- [BLZ ZHA User Guide](https://github.com/bouffalolab/zigpy-blz/blob/main/docs/Home_Assistant_BLZ_Radios_Integration_Guide_1.0.0.pdf)

## How to Contribute

We welcome contributions! If you'd like to contribute to this project, please follow the steps in the following guides:
- [First Contributions](https://github.com/firstcontributions/first-contributions/blob/master/README.md)

## Testing

Unit tests are available to verify the implementation. To run the tests, use:

```bash
pytest tests/
```


## Releases via PyPI

Tagged versions of `zigpy-blz` will be released via [PyPI](https://pypi.org/project/zigpy-blz/).

## Related Projects

- **[zigpy](https://github.com/zigpy/zigpy)**: The core Python Zigbee stack project that integrates with ZHA in Home Assistant.
- **[Home Assistant ZHA](https://www.home-assistant.io/integrations/zha/)**: Zigbee Home Automation integration component in Home Assistant.
- **[zha-device-handlers](https://github.com/zigpy/zha-device-handlers)**: Custom quirks for non-standard Zigbee devices in Home Assistant.


