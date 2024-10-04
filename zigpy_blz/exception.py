"""BLZ exceptions."""

from __future__ import annotations

import typing
from zigpy_blz.blz.types import FrameId

from zigpy.exceptions import APIException

class CommandError(APIException):
    def __init__(self, status=1, *args, **kwargs):
        """Initialize instance."""
        self._status = status
        super().__init__(*args, **kwargs)

    @property
    def status(self):
        return self._status


class MismatchedResponseError(APIException):
    def __init__(
        self, frame_id: FrameId, params: dict[str, typing.Any], *args, **kwargs
    ) -> None:
        """Initialize instance."""
        super().__init__(*args, **kwargs)
        self.frame_id = frame_id
        self.params = params