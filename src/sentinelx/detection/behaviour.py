"""Behaviour detector family wrapper."""

from sentinelx.detection.base import ModelDetector


class BehaviourDetector(ModelDetector):
    def __init__(self, package=None) -> None:
        super().__init__("behaviour", package)
