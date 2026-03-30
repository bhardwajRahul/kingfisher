import os
from typing import Any, Dict

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version: str, build_data: Dict[str, Any]) -> None:
        wheel_tag = os.environ.get("KINGFISHER_PYPI_WHEEL_TAG")
        if wheel_tag:
            build_data["tag"] = wheel_tag
            build_data["pure_python"] = False
