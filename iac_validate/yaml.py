# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Daniel Schmidt <danischm@cisco.com>

import importlib.util
import logging
import os
import subprocess
from typing import Any, Dict, List
from mergedeep import merge, Strategy

from ruamel import yaml

logger = logging.getLogger(__name__)


class VaultTag(yaml.YAMLObject):
    yaml_tag = "!vault"

    def __init__(self, v: str):
        self.value = v

    def __repr__(self) -> str:
        spec = importlib.util.find_spec("iac_validate.ansible_vault")
        if spec:
            if "ANSIBLE_VAULT_ID" in os.environ:
                vault_id = os.environ["ANSIBLE_VAULT_ID"] + "@" + str(spec.origin)
            else:
                vault_id = str(spec.origin)
            t = subprocess.check_output(
                [
                    "ansible-vault",
                    "decrypt",
                    "--vault-id",
                    vault_id,
                ],
                input=self.value.encode(),
            )
            return t.decode()
        return ""

    @classmethod
    def from_yaml(cls, loader: Any, node: Any) -> str:
        return str(cls(node.value))


class EnvTag(yaml.YAMLObject):
    yaml_tag = "!env"

    def __init__(self, v: str):
        self.value = v

    def __repr__(self) -> str:
        env = os.getenv(self.value)
        if env is None:
            return ""
        return env

    @classmethod
    def from_yaml(cls, loader: Any, node: Any) -> str:
        return str(cls(node.value))


def load_yaml_files(paths: List[str]) -> Dict[str, Any]:
    """Load all yaml files from a provided directory."""

    def _load_file(file_path: str, data: Dict[str, Any]) -> None:
        with open(file_path, "r") as file:
            if ".yaml" in file_path or ".yml" in file_path:
                data_yaml = file.read()
                y = yaml.YAML()
                y.preserve_quotes = True  # type: ignore
                y.register_class(VaultTag)
                y.register_class(EnvTag)
                dict = y.load(data_yaml)
                merge(data, dict, strategy=Strategy.TYPESAFE_ADDITIVE) 

    result: Dict[str, Any] = {}
    for path in paths:
        if os.path.isfile(path):
            _load_file(path, result)
        else:
            for dir, subdir, files in os.walk(path):
                for filename in files:
                    try:
                        _load_file(dir + os.path.sep + filename, result)
                    except:  # noqa: E722
                        logger.warning("Could not load file: {}".format(filename))
    return result
