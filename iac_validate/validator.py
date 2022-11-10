# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Daniel Schmidt <danischm@cisco.com>

import importlib
import importlib.util
import logging
import os
import subprocess
import sys
from typing import Any, List

import yamale
from yamale.yamale_error import YamaleError
import yaml

from iac_validate.util import load_yaml_files

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


class Validator:
    def __init__(self, schema_path: str, rules_path: str):
        if schema_path:
            logger.info("Loading schema")
            self.schema = yamale.make_schema(schema_path)
        self.errors: List[str] = []
        self.rules = {}
        if rules_path:
            logger.info("Loading rules")
            for filename in os.listdir(rules_path):
                if filename.endswith(".py"):
                    file_path = os.path.join(rules_path, filename)
                    spec = importlib.util.spec_from_file_location(
                        "iac_validate.rules", file_path
                    )
                    if spec is not None:
                        mod = importlib.util.module_from_spec(spec)
                        sys.modules["iac_validate.rules"] = mod
                        if spec.loader is not None:
                            spec.loader.exec_module(mod)
                            self.rules[mod.Rule.id] = mod.Rule

    def _validate_syntax_file(self, file_path: str) -> None:
        """Run syntactic validation for a single file"""
        filename = os.path.basename(file_path)
        if os.path.isfile(file_path) and (".yaml" in filename or ".yml" in filename):
            logger.info("Validate file: %s", filename)
            Loader = yaml.BaseLoader
            Loader.add_constructor("!vault", VaultTag.from_yaml)
            with open(file_path) as f:
                yaml_content = f.read()
            try:
                yaml.load(yaml_content, Loader=Loader)
            except yaml.error.MarkedYAMLError as e:
                msg = "Syntax error '{}': Line {}, Column {} - {}".format(
                    file_path,
                    e.problem_mark.line + 1,
                    e.problem_mark.column + 1,
                    e.problem,
                )
                logger.error(msg)
                self.errors.append(msg)
                return
            try:
                Loader = yaml.CSafeLoader
            except AttributeError:  # System does not have libyaml
                Loader = yaml.SafeLoader  # type: ignore

            Loader.add_constructor("!vault", VaultTag.from_yaml)
            data = yamale.make_data(file_path)
            try:
                yamale.validate(self.schema, data, strict=True)
            except YamaleError as e:
                for result in e.results:
                    for err in result.errors:
                        msg = "Syntax error '{}': {}".format(result.data, err)
                        logger.error(msg)
                        self.errors.append(msg)

    def validate_syntax(self, input_paths: List[str]) -> bool:
        """Run syntactic validation"""
        for input_path in input_paths:
            if os.path.isfile(input_path):
                self._validate_syntax_file(input_path)
            else:
                for dir, subdir, files in os.walk(input_path):
                    for filename in files:
                        file_path = os.path.join(dir, filename)
                        self._validate_syntax_file(file_path)
        if self.errors:
            return True
        return False

    def validate_semantics(self, input_paths: List[str]) -> bool:
        """Run semantic validation"""
        error = False
        logger.info("Loading yaml files from %s", input_paths)
        data = load_yaml_files(input_paths)

        results = {}
        for rule in self.rules.values():
            logger.info("Verifying rule id %s", rule.id)
            paths = rule.match(data)
            if len(paths) > 0:
                results[rule.id] = paths
        if len(results) > 0:
            error = True
            for id, paths in results.items():
                msg = "Semantic error, rule {}: {} ({})".format(
                    id, self.rules[id].description, paths
                )
                logger.error(msg)
                self.errors.append(msg)
        return error
