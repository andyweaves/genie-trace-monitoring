# Databricks notebook source
# MAGIC %md
# MAGIC # Deterministic security-pattern utilities
# MAGIC
# MAGIC Pure functions shared with local tests. No Spark, AI, network, credential validation or
# MAGIC payload execution. PyYAML is used only when loading configuration on the driver.

# COMMAND ----------

# MAGIC %md
# MAGIC ## Configuration validation
# MAGIC
# MAGIC Invalid patterns fail visibly. Built-in signatures use bounded expressions; unbounded
# MAGIC or nested variable repetitions are rejected so configuration cannot quietly remove limits.

# COMMAND ----------

import base64
import binascii
import json
import re
import unicodedata
import urllib.parse


_SECURITY_DEFAULT_LIMITS = {
    "max_input_chars": 262144,
    "max_forms": 32,
    "max_decode_depth": 2,
    "max_run_chars": 16384,
    "max_decoded_chars": 65536,
    "max_decode_candidates": 256,
}
_SECURITY_SCOPES = {"prompt", "answer", "tool_args", "tool_result"}
_SECURITY_B64 = re.compile(r"(?<![A-Za-z0-9_+/-])[A-Za-z0-9_+/-]{16,}={0,2}(?![A-Za-z0-9_+/-])")
_SECURITY_HEX = re.compile(r"\b[0-9a-fA-F]{16,}\b")
_SECURITY_PERCENT = re.compile(r"%[0-9a-fA-F]{2}")
_SECURITY_INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤﻿]")


def _validate_security_regex(pattern):
    if not isinstance(pattern, str) or not pattern or len(pattern) > 4096:
        raise ValueError("Security patterns must be nonempty strings of at most 4096 characters")
    compiled = re.compile(pattern)
    if compiled.search(""):
        raise ValueError("A security pattern must not match empty text")
    # Validation runs on the driver only. Worker matching uses ordinary compiled re patterns.
    from re import _parser, _constants

    def visit(items, inside_repeat=False):
        for op, arg in items:
            if op in (_constants.MAX_REPEAT, _constants.MIN_REPEAT, _constants.POSSESSIVE_REPEAT):
                minimum, maximum, child = arg
                if maximum == _constants.MAXREPEAT or maximum > 8192:
                    raise ValueError("Security regex repetitions must have a finite bound <= 8192")
                if inside_repeat and maximum != minimum:
                    raise ValueError("Nested variable repetitions are not supported")
                visit(child, inside_repeat or (maximum > 1 and maximum != minimum))
            elif op == _constants.SUBPATTERN:
                visit(arg[-1], inside_repeat)
            elif op == _constants.ATOMIC_GROUP:
                visit(arg, inside_repeat)
            elif op == _constants.BRANCH:
                for branch in arg[1]:
                    visit(branch, inside_repeat)
            elif op in (_constants.ASSERT, _constants.ASSERT_NOT):
                visit(arg[1], inside_repeat)
            elif op in (_constants.GROUPREF, _constants.GROUPREF_EXISTS):
                raise ValueError("Backreferences are not supported in security patterns")

    visit(_parser.parse(pattern, 0))
    return compiled


def load_security_config(path):
    import yaml

    with open(path, encoding="utf-8") as handle:
        config = yaml.safe_load(handle)
    build_security_matcher(config)  # Fail before scheduling any distributed scan.
    return config


# COMMAND ----------

# MAGIC %md
# MAGIC ## Bounded, passive matching and normalization
# MAGIC
# MAGIC Decode only to text, never to executable objects. Limits count failed decode attempts too.
# MAGIC Encoding alone is not a finding: a scoped signature must match. Outputs contain metadata
# MAGIC only, and a coverage-limit marker is returned even when no signature matched.

# COMMAND ----------


def build_security_matcher(config):
    if not isinstance(config, dict) or not isinstance(config.get("rules"), list):
        raise ValueError("Security configuration must contain a rules list")
    if set(config) - {"version", "rules", "limits", "runaway", "allowed_hosts"}:
        raise ValueError("Unknown security configuration key")
    if type(config.get("version", 1)) is not int or config.get("version", 1) != 1:
        raise ValueError("Unsupported security configuration version")
    supplied_limits = config.get("limits", {})
    if not isinstance(supplied_limits, dict) or set(supplied_limits) - set(_SECURITY_DEFAULT_LIMITS):
        raise ValueError("Unknown or malformed security scan limits")
    limits = dict(_SECURITY_DEFAULT_LIMITS, **supplied_limits)
    for name, value in limits.items():
        if type(value) is not int or value < 1:
            raise ValueError(f"{name} must be a positive integer")
    if limits["max_input_chars"] > 1048576 or limits["max_decode_depth"] > 4:
        raise ValueError("Input limit must be <= 1048576 and decode depth <= 4")
    if limits["max_forms"] > 128 or limits["max_decode_candidates"] > 1024:
        raise ValueError("At most 128 forms and 1024 decode candidates are supported")
    if limits["max_run_chars"] > 65536 or limits["max_decoded_chars"] > 1048576:
        raise ValueError("Decode run / total limits exceed supported bounds")
    runaway = config.get("runaway", {})
    if not isinstance(runaway, dict):
        raise ValueError("runaway must be a mapping")
    if set(runaway) - {"repeat_calls", "long_turn_minutes", "span_cap_hint"}:
        raise ValueError("Unknown runaway threshold")
    for name, value in runaway.items():
        if type(value) is not int or value < 1:
            raise ValueError(f"runaway.{name} must be a positive integer")
    hosts = config.get("allowed_hosts", [])
    if not isinstance(hosts, list) or any(not isinstance(host, str) or not host for host in hosts):
        raise ValueError("allowed_hosts must be a list of host names")
    allowed_hosts = tuple(host.lower().rstrip(".") for host in hosts)
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", host) for host in allowed_hosts):
        raise ValueError("Allowlisted hosts must be literal host names, not URLs or wildcards")
    if not 1 <= len(config["rules"]) <= 128:
        raise ValueError("Security configuration must contain between 1 and 128 rules")
    compiled = []
    ids = set()
    for rule in config["rules"]:
        if not isinstance(rule, dict):
            raise ValueError("Every security rule must be a mapping")
        identifier = rule.get("id")
        if not isinstance(identifier, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,79}", identifier) or identifier in ids:
            raise ValueError("Security rule IDs must be unique lowercase identifiers")
        ids.add(identifier)
        scopes = rule.get("scopes")
        if (not isinstance(scopes, list) or not scopes or any(not isinstance(scope, str) for scope in scopes)
                or set(scopes) - (_SECURITY_SCOPES | {"any"})):
            raise ValueError(f"Invalid scopes for {identifier}")
        category = rule.get("category")
        if not isinstance(category, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,79}", category):
            raise ValueError(f"Invalid category for {identifier}")
        score = rule.get("score")
        if type(score) not in (int, float) or not 0 <= score <= 1:
            raise ValueError(f"Invalid score for {identifier}")
        if type(rule.get("flagged")) is not bool or type(rule.get("destination", False)) is not bool:
            raise ValueError(f"Invalid flagged/destination setting for {identifier}")
        if rule.get("source") is not None and not isinstance(rule["source"], str):
            raise ValueError(f"Invalid provenance for {identifier}")
        patterns = rule.get("patterns")
        if not isinstance(patterns, list) or not 1 <= len(patterns) <= 16:
            raise ValueError(f"Expected 1..16 patterns for {identifier}")
        try:
            regexes = tuple(_validate_security_regex(pattern) for pattern in patterns)
        except (re.error, ValueError) as error:
            raise ValueError(f"Invalid regex for {identifier}: {error}") from error
        compiled.append((identifier, category, frozenset(scopes), float(score), rule["flagged"],
                         rule.get("source"), rule.get("destination", False), regexes))

    def scan(text, scope):
        if scope not in _SECURITY_SCOPES:
            raise ValueError("Unknown security scan scope")
        if text is None:
            return {"hits": [], "limits": [], "scanned_chars": 0}
        if not isinstance(text, str):
            raise TypeError("Security scan input must be text or None")
        reached = set()
        if len(text) > limits["max_input_chars"]:
            reached.add("input_chars")
        original = text[:limits["max_input_chars"]]
        forms = [(original, "raw", 0)]
        seen = {original}
        attempts = 0
        decoded_chars = 0

        def attempt():
            nonlocal attempts
            if attempts >= limits["max_decode_candidates"]:
                reached.add("decode_candidates")
                return False
            attempts += 1
            return True

        def add_form(value, method, depth):
            nonlocal decoded_chars
            if not value or value in seen:
                return
            if depth > limits["max_decode_depth"]:
                reached.add("decode_depth")
                return
            if len(forms) >= limits["max_forms"]:
                reached.add("forms")
                return
            if decoded_chars + len(value) > limits["max_decoded_chars"]:
                reached.add("decoded_chars")
                return
            seen.add(value)
            decoded_chars += len(value)
            forms.append((value, method, depth))

        def printable(raw):
            try:
                value = raw.decode("utf-8")
            except UnicodeDecodeError:
                return None
            if value and sum(char.isprintable() or char.isspace() for char in value) / len(value) > 0.9:
                return value
            return None

        index = 0
        while index < len(forms):
            value, encoding, depth = forms[index]
            index += 1
            prefix = "" if encoding == "raw" else encoding + "/"
            cleaned = unicodedata.normalize("NFKC", _SECURITY_INVISIBLE.sub("", "".join(
                chr(ord(char) - 0xE0000) if 0xE0020 <= ord(char) <= 0xE007E else char for char in value)))
            if cleaned != value and attempt():
                add_form(cleaned, prefix + "unicode", depth + 1)
            if _SECURITY_PERCENT.search(value) and attempt():
                add_form(urllib.parse.unquote(value), prefix + "url", depth + 1)
            if value.lstrip().startswith(("{", "[", '"')) and attempt():
                try:
                    parsed = json.loads(value)
                except (ValueError, RecursionError):
                    parsed = None
                pending = [parsed]
                nodes = 0
                while pending and nodes < limits["max_decode_candidates"]:
                    item = pending.pop()
                    nodes += 1
                    if isinstance(item, str):
                        add_form(item, prefix + "json", depth + 1)
                    elif isinstance(item, dict):
                        pending.extend(list(item.values())[:limits["max_decode_candidates"]])
                    elif isinstance(item, list):
                        pending.extend(item[:limits["max_decode_candidates"]])
                if pending:
                    reached.add("json_nodes")
            for regex, method in ((_SECURITY_B64, "base64"), (_SECURITY_HEX, "hex")):
                for match in regex.finditer(value):
                    if not attempt():
                        break
                    run = match.group(0)
                    if len(run) > limits["max_run_chars"]:
                        reached.add("run_chars")
                        continue
                    try:
                        if method == "base64":
                            raw = base64.b64decode(run + "=" * (-len(run) % 4), altchars=b"-_", validate=True)
                        elif len(run) % 2 == 0:
                            raw = bytes.fromhex(run)
                        else:
                            continue
                    except (binascii.Error, ValueError):
                        continue
                    decoded = printable(raw)
                    if decoded:
                        add_form(decoded, prefix + method, depth + 1)
            if attempts >= limits["max_decode_candidates"]:
                # Raw signatures still run even when expansion could not be completed.
                if index < len(forms):
                    reached.add("decode_candidates")
                break

        hits = []
        for identifier, category, scopes, score, flagged, source, destination, regexes in compiled:
            if "any" not in scopes and scope not in scopes:
                continue
            found_encoding = None
            for value, encoding, _ in forms:
                for regex in regexes:
                    for ordinal, match in enumerate(regex.finditer(value)):
                        if ordinal >= 128:
                            reached.add("match_candidates")
                            break
                        target = match.groupdict().get("url") if destination else None
                        if target and allowed_hosts:
                            try:
                                host = (urllib.parse.urlsplit(target).hostname or "").lower().rstrip(".")
                            except ValueError:
                                host = ""
                            if host and any(host == allowed or host.endswith("." + allowed) for allowed in allowed_hosts):
                                continue
                        found_encoding = encoding
                        break
                    if found_encoding is not None:
                        break
                if found_encoding is not None:
                    break
            if found_encoding is not None:
                hits.append({"rule_id": identifier, "category": category, "score": score,
                             "flagged": flagged, "encoding": found_encoding, "source": source})
        return {"hits": hits, "limits": sorted(reached), "scanned_chars": len(original)}

    return scan
