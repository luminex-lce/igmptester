"""Read and write src/configuration.py without losing its comments.

The file is parsed with `ast`. Each top-level `NAME = <literal>` assignment becomes a
setting, and the comment block directly above it becomes its help text. When saving,
only the source text of the changed values is replaced, so comments, commented-out
alternatives and layout stay exactly as they were.
"""
import ast
import io
import json
import os
import tokenize
from ipaddress import IPv4Address, AddressValueError

# Extra knowledge about the known settings. Settings that are not listed here are
# still shown, with an editor that matches the type of their current value.
SCHEMA = {
    "IFACE": {
        "label": "Network interface",
        "kind": "interface",
        "group": "Network",
    },
    "MGROUP_1": {
        "label": "Multicast group 1",
        "kind": "multicast",
        "group": "Network",
        "presets": [
            {"label": "sACN universe 1", "value": "239.255.0.1"},
            {"label": "Dante", "value": "239.255.255.255"},
            {"label": "mDNS", "value": "224.0.0.251"},
        ],
    },
    "MGROUP_2": {
        "label": "Multicast group 2",
        "kind": "multicast",
        "group": "Network",
        "presets": [
            {"label": "sACN universe 2", "value": "239.255.0.2"},
        ],
    },
    "IGMPV3_SUPPORT": {
        "label": "Run IGMPv3 tests",
        "kind": "bool",
        "group": "Test selection",
    },
    "SKIP_MANUAL": {
        "label": "Skip manual tests",
        "kind": "bool",
        "group": "Test selection",
    },
    "IGMP_MEMBERSHIP_REPORT_THRESHOLD": {
        "label": "Membership report threshold",
        "kind": "int",
        "min": 1,
        "group": "Limits and timing",
    },
    "RANDOMNESS_SAMPLE_COUNT": {
        "label": "Randomness sample count",
        "kind": "int",
        "min": 2,
        "max": 100,
        "group": "Limits and timing",
    },
    "RANDOMNESS_MAX_RESPONSE_TIME": {
        "label": "Randomness max response time",
        "kind": "int",
        "min": 2,
        "max": 25,
        "unit": "seconds",
        "group": "Limits and timing",
    },
    "PCAP_FILE": {
        "label": "Analyse a capture file",
        "kind": "pcap",
        "group": "Offline analysis",
    },
}


class ConfigError(Exception):
    def __init__(self, errors):
        super().__init__("; ".join(f"{k}: {v}" for k, v in errors.items()))
        self.errors = errors


def _read(path):
    with open(path, encoding="utf-8", newline="") as f:
        return f.read()


def _comment_lines(source):
    """Map line number -> comment text, for lines holding only a comment."""
    comments = {}
    for tok in tokenize.generate_tokens(io.StringIO(source).readline):
        if tok.type == tokenize.COMMENT and tok.line.strip().startswith("#"):
            comments[tok.start[0]] = tok.string[1:].strip()
    return comments


def _assignments(source):
    tree = ast.parse(source)
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)):
            try:
                value = ast.literal_eval(node.value)
            except ValueError:
                continue
            yield node.targets[0].id, value, node


def _kind_for(name, value):
    if name in SCHEMA:
        return SCHEMA[name]["kind"]
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    return "str"


def load(path):
    source = _read(path)
    comments = _comment_lines(source)
    settings = []
    previous = None
    for name, value, node in _assignments(source):
        help_lines = []
        line = node.lineno - 1
        while line in comments:
            help_lines.insert(0, comments[line])
            line -= 1
        if not help_lines and previous and previous[0] == node.lineno - 1:
            # settings on consecutive lines share the comment block above the first one
            help_lines = previous[1]
        previous = (node.end_lineno, help_lines)
        inline = _inline_comment(source, node)
        entry = {
            "name": name,
            "value": value,
            "kind": _kind_for(name, value),
            "label": name,
            "group": "Other",
            "help": "\n".join(help_lines),
            "inline": inline,
        }
        entry.update({k: v for k, v in SCHEMA.get(name, {}).items()})
        settings.append(entry)
    return settings


def _inline_comment(source, node):
    line = source.splitlines()[node.end_lineno - 1]
    rest = line.encode("utf-8")[node.value.end_col_offset:].decode("utf-8").strip()
    return rest[1:].strip() if rest.startswith("#") else ""


def _validate(name, kind, value, spec):  # noqa: C901
    """Return the value converted to the right Python type, or raise ValueError."""
    if kind == "bool":
        if not isinstance(value, bool):
            raise ValueError("must be true or false")
        return value
    if kind in ("int", "float"):
        if isinstance(value, bool):
            raise ValueError("must be a number")
        try:
            number = int(value) if kind == "int" else float(value)
        except (TypeError, ValueError):
            raise ValueError("must be a whole number" if kind == "int" else "must be a number")
        if kind == "int" and isinstance(value, float) and value != int(value):
            raise ValueError("must be a whole number")
        if "min" in spec and number < spec["min"]:
            raise ValueError(f"must be at least {spec['min']}")
        if "max" in spec and number > spec["max"]:
            raise ValueError(f"must be at most {spec['max']}")
        return number
    if kind == "multicast":
        text = str(value).strip()
        try:
            address = IPv4Address(text)
        except AddressValueError:
            raise ValueError(f"'{text}' is not a valid IPv4 address")
        if not address.is_multicast:
            raise ValueError(f"{text} is not a multicast address (224.0.0.0 - 239.255.255.255)")
        return text
    if kind == "interface":
        text = str(value).strip()
        if not text:
            raise ValueError("select the network interface the DUT is connected to")
        return text
    if kind == "pcap":
        if value is False or value is None or value == "":
            return False
        return str(value).strip()
    if not isinstance(value, str):
        raise ValueError("must be text")
    return value


def _literal(value):
    if isinstance(value, bool) or value is None:
        return repr(value)
    if isinstance(value, (int, float)):
        return repr(value)
    return json.dumps(value)  # double quoted, matching the style of the file


def save(path, changes):
    """Apply {name: value} changes to the configuration file. Returns the new settings."""
    source = _read(path)
    current = {name: (value, node) for name, value, node in _assignments(source)}
    errors = {}
    new_values = {}
    for name, value in changes.items():
        if name not in current:
            errors[name] = "unknown setting"
            continue
        old_value = current[name][0]
        kind = _kind_for(name, old_value)
        try:
            new_values[name] = _validate(name, kind, value, SCHEMA.get(name, {}))
        except ValueError as e:
            errors[name] = str(e)

    merged = {name: value for name, (value, _) in current.items()}
    merged.update(new_values)
    if ("MGROUP_1" in new_values or "MGROUP_2" in new_values) and \
            merged.get("MGROUP_1") and merged.get("MGROUP_1") == merged.get("MGROUP_2"):
        errors["MGROUP_2"] = "must be different from multicast group 1"
    if errors:
        raise ConfigError(errors)

    lines = source.splitlines(keepends=True)
    # Replace from the bottom up so earlier offsets stay valid.
    edits = sorted(((current[n][1], v) for n, v in new_values.items() if v != current[n][0]
                    or type(v) is not type(current[n][0])),
                   key=lambda e: (e[0].value.lineno, e[0].value.col_offset), reverse=True)
    for node, value in edits:
        start, end = node.value.lineno - 1, node.value.end_lineno - 1
        first = lines[start].encode("utf-8")
        last = lines[end].encode("utf-8")
        replaced = first[:node.value.col_offset] + _literal(value).encode("utf-8") \
            + last[node.value.end_col_offset:]
        lines[start:end + 1] = [replaced.decode("utf-8")]
    new_source = "".join(lines)

    ast.parse(new_source)  # never write a file Python cannot import
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        f.write(new_source)
    os.replace(tmp, path)
    return load(path)
