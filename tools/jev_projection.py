"""Strict, text-redacted projection of repair-state-v2 for Jev transport."""
import re
import unicodedata
from jev_contracts import canonical, require, validate_state

POLICY_VERSION = "jev-disclosure-v3"
MAX_PROJECTION_BYTES = 24 * 1024
_UNSAFE = re.compile(r"(?i)(?:[A-Z]:[\\/]|https?://|[\w.+-]+@[\w.-]+|(?:api[_-]?key|bearer|password|secret|token)\s*[:=]|(?:^|\s)/(?:[^\s]+))")
_EMAIL = re.compile(r"(?i)\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b")
_URL = re.compile(r"(?i)https?://[^\s,;]+")
_AUTHORIZATION = re.compile(r"(?i)\b(?:proxy-)?authorization[ \t]*:[^\r\n]*(?:\r?\n[ \t]+[^\r\n]*)*")
_SECRET = re.compile(r"(?i)\b(api[_-]?key|bearer|password|secret|token)\s*[:=]\s*(?:bearer\s+)?[^\s,;]+")
_BEARER = re.compile(r"(?i)\bbearer\s+[^\s,;]+")
_INTL_PHONE = re.compile(r"(?<![\w+])\+[1-9](?:\d|[ \t-][ \t]*\d)*(?:(?:[ \t-]\s*\(\s*|[ \t-]|\(\s*)\d+\s*\)?)*(?P<extension>\s*(?:x|ext(?:[.:])?|#)\s*[A-Za-z0-9]+)?(?![\w]|[./]\d)", re.IGNORECASE)
_UNRECOGNIZED_INTL_PHONE = re.compile(r"(?<![\w+])\+[1-9](?:\d|[ -]\d)*(?:[./]\d+)")
_DOMESTIC_PHONE_BASE = r"(?:\b0\d{4}(?:-|[ \t]+)\d{6}|\b0\d{10}(?!\d)|\(\d{3}\)[ \t]*\d{3}(?:[-.]|[ \t]+)\d{4}|\b\d{3}(?:[-.]|[ \t]+)\d{3}(?:[-.]|[ \t]+)\d{4}|\b\d{10}(?!\d))"
_DOMESTIC_PHONE_SUFFIX = r"(?:[ \t]*(?:x|ext(?:[.:])?|#)[ \t]*(?=(?:[\w./-]*[^\W\d_]|[0-9]+[-./_][\w_]))[\w./-]+)"
_MALFORMED_DOMESTIC_PHONE_SUFFIX = re.compile(r"(?<![\w+])" + _DOMESTIC_PHONE_BASE + _DOMESTIC_PHONE_SUFFIX, re.IGNORECASE)
_UNCONSUMED_DOMESTIC_PHONE_SUFFIX = re.compile(r"(?<![\w+])" + _DOMESTIC_PHONE_BASE + r"(?![ \t]*(?:x|ext(?:[.:])?|#))(?=[\w])", re.IGNORECASE)
_PHONE = re.compile(r"(?<![\w+])" + _DOMESTIC_PHONE_BASE + r"(?:[ \t]*(?:x|ext(?:[.:])?|#)[ \t]*\d+)?(?!\w)", re.IGNORECASE)

_NUMERIC_MEASURE = re.compile(r"(?:vs)?[+-]?\d+\.\d+[^\W\d_]+\b", re.UNICODE | re.IGNORECASE)
_FRACTION_MEASURE = re.compile(r"(?<![\w.+-])[+-]?\d+/\d+[^\W\d_]+\b", re.UNICODE | re.IGNORECASE)
_PATH = re.compile(r"(?:(?:[A-Za-z]:[\\/])|(?<![\w])/(?!/))[^\s,;]+")
_NUMERIC_TOKEN = re.compile(r"[+-]?(?:\d+\.\d+|\d+/\d+)(?![\w./])")
_FRACTION = re.compile(r"\b\d+/\d+(?!\d)")
_TEXT_IDENTIFIER = re.compile(r"(?<![\w.-])(?:[A-Za-z0-9]+[-_.])+(?:component|feature)(?:[-_.][A-Za-z0-9]+)*(?![\w-]|\.(?=[\w-]))", re.IGNORECASE)


def _redact_filenames(value):
    def filename_char(char):
        return char.isalnum() or char in "_.-" or unicodedata.category(char).startswith("M")

    output = []
    cursor = 0
    while cursor < len(value):
        if not filename_char(value[cursor]):
            output.append(value[cursor])
            cursor += 1
            continue
        end = cursor + 1
        while end < len(value) and filename_char(value[end]):
            end += 1
        token_end = end
        while token_end > cursor and value[token_end - 1] == ".":
            token_end -= 1
        token = value[cursor:token_end]
        if "." in token and any(char.isalpha() for char in token) and not _NUMERIC_MEASURE.fullmatch(token):
            output.append("[redacted filename]")
        else:
            output.append(token)
        output.append(value[token_end:end])
        cursor = end
    return "".join(output)

def _has_combining_mark_boundary(value, start, end):
    return (
        start > 0 and unicodedata.category(value[start - 1]).startswith("M")
    ) or (
        end < len(value) and unicodedata.category(value[end]).startswith("M")
    )

def _has_phone_suffix_after_separator_chain(
        value, index, *, allow_measure=False, reject_adjacent_alphanumeric=False):
    extension_marker = r"(?i)(?:x|ext(?:[.:])?|#)"
    while index < len(value):
        if re.match(extension_marker, value[index:]):
            return True
        if allow_measure and (
                _NUMERIC_MEASURE.match(value, index) or _FRACTION_MEASURE.match(value, index)
                or _NUMERIC_TOKEN.match(value, index)):
            return False
        start = index
        while index < len(value):
            char = value[index]
            if allow_measure and char in "+-" and (
                    _NUMERIC_MEASURE.match(value, index) or _FRACTION_MEASURE.match(value, index)
                    or _NUMERIC_TOKEN.match(value, index)):
                break
            if char == "+" or not unicodedata.category(char).startswith(("P", "S")):
                break
            if char in ",;":
                allow_measure = True
            index += 1
        while index < len(value) and value[index].isspace():
            index += 1
        if index == start:
            break
    if index == len(value):
        return False
    if re.match(extension_marker, value[index:]):
        return True
    if allow_measure and (
            _NUMERIC_MEASURE.match(value, index) or _FRACTION_MEASURE.match(value, index)
            or _NUMERIC_TOKEN.match(value, index)):
        return False
    if _PHONE.match(value, index):
        return False
    international_phone = _INTL_PHONE.match(value, index)
    if international_phone:
        number = (
            international_phone.group()[:international_phone.start("extension") - international_phone.start()]
            if international_phone.group("extension") else international_phone.group()
        )
        digits = sum(char.isdigit() for char in number)
        group_breaks = max(0, len(re.findall(r"\d+", number)) - 1)
        if 8 <= digits <= 15 and group_breaks <= 14:
            return False
    if reject_adjacent_alphanumeric and (
            value[index].isalnum() or value[index] == "_"
            or unicodedata.category(value[index]).startswith("M")):
        return True
    if (
            value[index].isdigit() or value[index] in "+-./:("
            or unicodedata.category(value[index]).startswith("M")
    ):
        return True
    while index < len(value) and not value[index].isspace() and value[index] not in ",;":
        if value[index].isdigit():
            return True
        index += 1
    return False

def _has_punctuated_phone_continuation(value, *, preceding_whitespace=False):
    leading = re.match(r"\s*", value)
    token_start = leading.end()
    if token_start == len(value):
        return False
    # Complete decimal/fraction tokens are separate measurements; incomplete
    # numeric groups and punctuated tails remain fail-closed candidates.
    if (token_start > 0 or preceding_whitespace) and (
            _NUMERIC_MEASURE.match(value, token_start) or _FRACTION_MEASURE.match(value, token_start)
            or _NUMERIC_TOKEN.match(value, token_start)):
        return False
    if re.match(r"(?i)(?:x|ext(?:[.:])?|#)\s*\d+", value[token_start:]):
        return True
    index = token_start
    if value[index].isdigit():
        return True
    if value[index] in ",;":
        while index < len(value) and value[index] in ",;":
            index += 1
            while index < len(value) and value[index].isspace():
                index += 1
        return _has_phone_suffix_after_separator_chain(value, index, allow_measure=True)
    if not unicodedata.category(value[index]).startswith(("P", "S")):
        return False
    while index < len(value) and unicodedata.category(value[index]).startswith(("P", "S")):
        if value[index] in "+-" and (
                _NUMERIC_MEASURE.match(value, index) or _FRACTION_MEASURE.match(value, index)
                or _NUMERIC_TOKEN.match(value, index)):
            break
        if value[index] == "+" and _INTL_PHONE.match(value, index):
            break
        index += 1
    punctuation_end = index
    punctuation = value[token_start:punctuation_end]
    while index < len(value) and value[index].isspace():
        index += 1
    allow_measure = (
        any(char in ",;" for char in punctuation)
        or (punctuation == "." and index > punctuation_end)
    )
    if allow_measure and (
            _NUMERIC_MEASURE.match(value, index) or _FRACTION_MEASURE.match(value, index)
            or _NUMERIC_TOKEN.match(value, index)):
        return False
    return _has_phone_suffix_after_separator_chain(
        value, index, allow_measure=allow_measure,
        reject_adjacent_alphanumeric=index == punctuation_end
    )
def _redact_international_phones(value, where):
    # Decimal/fraction measurements can resemble international numbers to the ambiguous-phone
    # fallback. Shield only complete unit-bearing tokens already validated by the
    # numeric-measure grammar, while preserving offsets for exact output.
    shielded = list(value)
    for measure in (*_NUMERIC_MEASURE.finditer(value), *_FRACTION_MEASURE.finditer(value)):
        shielded[measure.start():measure.end()] = "\0" * (measure.end() - measure.start())
    shielded = "".join(shielded)
    matches = list(_INTL_PHONE.finditer(shielded))
    matches_by_start = {match.start(): match for match in matches}
    # Every plausible international-number start must parse as one complete token.
    # This also rejects candidates that the matching regex would otherwise skip.
    for start in (match.start() for match in re.finditer(r"(?<![\w+])\+[1-9]", shielded)):
        require(start in matches_by_start, where + ": malformed international contact number cannot be redacted")
    # Reject regex backtracking that leaves a phone-like group or identifier suffix.
    for match in matches:
        suffix = value[match.end():]
        preceding_whitespace = match.end() > 0 and value[match.end() - 1].isspace()
        require(
            not _has_punctuated_phone_continuation(suffix, preceding_whitespace=preceding_whitespace),
            where + ": unconsumed international contact number extension cannot be redacted",
        )
        extension_candidate = re.match(r"\s*(?:x|ext(?:[.:])?|#)[^\s,;]*", suffix, re.IGNORECASE)
        if extension_candidate:
            require(
                re.fullmatch(r"\s*(?:x|ext(?:[.:])?|#)\s*\d+", extension_candidate.group(), re.IGNORECASE) is not None,
                where + ": unsupported international contact number suffix cannot be redacted",
            )
            require(
                re.match(r"\s*(?:x|ext(?:[.:])?|#)", suffix[extension_candidate.end():], re.IGNORECASE) is None,
                where + ": unconsumed international contact number extension cannot be redacted",
            )
            require(
                match.group("extension") is None,
                where + ": unconsumed international contact number extension cannot be redacted",
            )
        if suffix and (suffix[0].isalnum() or suffix[0] == "_" or unicodedata.category(suffix[0]).startswith("M")):
            require(False, where + ": unconsumed international contact number suffix cannot be redacted")
        trailing_groups = re.match(r"[ \t-]*(?:\d+|\(\s*\d+(?:\s*\))?)(?:[ \t-]+(?:\d+|\(\s*\d+(?:\s*\))?))*", suffix)
        if trailing_groups and trailing_groups.end() < len(suffix):
            following = suffix[trailing_groups.end()]
            require(
                not (following.isalnum() or following == "_" or unicodedata.category(following).startswith("M")),
                where + ": unconsumed international contact number suffix cannot be redacted",
            )
    for match in reversed(matches):
        number = match.group()[:match.start("extension") - match.start()] if match.group("extension") else match.group()
        digits = sum(char.isdigit() for char in number)
        groups = re.findall(r"\d+", number)
        group_breaks = max(0, len(groups) - 1)
        if match.group("extension"):
            require(
                re.fullmatch(r"\s*(?:x|ext(?:[.:])?|#)\s*\d+", match.group("extension"), re.IGNORECASE) is not None,
                where + ": unsupported international contact number suffix cannot be redacted",
            )
        require(8 <= digits <= 15 and group_breaks <= 14, where + ": ambiguous or overlong contact number cannot be redacted")
        shielded = shielded[:match.start()] + " " * (match.end() - match.start()) + shielded[match.end():]
    require(not _UNRECOGNIZED_INTL_PHONE.search(shielded), where + ": ambiguous international contact number cannot be redacted")
    for match in reversed(matches):
        value = value[:match.start()] + "[redacted contact number]" + value[match.end():]
    return value


def _safe_text(value, where, identifiers):
    require(isinstance(value, str) and len(value) <= 600, where + ": bounded text required")
    value = unicodedata.normalize("NFC", value)
    value = _EMAIL.sub("[redacted email]", value)
    value = _URL.sub("[redacted URL]", value)
    value = _BEARER.sub("[redacted credential]", value)
    value = _AUTHORIZATION.sub("[redacted credential]", value)
    value = _SECRET.sub("[redacted credential]", value)
    value = _redact_international_phones(value, where)
    require(not _UNCONSUMED_DOMESTIC_PHONE_SUFFIX.search(value), where + ": unconsumed domestic contact number suffix cannot be redacted")
    require(not _MALFORMED_DOMESTIC_PHONE_SUFFIX.search(value), where + ": malformed domestic contact number extension cannot be redacted")
    for match in _PHONE.finditer(value):
        require(
            re.match(r"[ \t]*(?:x|ext(?:[.:])?|#)", value[match.end():], re.IGNORECASE) is None,
            where + ": unconsumed domestic contact number extension cannot be redacted",
        )
        following = value[match.end():]
        require(
            not (following and unicodedata.category(following[0]).startswith("M")),
            where + ": unconsumed domestic contact number suffix cannot be redacted",
        )
        require(
            not _has_punctuated_phone_continuation(following),
            where + ": unconsumed domestic contact number extension cannot be redacted",
        )
    value = _PHONE.sub("[redacted contact number]", value)

    value = _PATH.sub("[redacted local path]", value)
    if identifiers:
        pattern = re.compile(r"(?<![\w.-])(?:" + "|".join(re.escape(name) for name in sorted(identifiers, key=len, reverse=True)) + r")(?![\w-]|\.(?=[\w-]))")

        def pseudonymize(segment):
            replaced = []
            cursor = 0
            for match in pattern.finditer(segment):
                if _has_combining_mark_boundary(segment, match.start(), match.end()):
                    continue
                replaced.extend((segment[cursor:match.start()], identifiers[match.group(0)]))
                cursor = match.end()
            replaced.append(segment[cursor:])
            return "".join(replaced)

        measurement_ranges = sorted(
            (match.start(), match.end())
            for expression in (_NUMERIC_MEASURE, _FRACTION_MEASURE, _NUMERIC_TOKEN, _FRACTION)
            for match in expression.finditer(value)
        )
        protected_ranges = []
        for start, end in measurement_ranges:
            if protected_ranges and start < protected_ranges[-1][1]:
                protected_ranges[-1] = (protected_ranges[-1][0], max(protected_ranges[-1][1], end))
            else:
                protected_ranges.append((start, end))

        replaced = []
        cursor = 0
        for start, end in protected_ranges:
            replaced.extend((pseudonymize(value[cursor:start]), value[start:end]))
            cursor = end
        replaced.append(pseudonymize(value[cursor:]))
        value = "".join(replaced)
    value = unicodedata.normalize("NFC", value)
    value = _redact_filenames(value)
    without_fractions = _FRACTION.sub("", value)
    require(not _UNSAFE.search(value) and not any(ch in without_fractions for ch in ("/", "\\")), where + ": unsafe text cannot be redacted")
    return value


def project_state(state):
    validate_state(state)
    focus = state["focus"]
    components = state["components"]
    facts = state["evidence"]["facts"] + state["specification"]["implementationFacts"]
    requirements = state["specification"]["requirements"]
    gates = state["gates"]
    attempts = state["recentAttempts"]

    component_names = {item["id"] for item in components}
    component_names.update(name for item in attempts for name in item["componentIds"])
    feature_names = {item["featureId"] for item in requirements}
    feature_names.update(focus["requiredFeatureIds"])
    feature_names.update(name for item in attempts for name in item["improvedFeatureIds"] + item["regressedFeatureIds"])
    retained_text = [unicodedata.normalize("NFC", focus["symptom"])]
    retained_text.extend(unicodedata.normalize("NFC", item["role"]) for item in components)
    retained_text.extend(unicodedata.normalize("NFC", value) for item in components for value in item["protectedProperties"])
    retained_text.extend(unicodedata.normalize("NFC", item["statement"]) for item in requirements)
    retained_text.extend(unicodedata.normalize("NFC", item["statement"]) for item in facts)
    retained_text.extend(unicodedata.normalize("NFC", item["hypothesis"]) for item in attempts)
    for text in retained_text:
        for match in _TEXT_IDENTIFIER.finditer(text):
            if _has_combining_mark_boundary(text, match.start(), match.end()):
                continue
            if "component" in match.group(0).lower():
                component_names.add(match.group(0))
            else:
                feature_names.add(match.group(0))
    component_pseudonyms = {name: "c" + str(index + 1) for index, name in enumerate(sorted({unicodedata.normalize("NFC", name) for name in component_names}))}
    feature_pseudonyms = {name: "f" + str(index + 1) for index, name in enumerate(sorted({unicodedata.normalize("NFC", name) for name in feature_names}))}
    component_ids = {name: component_pseudonyms[unicodedata.normalize("NFC", name)] for name in component_names}
    feature_ids = {name: feature_pseudonyms[unicodedata.normalize("NFC", name)] for name in feature_names}
    text_ids = dict(component_pseudonyms)
    for name, pseudonym in feature_pseudonyms.items():
        require(name not in text_ids, "ambiguous component/feature identifier in retained text")
        text_ids[name] = pseudonym
    safe = lambda value, where: _safe_text(value, where, text_ids)

    symptom = safe(focus["symptom"], "focus symptom")
    component_roles = {item["id"]: safe(item["role"], "component role") for item in components}
    component_properties = {item["id"]: [safe(value, "protected property") for value in item["protectedProperties"]] for item in components}
    requirement_text = {item["featureId"]: safe(item["statement"], "requirement") for item in requirements}
    fact_text = {item["id"]: safe(item["statement"], "fact") for item in facts}
    attempt_text = [safe(item["hypothesis"], "attempt hypothesis") for item in attempts]

    evidence_ids = {item["id"]: "e" + str(index + 1) for index, item in enumerate(sorted(facts, key=lambda value: value["id"]))}
    projected = {
        "schemaVersion": "repair-state-v2",
        "passId": "pass-1",
        "sceneKind": state["sceneKind"],
        "focus": {"issueId": "issue-1", "componentIds": [component_ids[item] for item in focus["componentIds"]], "symptom": symptom, "requiredFeatureIds": [feature_ids[item] for item in focus["requiredFeatureIds"]]},
        "components": [{"id": component_ids[item["id"]], "role": component_roles[item["id"]], "parentId": component_ids.get(item["parentId"]), "sharedResourceUsers": ["shared"] if item["sharedResourceUsers"] else [], "protectedProperties": component_properties[item["id"]]} for item in components],
        "specification": {"requirements": [{"featureId": feature_ids[item["featureId"]], "statement": requirement_text[item["featureId"]], "evidenceIds": [evidence_ids[name] for name in item["evidenceIds"]]} for item in requirements], "implementationFacts": [{"id": evidence_ids[item["id"]], "source": item["source"], "kind": item["kind"], "statement": fact_text[item["id"]]} for item in state["specification"]["implementationFacts"]]},
        "gates": [{"id": item["id"], "status": item["status"], "blocking": item["blocking"], "coverage": item["coverage"], "reasonCodes": list(item["reasonCodes"]), "evidenceIds": [evidence_ids[name] for name in item["evidenceIds"]]} for item in gates],
        "evidence": {"facts": [{"id": evidence_ids[item["id"]], "source": item["source"], "kind": item["kind"], "statement": fact_text[item["id"]]} for item in state["evidence"]["facts"]], "missing": list(state["evidence"]["missing"]), "comparison": state["evidence"]["comparison"], "conflicts": [[evidence_ids[name] for name in pair] for pair in state["evidence"]["conflicts"]]},
        "recentAttempts": [{"strategyId": "attempt" + str(index + 1), "componentIds": [component_ids[name] for name in item["componentIds"]], "hypothesis": attempt_text[index], "outcome": item["outcome"], "improvedFeatureIds": [feature_ids[name] for name in item["improvedFeatureIds"]], "regressedFeatureIds": [feature_ids[name] for name in item["regressedFeatureIds"]], "evidenceIds": [evidence_ids[name] for name in item["evidenceIds"]]} for index, item in enumerate(attempts)],
    }
    require(len(canonical(projected)) <= MAX_PROJECTION_BYTES, "outbound projection exceeds 24KiB")
    validate_state(projected)
    return projected
