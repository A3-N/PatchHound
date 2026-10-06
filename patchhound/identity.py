"""Resolve NTDS account identifiers to BloodHound AD nodes.

BloodHound names AD users as ``SAM@DOMAIN.FQDN`` and computers as
``HOST.DOMAIN.FQDN``.  Those display names are not necessarily a user's UPN.
Likewise, sAMAccountName is unique only inside an AD domain.  This module keeps
those namespaces separate, but can learn missing NetBIOS-to-DNS aliases from
globally unique SAM anchors in the supplied offline data.  It deliberately
never maps an NTDS credential directly to an AZUser.  BloodHound's hybrid
relationship is keyed by the AD user's object ID and the AZUser's ``onpremid``
property instead.
"""

from collections.abc import Iterable

Target = dict[str, str]
TargetIndex = dict[str, object]


def _text(value) -> str:
    return "" if value is None else str(value).strip()


def _key(value) -> str:
    return _text(value).casefold()


def _domain_from_dn(value) -> str:
    parts = []
    for component in _text(value).split(","):
        key, separator, val = component.strip().partition("=")
        if separator and key.casefold() == "dc" and val:
            parts.append(val)
    return ".".join(parts)


def _node_domain(kind: str, row: dict) -> str:
    domain = _text(row.get("domain")) or _domain_from_dn(row.get("distinguishedname"))
    if domain:
        return domain

    name = _text(row.get("name"))
    if kind == "User" and "@" in name:
        return name.rsplit("@", 1)[1]
    if kind == "Computer" and "." in name:
        return name.split(".", 1)[1]
    return ""


def _node_sam(kind: str, row: dict, domain: str) -> str:
    sam = _text(row.get("sam"))
    if sam:
        return f"{sam.rstrip('$')}$" if kind == "Computer" else sam

    name = _text(row.get("name"))
    if kind == "User" and "@" in name:
        return name.rsplit("@", 1)[0]
    if kind == "Computer" and name:
        suffix = f".{domain}" if domain else ""
        host = (
            name[: -len(suffix)]
            if suffix and name.casefold().endswith(suffix.casefold())
            else name.split(".", 1)[0]
        )
        return f"{host.rstrip('$')}$" if host else ""
    return ""


def _add(mapping: dict[object, list[Target]], key, target: Target):
    if not key:
        return
    bucket = mapping.setdefault(key, [])
    identity = (target["kind"], target["objectid"].casefold())
    if all((item["kind"], item["objectid"].casefold()) != identity for item in bucket):
        bucket.append(target)


def build_target_index(
    domain_rows: Iterable[dict], node_rows: Iterable[dict]
) -> tuple[TargetIndex, dict[str, int]]:
    """Build a domain-aware local index from BloodHound graph rows."""

    domain_aliases: dict[str, set[str]] = {}
    inferred_aliases: dict[str, set[str]] = {}

    for row in domain_rows:
        fqdn = _text(row.get("name")) or _text(row.get("domain"))
        if not fqdn:
            continue
        fqdn_key = _key(fqdn)
        domain_aliases.setdefault(fqdn_key, set()).add(fqdn_key)

        netbios = _key(row.get("netbios"))
        if netbios:
            domain_aliases.setdefault(netbios, set()).add(fqdn_key)

        # Older SharpHound data may not contain the netbios property.  The
        # first DNS label is only a fallback and remains ambiguity checked.
        first_label = fqdn_key.split(".", 1)[0]
        if first_label:
            inferred_aliases.setdefault(first_label, set()).add(fqdn_key)

    index: TargetIndex = {
        "domain_aliases": domain_aliases,
        "inferred_domain_aliases": inferred_aliases,
        "learned_domain_aliases": {},
        "scoped_sam": {},
        "bare_sam": {},
        "user_upn": {},
    }
    stats = {"nodes": 0, "users": 0, "computers": 0, "skipped_without_objectid": 0}

    for row in node_rows:
        objectid = _text(row.get("objectid"))
        if not objectid:
            stats["skipped_without_objectid"] += 1
            continue

        labels = set(row.get("labels") or [])
        for kind in ("User", "Computer"):
            if kind not in labels:
                continue

            domain = _node_domain(kind, row)
            sam = _node_sam(kind, row, domain)
            target = {
                "kind": kind,
                "objectid": objectid,
                "name": _text(row.get("name")) or objectid,
                "domain": domain,
                "sam": sam,
            }
            stats["nodes"] += 1
            stats["users" if kind == "User" else "computers"] += 1

            if domain and sam:
                domain_key = _key(domain)
                domain_aliases.setdefault(domain_key, set()).add(domain_key)
                first_label = domain_key.split(".", 1)[0]
                if first_label:
                    inferred_aliases.setdefault(first_label, set()).add(domain_key)
                _add(index["scoped_sam"], (domain_key, _key(sam)), target)
            if sam:
                _add(index["bare_sam"], _key(sam), target)
            if kind == "User":
                upn = _key(row.get("upn"))
                if upn:
                    _add(index["user_upn"], upn, target)

    return index, stats


def _resolved_domains(index: TargetIndex, domain: str) -> tuple[set[str], str]:
    domain_key = _key(domain)
    explicit = index["domain_aliases"].get(domain_key, set())
    if len(explicit) == 1:
        return set(explicit), "domain"

    # A collected Domain.netbios value is authoritative when unique.  When it
    # is missing or collides, consistent account evidence from this NTDS file
    # is stronger than guessing from the first DNS label.
    learned = index.get("learned_domain_aliases", {}).get(domain_key, set())
    if len(learned) == 1 and (not explicit or learned.issubset(explicit)):
        return set(learned), "learned_domain"
    if explicit:
        return set(explicit), "ambiguous_domain"

    inferred = index["inferred_domain_aliases"].get(domain_key, set())
    if inferred:
        return set(inferred), "inferred_domain"
    return set(), "unknown_domain"


def _target_identity(target: Target) -> tuple[str, str]:
    return target["kind"], target["objectid"].casefold()


def _unique_targets(targets: Iterable[Target]) -> list[Target]:
    unique = {}
    for target in targets:
        unique[_target_identity(target)] = target
    return list(unique.values())


def _learn_domain_aliases(rows: Iterable[dict], index: TargetIndex, minimum_anchors: int = 2):
    """Learn otherwise unavailable NTDS-domain aliases from unambiguous SAMs.

    secretsdump normally emits ``NETBIOS\\sam`` while BloodHound commonly has a
    DNS domain on each node.  Old or partial collections may lack the Domain
    node's ``netbios`` property.  A SAM that occurs on exactly one graph node
    is still a safe account match and provides an offline domain anchor.  Two
    distinct, unanimous anchors are required before that alias may disambiguate
    SAMs that exist in more than one domain.
    """

    evidence: dict[str, dict[str, set[str]]] = {}
    for row in rows:
        domain_key = _key(row.get("domain"))
        sam_key = _key(row.get("sam"))
        if not domain_key or not sam_key:
            continue

        # There is nothing to learn when collected or deterministic graph
        # metadata already maps the token to exactly one DNS domain.
        explicit = index["domain_aliases"].get(domain_key, set())
        inferred = index["inferred_domain_aliases"].get(domain_key, set())
        if len(explicit) == 1 or (not explicit and len(inferred) == 1):
            continue

        matches = index["bare_sam"].get(sam_key, [])
        if len(matches) != 1:
            continue
        target_domain = _key(matches[0].get("domain"))
        if not target_domain:
            continue
        by_domain = evidence.setdefault(domain_key, {})
        by_domain.setdefault(target_domain, set()).add(sam_key)

    learned: dict[str, set[str]] = {}
    for alias, by_domain in evidence.items():
        if len(by_domain) != 1:
            continue
        target_domain, anchors = next(iter(by_domain.items()))
        if len(anchors) < minimum_anchors:
            continue

        # If a collected NetBIOS alias is ambiguous, learning may narrow it
        # only to one of those collected candidates, never invent a third.
        explicit = index["domain_aliases"].get(alias, set())
        if explicit and target_domain not in explicit:
            continue
        learned[alias] = {target_domain}

    index["learned_domain_aliases"] = learned


def _classify(row: dict, index: TargetIndex) -> tuple[Target | None, str]:
    sam = _text(row.get("sam"))
    domain = _text(row.get("domain"))
    upn = _text(row.get("upn"))

    bare_matches = index["bare_sam"].get(_key(sam), []) if sam else []
    upn_matches = index["user_upn"].get(_key(upn), []) if upn else []

    if sam and domain:
        domains, source = _resolved_domains(index, domain)
        scoped_matches = _unique_targets(
            target for fqdn in domains for target in index["scoped_sam"].get((fqdn, _key(sam)), [])
        )

        if len(scoped_matches) == 1:
            scoped = scoped_matches[0]
            if len(upn_matches) == 1 and _target_identity(upn_matches[0]) != _target_identity(
                scoped
            ):
                return None, "ambiguous_conflicting_identifiers"
            return scoped, source if len(domains) == 1 else "domain_candidate"

        if len(scoped_matches) > 1:
            if len(upn_matches) == 1:
                upn_identity = _target_identity(upn_matches[0])
                if any(_target_identity(target) == upn_identity for target in scoped_matches):
                    return upn_matches[0], "upn_disambiguated_domain"
                return None, "ambiguous_conflicting_identifiers"
            return None, "ambiguous_scoped_sam"

        # A real UPN collected on the same NTDS line can safely recover from
        # a missing NetBIOS alias.  If both identifiers resolve, they must
        # agree on the same AD node.
        if len(upn_matches) == 1:
            if bare_matches and all(
                _target_identity(target) != _target_identity(upn_matches[0])
                for target in bare_matches
            ):
                return None, "ambiguous_conflicting_identifiers"
            return upn_matches[0], "upn"
        if len(upn_matches) > 1:
            return None, "ambiguous_upn"

        # The domain label can be absent, stale, or a NetBIOS value not present
        # in an older BloodHound collection.  A SAM found on exactly one AD
        # graph node is unambiguous without contacting the domain.
        if len(bare_matches) == 1:
            return bare_matches[0], "unique_sam_fallback"
        if len(bare_matches) > 1:
            return None, "ambiguous_domain_sam"
        return None, "no_sam_match" if domains else "unknown_domain"

    if upn:
        if len(upn_matches) == 1:
            if bare_matches and all(
                _target_identity(target) != _target_identity(upn_matches[0])
                for target in bare_matches
            ):
                return None, "ambiguous_conflicting_identifiers"
            return upn_matches[0], "upn"
        if len(upn_matches) > 1:
            return None, "ambiguous_upn"
        if not sam:
            return None, "no_upn_match"

    if sam:
        if len(bare_matches) == 1:
            return bare_matches[0], "unique_sam"
        if len(bare_matches) > 1:
            return None, "ambiguous_unscoped_sam"
    return None, "no_identifier_match"


def match_rows(
    rows: Iterable[dict], index: TargetIndex
) -> tuple[list[dict], list[dict], list[dict]]:
    """Resolve rows, returning updates, unmatched rows, and ambiguous rows."""

    rows = list(rows)
    _learn_domain_aliases(rows, index)

    updates_by_target: dict[tuple[str, str], dict] = {}
    unmatched: list[dict] = []
    ambiguous: list[dict] = []

    for row in rows:
        target, reason = _classify(row, index)
        if target is None:
            rejected = dict(row)
            rejected["match_reason"] = reason
            if reason.startswith("ambiguous_"):
                ambiguous.append(rejected)
            else:
                unmatched.append(rejected)
            continue

        update = {
            "kind": target["kind"],
            "objectid": target["objectid"],
            "target_name": target["name"],
            "match_reason": reason,
            "nt": row.get("nt"),
            "pwd": row.get("pwd"),
        }
        key = (target["kind"], target["objectid"].casefold())
        # Rows retain input order, so the last identifier resolving to a node
        # is authoritative even when an older hash happened to be cracked.
        updates_by_target.pop(key, None)
        updates_by_target[key] = update

    return list(updates_by_target.values()), unmatched, ambiguous
