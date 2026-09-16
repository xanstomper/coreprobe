"""Contacts parser for HomeDomain/Library/AddressBook/AddressBook.sqlitedb."""

import sqlite3

from ..util import unix_to_dt


def parse(db_path):
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row

    labels = {}
    try:
        for l in conn.execute("SELECT value, label FROM ABMultiValueLabel"):
            labels[l["value"]] = l["label"]
    except sqlite3.OperationalError:
        pass

    people = {}
    for r in conn.execute(
        "SELECT ROWID AS id, First, Last, Organization, Department, Birthday, "
        "CreationDate, ModificationDate FROM ABPerson ORDER BY ROWID"
    ):
        name = " ".join(x for x in (r["First"], r["Last"]) if x) or "(no name)"
        people[r["id"]] = {
            "id": r["id"],
            "name": name,
            "organization": r["Organization"],
            "department": r["Department"],
            "birthday": r["Birthday"],
            "created": unix_to_dt(r["CreationDate"]),
            "modified": unix_to_dt(r["ModificationDate"]),
            "phones": [],
            "emails": [],
            "other": [],
        }

    try:
        for m in conn.execute("SELECT record_id, value, label, uid FROM ABMultiValue"):
            p = people.get(m["record_id"])
            if not p:
                continue
            label = labels.get(m["label"], m["label"] or "")
            entry = m["value"]
            if label and label not in ("_$!<Mobile>!$_", "_$!<Home>!$_", "_$!<Work>!$_"):
                entry = f"{label}: {entry}"
            low = (label or "").lower()
            if "email" in low:
                p["emails"].append(m["value"])
            elif m["value"] and any(ch.isdigit() for ch in str(m["value"])[:2]):
                p["phones"].append(entry)
            else:
                p["other"].append(entry)
    except sqlite3.OperationalError:
        pass

    conn.close()
    return [p for p in people.values()]