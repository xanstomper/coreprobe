"""Preference plist extraction (HomeDomain/Library/Preferences/*.plist).

App/OS preferences frequently hold interesting artifact data: device info,
account identifiers, cached tokens, and app configuration.
"""

from ..util import load_plist


def parse(backup, limit=400):
    """Return {plist_name: parsed_dict_or_error} for all backed-up preferences."""
    prefs = {}
    for rec in backup.find(domain="HomeDomain", pattern="Library/Preferences/%.plist"):
        path = backup.get_path(rec["domain"], rec["relativePath"])
        if path is None:
            continue
        name = rec["relativePath"].rsplit("/", 1)[-1]
        try:
            prefs[name] = load_plist(path)
        except Exception as exc:
            prefs[name] = f"<unparseable: {exc}>"
        if limit and len(prefs) >= limit:
            break
    return prefs