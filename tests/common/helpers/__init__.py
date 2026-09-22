import json


def _pillar_files(pillar_defaults, target, request=None):
    try:
        refresh, pillar_defaults = pillar_defaults[0], pillar_defaults[1]
    except KeyError:
        refresh = True
    if request:
        overrides = getattr(request, "param", {})
        try:
            refresh, overrides = overrides[0], overrides[1]
        except KeyError:
            pass
    else:
        overrides = {}
    defs = pillar_defaults.copy()
    defs.update(overrides)
    if defs and "top" not in defs:
        top = {"base": {target: list(defs)}}
        defs["top"] = top
    files = []
    for sls_name, sls_contents in defs.items():
        files.append((f"{sls_name}.sls", json.dumps(sls_contents).replace("%ID", target)))
    return files, refresh
