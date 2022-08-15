import copy
import datetime
import json
from in_toto.models import metadata

# hardcoded constants - should eventually be referenced from Keylime
ALLOWLIST_CURRENT_VERSION = 5
EMPTY_ALLOWLIST = {
    "meta": {
        "version": ALLOWLIST_CURRENT_VERSION,
    },
    "release": 0,
    "hashes": {},
    "keyrings": {},
    "ima": {"ignored_keyrings": [], "log_hash_alg": "sha1"},
}

# Converts legacy allowlists to new JSON format.
def convert_legacy_allowlist(allowlist_path):
    with open(allowlist_path, "r") as f:
        alist_raw = f.read()

    alist = copy.deepcopy(EMPTY_ALLOWLIST)
    alist["meta"]["timestamp"] = str(datetime.datetime.now())
    alist["meta"]["generator"] = "keylime-legacy-format-upgrade"

    for line in alist_raw.splitlines():
        line = line.strip()
        if len(line) == 0:
            continue

        pieces = line.split(None, 1)
        if not len(pieces) == 2:
            print("Line in Allowlist does not consist of hash and file path: %s", line)
            continue

        (checksum_hash, path) = pieces

        if path.startswith("%keyring:"):
            entrytype = "keyrings"
            path = path[len("%keyring:") :]  # remove leading '%keyring:' from path to get keyring name
        else:
            entrytype = "hashes"

        if path in alist[entrytype]:
            alist[entrytype][path].append(checksum_hash)
        else:
            alist[entrytype][path] = [checksum_hash]
    return alist

# Reads an in-toto .link file present at link_path and converts it to a Keylime
# policy, or appends to an existing policy if provided.
def convert_link(link_path, policy=None):
    if not policy:
        policy = copy.deepcopy(EMPTY_ALLOWLIST)
        policy["meta"]["timestamp"] = str(datetime.datetime.now())
        policy["meta"]["generator"] = "keylime-policy-importer"

    link = metadata.Metablock.load(link_path)
    artifacts = link.signed.products

    for path in artifacts.keys():
        entrytype = "hashes"
        hash = artifacts[path]["sha256"]
        if path in policy[entrytype]:
            policy[entrytype][path].append(hash)
        else:
            policy[entrytype][path] = [hash]

    return policy

if __name__ == "__main__":
    link_path = "artifacts/example-link.link"
    policy = convert_link(link_path, policy=convert_legacy_allowlist("artifacts/allowlist.txt"))
    print(json.dumps(policy))
    with open("keylime-policy.txt", "w") as f:
        f.write(json.dumps(policy))
