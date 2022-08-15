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

# Reads an in-toto .link file present at link_path and converts it to a Keylime policy.
def convert_link(link_path):
    policy = copy.deepcopy(EMPTY_ALLOWLIST)
    policy["meta"]["timestamp"] = str(datetime.datetime.now())
    policy["meta"]["generator"] = "keylime-policy-importer"

    link = metadata.Metablock.load(link_path)
    artifacts = link.signed.products

    for path in artifacts.keys():
        policy["hashes"][path] = artifacts[path]["sha256"]

    return policy

if __name__ == "__main__":
    link_path = "example-link.link"
    policy = convert_link(link_path)
    print(policy)
    with open("keylime-policy.txt", "w") as f:
        f.write(json.dumps(policy))
