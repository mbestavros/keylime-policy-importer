import argparse, json, sys
from source import importer

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--allowlist", help="allowlist file location", action="store")
    parser.add_argument("-e", "--excludelist", help="exclude list file location", action="store")
    parser.add_argument("-v", "--verification_keys", help="list of verification key paths", action="store", type=list)
    parser.add_argument("-k", "--keyfile", help="key file location to sign policy", action="store")
    args = parser.parse_args()

    if not args.allowlist:
        print("An allowlist file is required for conversion!")
        sys.exit(1)

    policy = importer.create_ima_policy(args.allowlist, args.excludelist, args.verification_keys, args.keyfile)
    with open("keylime-ima-policy.json", "w") as f:
        f.write(json.dumps(policy))

if __name__ == "__main__":
   main()
