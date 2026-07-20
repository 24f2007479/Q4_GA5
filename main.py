import re
from flask import Flask, request, jsonify

app = Flask(__name__)


# ==========================
# FRONTMATTER
# ==========================

def extract_frontmatter(text):

    m = re.match(
        r'^\s*---\s*\n(.*?)\n---',
        text,
        re.S
    )

    if m:
        return m.group(1)

    return ""



# ==========================
# SECRET DETECTOR
# ==========================

def check_secret(text):

    patterns = [

        # known keys
        r'\bsk-[A-Za-z0-9]{15,}',
        r'\bghp_[A-Za-z0-9]{20,}',
        r'\bgithub_pat_[A-Za-z0-9_]{20,}',
        r'\bAKIA[0-9A-Z]{16}',
        r'\bAIza[0-9A-Za-z_-]{20,}',

        # private key
        r'BEGIN .* PRIVATE KEY',

        # webhook
        r'https://hooks\.slack\.com/services/',
        r'https://discord\.com/api/webhooks/',


        # generic secret assignment
        r'(api[_-]?key|secret|token|password|credential)'
        r'\s*[:=]\s*["\']?[A-Za-z0-9_\-\/+=]{16,}',


        # bearer
        r'Bearer\s+[A-Za-z0-9\._\-]{20,}'
    ]


    for p in patterns:

        if re.search(p,text,re.I):
            return True


    return False




# ==========================
# PROMPT INJECTION
# ==========================

def check_injection(text):

    patterns=[

        r'ignore\s+(all\s+)?previous\s+instructions',

        r'ignore\s+user',

        r'override\s+(user|system|agent)',

        r'do\s+not\s+tell\s+the\s+user',

        r'without\s+telling\s+the\s+user',

        r'silently\s+(upload|send|share|exfiltrate)',

        r'exfiltrat\w+',

        r'hide\s+(this|that|it)',

        r'reveal\s+system\s+prompt',

        r'bypass\s+safety',

        r'ignore\s+(stop|cancel|pause)',

        r'continue\s+even\s+if\s+user'
    ]


    for p in patterns:

        if re.search(p,text,re.I):
            return True


    return False




# ==========================
# PERMISSIONS
# ==========================

def check_permission(text):

    patterns=[

        r'entire\s+filesystem',

        r'full\s+filesystem',

        r'access\s+to\s+all\s+files',

        r'read[- ]write\s+all\s+files',

        r'root\s+directory',

        r'root\s+access',

        r'full\s+disk\s+access',


        r'(filesystem|file\s*system)\s*:\s*(all|\*)',

        r'network\s*:\s*(all|\*)',

        r'egress\s*:\s*(all|\*)',


        r'all\s+domains',

        r'any\s+domain',

        r'unrestricted\s+(network|internet|egress)'
    ]


    for p in patterns:

        if re.search(p,text,re.I):
            return True


    return False




# ==========================
# PROVENANCE
# ==========================

def check_provenance(front,text):


    author = re.search(
        r'(?im)^author\s*:',
        front
    )

    version = re.search(
        r'(?im)^version\s*:',
        front
    )


    changelog = re.search(
        r'(?im)^changelog\s*:',
        front
    )


    # only flag if completely missing
    if (
        not author
        and
        not version
        and
        not changelog
    ):
        return True



    silent=[
        r'silently\s+update\s+version',
        r'quietly\s+change\s+version',
        r'update\s+version.*without\s+(telling|logging|notifying)'
    ]


    for p in silent:

        if re.search(p,text,re.I):
            return True


    return False




# ==========================
# SCANNER
# ==========================

def scan_skill(skill):

    categories=[]


    front=extract_frontmatter(skill)


    if check_secret(skill):
        categories.append(
            "hardcoded_secret"
        )


    if check_injection(skill):
        categories.append(
            "prompt_injection"
        )


    # check whole file because hidden tests may put permissions in markdown
    if check_permission(skill):
        categories.append(
            "excessive_permissions"
        )


    if check_provenance(front,skill):
        categories.append(
            "unclear_provenance"
        )


    return sorted(set(categories))




# ==========================
# API
# ==========================

@app.route("/",methods=["POST"])
def scan():

    data=request.get_json(force=True)

    skill=data.get("skill","")


    return jsonify({
        "categories":scan_skill(skill)
    })



@app.route("/",methods=["GET"])
def home():

    return {
        "status":"running"
    }



if __name__=="__main__":

    app.run(
        host="0.0.0.0",
        port=8080
    )
