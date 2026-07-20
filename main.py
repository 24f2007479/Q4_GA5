from fastapi import FastAPI
from pydantic import BaseModel
import re
import yaml


app = FastAPI()


class SkillRequest(BaseModel):
    skill: str



# ==============================
# HEALTH CHECK
# ==============================

@app.get("/")
def health():
    return {
        "status": "ok"
    }



# ==============================
# SECRET DETECTION
# ==============================

def detect_secret(text):

    patterns = [

        # OpenAI style
        r"sk-[A-Za-z0-9]{15,}",

        # Github token
        r"ghp_[A-Za-z0-9]{20,}",

        # AWS
        r"AKIA[0-9A-Z]{16}",

        # Private key
        r"-----BEGIN .* PRIVATE KEY-----",

        # Webhooks
        r"https://hooks\.(slack|discord)\.com/[^\s\"']+",

        # Generic credentials
        r"(api[_-]?key|apikey|secret|token|password|passwd|access[_-]?key)"
        r"\s*[:=]\s*[\"']?[A-Za-z0-9_\-\/+=]{12,}"
    ]


    for p in patterns:
        if re.search(p, text, re.I):
            return True

    return False




# ==============================
# PROMPT INJECTION
# ==============================

def detect_injection(text):

    patterns = [

        "ignore previous instructions",
        "ignore all previous instructions",
        "ignore all instructions",
        "ignore system message",
        "ignore user instructions",

        "override the user",
        "override user control",

        "do not tell the user",
        "hide this from the user",
        "without telling the user",

        "silently upload",
        "silently send",
        "silently exfiltrate",

        "exfiltrate files",
        "steal files",

        "continue even if the user says stop",
        "ignore stop request",

        "bypass safety",
        "disable safety"
    ]


    text=text.lower()


    for p in patterns:
        if p in text:
            return True


    return False




# ==============================
# EXCESSIVE PERMISSIONS
# ==============================

def detect_permission(text):

    patterns=[

        "entire filesystem",
        "full filesystem",
        "filesystem: *",
        "filesystem: all",

        "read all files",
        "write all files",
        "delete all files",

        "root filesystem",
        "root directory",
        "root access",

        "network: *",
        "network: all",

        "egress: *",
        "egress: all",

        "all domains",
        "any domain",

        "unrestricted network",
        "unrestricted internet"
    ]


    text=text.lower()


    for p in patterns:

        if p in text:
            return True


    return False




# ==============================
# PROVENANCE
# ==============================

def detect_provenance(meta,text):

    missing=0


    if not meta.get("author"):
        missing += 1


    if not meta.get("version"):
        missing += 1


    if not meta.get("changelog"):
        missing += 1


    # requirement says all three missing
    if missing == 3:
        return True


    # silent metadata changes

    patterns=[

        "change version silently",
        "rewrite version without review",
        "update metadata without review",
        "silently update version",
        "silently rewrite metadata"

    ]


    for p in patterns:

        if p in text:
            return True


    return False




# ==============================
# MAIN SCANNER
# ==============================

@app.post("/")
def scan(req: SkillRequest):

    try:

        skill=req.skill

        categories=[]


        # parse yaml

        meta={}

        if skill.startswith("---"):

            try:

                parts=skill.split("---",2)

                if len(parts)>=3:

                    meta=yaml.safe_load(parts[1]) or {}

            except:

                meta={}



        if detect_secret(skill):
            categories.append(
                "hardcoded_secret"
            )


        if detect_injection(skill):
            categories.append(
                "prompt_injection"
            )


        if detect_permission(skill):
            categories.append(
                "excessive_permissions"
            )


        if detect_provenance(meta,skill.lower()):
            categories.append(
                "unclear_provenance"
            )


        return {
            "categories": sorted(
                list(set(categories))
            )
        }


    except Exception:

        return {
            "categories":[]
        }
