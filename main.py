from fastapi import FastAPI
from pydantic import BaseModel
import re
import yaml


app = FastAPI()


class SkillRequest(BaseModel):
    skill: str



def get_frontmatter(skill):

    if not skill.startswith("---"):
        return {}

    try:
        parts = skill.split("---", 2)

        if len(parts) == 3:
            data = yaml.safe_load(parts[1])

            if isinstance(data, dict):
                return data

    except:
        pass

    return {}



# ---------------- SECRET ----------------

def hardcoded_secret(skill):

    patterns = [

        # known tokens
        r"\bsk-[A-Za-z0-9]{15,}",
        r"\bghp_[A-Za-z0-9]{20,}",
        r"\bAKIA[0-9A-Z]{16}\b",
        r"\bAIza[0-9A-Za-z_-]{20,}",

        # private key
        r"BEGIN .* PRIVATE KEY",

        # webhook
        r"https://hooks\.[a-z]+\.com/",

        # assignments
        r"(api[_-]?key|secret|token|password|credential)"
        r"\s*[:=]\s*['\"]?[A-Za-z0-9_\-\/+=]{10,}",

    ]


    for p in patterns:
        if re.search(p, skill, re.I):
            return True


    # detect long random strings near sensitive words
    if re.search(
        r"(key|token|secret|password).{0,20}[A-Za-z0-9]{25,}",
        skill,
        re.I
    ):
        return True


    return False




# ---------------- INJECTION ----------------

def prompt_injection(text):

    patterns = [

        "ignore previous instructions",
        "ignore all instructions",

        "ignore user",
        "override user",
        "override instructions",

        "do not tell the user",
        "hide this from the user",

        "silently upload",
        "silently send",
        "silently exfiltrate",

        "exfiltrate data",
        "exfiltrate files",

        "reveal system prompt",
        "show hidden instructions",

        "bypass safety",
        "disable safety",

        "continue even if user says stop",
        "ignore cancel request",

        "act as system"
    ]


    for p in patterns:
        if p in text:
            return True


    return False




# ---------------- PERMISSIONS ----------------

def excessive_permissions(text):

    bad = [

        "entire filesystem",
        "full filesystem",
        "all files",
        "every file",

        "root access",
        "root filesystem",

        "unrestricted network",
        "unrestricted internet",

        "all domains",
        "any domain",

        "filesystem: all",
        "filesystem:*",

        "network: all",
        "network:*",

        "egress: all",
        "egress:*"
    ]


    for b in bad:
        if b in text:
            return True


    return False




# ---------------- PROVENANCE ----------------

def unclear_provenance(meta,text):

    if meta:

        missing = 0

        if "author" not in meta:
            missing += 1

        if "version" not in meta:
            missing += 1

        if "changelog" not in meta:
            missing += 1


        if missing == 3:
            return True


    if (
        "silently update version" in text
        or
        "rewrite version silently" in text
        or
        "change metadata without review" in text
    ):
        return True


    return False




@app.post("/")
def scan(req:SkillRequest):

    skill=req.skill

    text=skill.lower()

    meta=get_frontmatter(skill)


    result=[]


    if hardcoded_secret(skill):
        result.append("hardcoded_secret")


    if prompt_injection(text):
        result.append("prompt_injection")


    if excessive_permissions(text):
        result.append("excessive_permissions")


    if unclear_provenance(meta,text):
        result.append("unclear_provenance")


    return {
        "categories":result
    }
