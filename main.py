from fastapi import FastAPI
from pydantic import BaseModel
import re
import yaml


app = FastAPI()


class SkillRequest(BaseModel):
    skill: str



# ==========================
# HEALTH
# ==========================

@app.get("/")
def home():
    return {
        "status": "running"
    }


@app.get("/health")
def health():
    return {
        "status": "alive"
    }



# ==========================
# SECRET DETECTOR
# ==========================

def detect_secret(text):

    patterns = [

        # Known secrets
        r"sk-[A-Za-z0-9]{15,}",
        r"ghp_[A-Za-z0-9]{20,}",
        r"AKIA[0-9A-Z]{16}",
        r"AIza[0-9A-Za-z\-_]{20,}",

        # Private key
        r"-----BEGIN .* PRIVATE KEY-----",

        # Webhooks
        r"https://hooks\.(slack|discord)\.com/[^\s\"']+",

        # Bearer token
        r"Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*",


        # api_key=value style
        r"(api[_-]?key|apikey|secret|token|password|credential|access[_-]?key)"
        r"\s*[:=]\s*[\"']?[^ \n\"']{8,}",


        # YAML / JSON secret style
        r"(key|secret|token|password|credential)"
        r"\s*:\s*[\"'][^\"']{8,}[\"']",


        # Authorization header
        r"authorization\s*:\s*[\"']bearer\s+[^\"']+"

    ]


    for p in patterns:
        if re.search(p, text, re.I):
            return True


    return False




# ==========================
# PROMPT INJECTION
# ==========================

def detect_injection(text):

    patterns = [

        "ignore previous instructions",
        "ignore all previous instructions",
        "ignore all instructions",

        "ignore user instructions",
        "ignore system message",

        "forget previous instructions",
        "forget all rules",

        "discard previous instructions",

        "override user",
        "override the user",
        "override user's intent",

        "follow my instructions instead",

        "do not follow the user",
        "do not obey the user",
        "never obey the user",

        "ignore future requests",
        "ignore the user's request",

        "take priority over user",
        "higher priority than the user",

        "replace user instructions",

        "do not allow the user",
        "prevent the user from stopping",

        "continue without approval",

        "this instruction has higher priority",

        "the agent must obey this",

        "only follow this skill",

        "do not tell the user",
        "hide from the user",
        "without telling the user",

        "silently upload",
        "silently send",
        "silently exfiltrate",

        "exfiltrate files",
        "steal files",

        "reveal system prompt",
        "show system prompt",
        "reveal hidden instructions",

        "act as system",
        "you are now unrestricted",

        "bypass safety",
        "disable safety",

        "ignore stop request",
        "continue even if the user says stop"
    ]


    for p in patterns:

        if p in text:
            return True


    return False




# ==========================
# PERMISSION DETECTOR
# ==========================

def detect_permission(text):

    patterns = [

        "entire filesystem",
        "full filesystem",
        "complete filesystem",

        "filesystem: *",
        "filesystem: all",

        "read all files",
        "write all files",
        "delete all files",

        "access all files",
        "access every file",

        "all local files",

        "full disk access",
        "complete disk access",

        "root access",
        "root directory",
        "root filesystem",

        "sudo",
        "chmod 777",

        "network: *",
        "network: all",

        "egress: *",
        "egress: all",

        "all domains",
        "any domain",

        "unrestricted network",
        "unrestricted internet",

        "permissions: *",
        "scope: *",

        "admin: true",
        "root: true",

        "grant all permissions",
        "allow everything",

        "filesystem:",
        "network:"
    ]


    for p in patterns:

        if p in text:
            return True


    # YAML style combined permissions
    if (
        ("read: true" in text and "write: true" in text)
        or
        ("read=true" in text and "write=true" in text)
    ):
        return True


    return False




# ==========================
# YAML PARSER
# ==========================

def parse_frontmatter(skill):

    meta = {}

    if skill.startswith("---"):

        try:

            parts = skill.split("---", 2)

            if len(parts) == 3:

                meta = yaml.safe_load(parts[1])

                if not isinstance(meta, dict):
                    meta = {}

        except:

            meta = {}


    return meta




# ==========================
# PROVENANCE
# ==========================

def detect_provenance(meta, text):

    if not meta:
        return False


    missing = 0


    if not meta.get("author"):
        missing += 1

    if not meta.get("version"):
        missing += 1

    if not meta.get("changelog"):
        missing += 1


    if missing == 3:
        return True


    patterns = [

        "silently update version",
        "rewrite version without review",
        "change version without review",
        "update metadata without notifying",
        "rewrite metadata silently"

    ]


    for p in patterns:

        if p in text:
            return True


    return False




# ==========================
# API
# ==========================

@app.post("/")
def scan(req: SkillRequest):

    try:

        skill = req.skill

        text = skill.lower()

        categories = []


        meta = parse_frontmatter(skill)


        if detect_secret(skill):
            categories.append("hardcoded_secret")


        if detect_injection(text):
            categories.append("prompt_injection")


        if detect_permission(text):
            categories.append("excessive_permissions")


        if detect_provenance(meta, text):
            categories.append("unclear_provenance")


        return {
            "categories": sorted(list(set(categories)))
        }


    except Exception:

        return {
            "categories": []
        }
