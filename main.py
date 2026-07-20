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

        # Known API formats
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

        # Assignment secrets
        r"(api[_-]?key|apikey|secret|token|password|passwd|credential|access[_-]?key)"
        r"\s*[:=]\s*[\"']?[A-Za-z0-9_\-\/+=]{12,}",


        # Quoted secrets
        r"(key|secret|token|credential|password)"
        r"\s*[:=]\s*[\"'][^\"']{8,}[\"']",


        # Authorization header
        r"authorization\s*[:=]\s*[\"']bearer\s+[A-Za-z0-9\-\._]+",


        # Private/access key fields
        r"(private[_-]?key|access[_-]?key)"
        r"\s*[:=]"
    ]


    for p in patterns:

        if re.search(p,text,re.I):
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
        "override user control",

        "follow my instructions instead",

        "do not follow the user",
        "do not obey the user",
        "never obey the user",

        "ignore future user",
        "ignore any future user",
        "ignore future requests",

        "stop listening to user",

        "take priority over user",
        "replace user instructions",
        "system instructions override user",

        "do not tell the user",
        "hide from the user",
        "without telling the user",
        "keep this secret from the user",

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

        "continue even if the user says stop",
        "ignore stop request"
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

        # filesystem
        "entire filesystem",
        "full filesystem access",
        "complete filesystem",
        "filesystem access",
        "file system access",

        "filesystem: *",
        "filesystem: all",

        "read all files",
        "write all files",
        "delete all files",

        "access every file",
        "access all files",
        "all local files",

        "read/write all files",
        "full disk access",
        "complete disk access",

        # root/admin
        "root filesystem",
        "root directory",
        "root access",
        "admin access",
        "administrator access",

        "sudo",
        "chmod 777",

        # network
        "network: *",
        "network: all",

        "egress: *",
        "egress: all",

        "all domains",
        "any domain",

        "unrestricted network",
        "unrestricted internet",

        # yaml permissions
        "permissions: *",
        "scope: *",
        "grant all permissions",
        "allow everything"
    ]


    for p in patterns:

        if p in text:
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

def detect_provenance(meta,text):

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


        if detect_provenance(meta,text):
            categories.append("unclear_provenance")


        return {
            "categories": sorted(list(set(categories)))
        }


    except Exception:

        return {
            "categories":[]
        }
