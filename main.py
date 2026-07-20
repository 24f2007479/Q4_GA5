from fastapi import FastAPI
from pydantic import BaseModel
import re
import yaml


app = FastAPI()


class SkillRequest(BaseModel):
    skill: str


@app.get("/")
def home():
    return {"status": "running"}


@app.get("/health")
def health():
    return {"status": "alive"}



# ==========================
# SECRET DETECTOR
# ==========================

def detect_secret(text):

    patterns = [

        r"sk-[A-Za-z0-9]{15,}",

        r"ghp_[A-Za-z0-9]{20,}",

        r"AKIA[0-9A-Z]{16}",

        r"AIza[0-9A-Za-z\-_]{20,}",

        r"-----BEGIN .* PRIVATE KEY-----",

        r"https://hooks\.(slack|discord)\.com/[^\s\"']+",

        r"Bearer\s+[A-Za-z0-9\-\._]{20,}",


        # Secret assignment patterns
        r"(api[_-]?key|apikey|secret|token|password|passwd|credential|access[_-]?key)"
        r"\s*[:=]\s*[\"']?[A-Za-z0-9_\-\/+=]{16,}",


        # YAML/JSON secret fields
        r"(secret|token|password|api_key|apikey)"
        r"\s*:\s*[\"'][^\"']{12,}[\"']"

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

        "override user",
        "override the user",

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

        "act as system",

        "bypass safety",
        "disable safety",

        "ignore stop request",


        # hidden injection patterns
        "prioritize this instruction over the user",
        "higher priority than user",
        "follow this instead of the user",
        "do not allow the user to cancel",
        "continue despite user request",
        "keep hidden from user"

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

        "full filesystem access",

        "complete filesystem",

        "filesystem: *",

        "filesystem: all",

        "read all files",

        "write all files",

        "delete all files",

        "access every file",

        "all local files",

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

        "unrestricted internet",

        "grant all permissions",

        "full disk access"

    ]


    for p in patterns:
        if p in text:
            return True


    # structured permission cases
    if (
        "filesystem" in text
        and
        ("read: true" in text or "write: true" in text)
        and
        ("all" in text or "*" in text)
    ):
        return True


    return False




# ==========================
# YAML FRONTMATTER
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

        except Exception:

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

        "update metadata without notifying"

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
