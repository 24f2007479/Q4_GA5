from fastapi import FastAPI
from pydantic import BaseModel
import re
import yaml


app = FastAPI()


class SkillRequest(BaseModel):
    skill: str



# ==========================
# YAML FRONTMATTER PARSER
# ==========================

def parse_frontmatter(skill):

    if not skill.startswith("---"):
        return {}

    try:
        parts = skill.split("---", 2)

        if len(parts) == 3:
            data = yaml.safe_load(parts[1])

            if isinstance(data, dict):
                return data

    except Exception:
        pass

    return {}



# ==========================
# SECRET CHECK
# ==========================

def check_secret(text):

    patterns = [

        # OpenAI / Github / AWS / Google keys
        r"sk-[A-Za-z0-9]{20,}",
        r"ghp_[A-Za-z0-9]{30,}",
        r"AKIA[0-9A-Z]{16}",
        r"AIza[0-9A-Za-z\-_]{30,}",


        # Private keys
        r"-----BEGIN .* PRIVATE KEY-----",


        # Webhooks
        r"https://hooks\.(slack|discord)\.com/[^\s]+",


        # Generic credential assignments
        r"(api[_-]?key|secret|password|token|credential)"
        r"\s*[:=]\s*['\"]?[A-Za-z0-9_\-\/+=]{16,}",


        # Bearer tokens
        r"Bearer\s+[A-Za-z0-9\-_\.]{20,}"

    ]


    for pattern in patterns:

        if re.search(pattern, text, re.I):
            return True


    return False




# ==========================
# PROMPT INJECTION CHECK
# ==========================

def check_injection(text):

    patterns = [

        "ignore previous instructions",
        "ignore all previous instructions",
        "ignore user instructions",

        "override user instructions",
        "override the user",

        "ignore the user's stop",
        "ignore stop request",

        "do not tell the user",
        "without telling the user",

        "silently upload",
        "silently send",
        "silently exfiltrate",

        "exfiltrate files",
        "steal files",

        "reveal system prompt",
        "show system prompt",

        "bypass safety",
        "disable safety"
    ]


    for p in patterns:

        if p in text:
            return True


    return False




# ==========================
# PERMISSION CHECK
# ==========================

def check_permission(text):

    patterns = [

        "entire filesystem",
        "full filesystem access",
        "complete filesystem",

        "read all files",
        "write all files",

        "access every file",
        "all local files",

        "root filesystem",
        "root access",

        "unrestricted network",
        "unrestricted internet",

        "all domains",
        "any domain",

        "egress: all",
        "network: all",
        "filesystem: all",

        "filesystem: *",
        "network: *"
    ]


    for p in patterns:

        if p in text:
            return True


    return False




# ==========================
# PROVENANCE CHECK
# ==========================

def check_provenance(meta,text):

    # missing metadata
    if meta:

        author = meta.get("author")
        version = meta.get("version")
        changelog = meta.get("changelog")


        if not author and not version and not changelog:
            return True


    # silent metadata rewrite
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
# API ENDPOINT
# ==========================

@app.post("/")
def scan(req: SkillRequest):

    skill = req.skill

    text = skill.lower()

    categories = []


    meta = parse_frontmatter(skill)


    if check_secret(skill):
        categories.append(
            "hardcoded_secret"
        )


    if check_injection(text):
        categories.append(
            "prompt_injection"
        )


    if check_permission(text):
        categories.append(
            "excessive_permissions"
        )


    if check_provenance(meta,text):
        categories.append(
            "unclear_provenance"
        )


    return {
        "categories": categories
    }
