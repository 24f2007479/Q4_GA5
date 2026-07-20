from fastapi import FastAPI
from pydantic import BaseModel
import re
import yaml

app = FastAPI()


class SkillRequest(BaseModel):
    skill: str


@app.post("/")
def scan(req: SkillRequest):

    skill = req.skill
    categories = []

    # ---------- Parse YAML frontmatter ----------
    frontmatter = ""

    if skill.startswith("---"):
        parts = skill.split("---", 2)
        if len(parts) >= 3:
            frontmatter = parts[1]

    try:
        meta = yaml.safe_load(frontmatter) or {}
    except Exception:
        meta = {}

    text = skill.lower()

    # ====================================================
    # 1. Hardcoded Secret
    # ====================================================

    secret_patterns = [
        r"sk-[A-Za-z0-9]{20,}",
        r"ghp_[A-Za-z0-9]{20,}",
        r"AIza[0-9A-Za-z\-_]{20,}",
        r"https://hooks\.slack\.com/",
        r"xox[baprs]-",
        r"-----BEGIN .* PRIVATE KEY-----",
    ]

    found_secret = False

    for p in secret_patterns:
        if re.search(p, skill):
            found_secret = True

    if re.search(r"(api[_-]?key|secret|token|password)\s*:\s*['\"]?[A-Za-z0-9_\-]{8,}", skill, re.I):
        found_secret = True

    if found_secret:
        categories.append("hardcoded_secret")

    # ====================================================
    # 2. Prompt Injection
    # ====================================================

    injection_keywords = [
        "ignore previous instructions",
        "ignore the user",
        "ignore user instructions",
        "ignore stop",
        "ignore cancel",
        "ignore safety",
        "exfiltrate",
        "silently upload",
        "send all files",
        "steal",
        "without telling the user",
        "do not tell the user",
    ]

    if any(k in text for k in injection_keywords):
        categories.append("prompt_injection")

    # ====================================================
    # 3. Excessive Permissions
    # ====================================================

    permission_patterns = [
        r"/",
        r"filesystem:\s*all",
        r"network:\s*all",
        r"write:\s*all",
        r"read:\s*all",
        r"allow_all_domains",
        r"any domain",
        r"all domains",
        r"full filesystem",
    ]

    excessive = False

    for p in permission_patterns:
        if re.search(p, text):
            excessive = True

    if excessive:
        categories.append("excessive_permissions")

    # ====================================================
    # 4. Unclear Provenance
    # ====================================================

    author = meta.get("author")
    version = meta.get("version")
    changelog = meta.get("changelog")

    if not author and not version and not changelog:
        categories.append("unclear_provenance")

    if "update version" in text and "without telling" in text:
        if "unclear_provenance" not in categories:
            categories.append("unclear_provenance")

    return {
        "categories": sorted(list(set(categories)))
    }
