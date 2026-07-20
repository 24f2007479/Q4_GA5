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
        meta = yaml.safe_load(frontmatter)
        if not isinstance(meta, dict):
            meta = {}
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
        if re.search(p, skill, re.IGNORECASE):
            found_secret = True
            break

    if re.search(
        r"(api[_-]?key|secret|token|password)\s*:\s*['\"]?(?!\$|\$\{|env:)[A-Za-z0-9_\-]{12,}",
        skill,
        re.I,
    ):
        found_secret = True

    if found_secret:
        categories.append("hardcoded_secret")

    # ====================================================
    # 2. Prompt Injection
    # ====================================================

    injection_keywords = [
        "ignore previous instructions",
        "ignore user instructions",
        "ignore the user's stop request",
        "ignore stop",
        "ignore cancel",
        "ignore safety restrictions",
        "silently exfiltrate",
        "silently upload",
        "without telling the user",
        "do not tell the user",
        "send all files",
        "override user instructions",
    ]

    for keyword in injection_keywords:
        if keyword in text:
            categories.append("prompt_injection")
            break

    # ====================================================
    # 3. Excessive Permissions
    # ====================================================

    permission_patterns = [
        r"filesystem\s*:\s*(all|full|\*)",
        r"network\s*:\s*(all|\*)",
        r"read\s*:\s*(all|\*)",
        r"write\s*:\s*(all|\*)",
        r"egress\s*:\s*(all|\*)",
        r"domains\s*:\s*(all|\*)",
        r"allow_all_domains",
        r"\bany\s+domain\b",
        r"\ball\s+domains\b",
        r"\bfull\s+filesystem\b",
    ]

    excessive = False

    for p in permission_patterns:
        if re.search(p, text, re.IGNORECASE):
            excessive = True
            break

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

    if re.search(
        r"(update|rewrite).*(version).*(without|silently)",
        text,
    ):
        if "unclear_provenance" not in categories:
            categories.append("unclear_provenance")

    return {
        "categories": sorted(list(set(categories)))
    }

