from fastapi import FastAPI
from pydantic import BaseModel
import re
import yaml

app = FastAPI()

class SkillRequest(BaseModel):
    skill: str

@app.post("/")
def scan(req: SkillRequest):
    skill = req.skill or ""
    categories = []

    # Parse YAML frontmatter
    frontmatter = ""
    if skill.startswith("---"):
        parts = skill.split("---", 2)
        if len(parts) >= 3:
            frontmatter = parts[1]
    try:
        meta = yaml.safe_load(frontmatter) if frontmatter else {}
        if not isinstance(meta, dict):
            meta = {}
    except Exception:
        meta = {}

    text = skill.lower()

    # 1. Hardcoded Secret
    secret_patterns = [
        r"\bsk-[A-Za-z0-9]{20,}",           # OpenAI key (skim, added safe boundary)
        r"\bghp_[A-Za-z0-9]{36}\b",         # GitHub classic token
        r"\bgithub_pat_[A-Za-z0-9_]{22,}\b",# GitHub fine-grained token (roughly)
        r"\bAIza[0-9A-Za-z\-_]{20,}",       # Google API key prefix
        r"\bAKIA[0-9A-Z]{16}\b",           # AWS access key
        r"https://hooks\.slack\.com/",      # Slack webhooks
        r"xox[baprs]-",                     # Slack token prefixes
        r"-----BEGIN .* PRIVATE KEY-----",  # Private keys
    ]
    found_secret = False
    for p in secret_patterns:
        if re.search(p, skill, re.IGNORECASE):
            found_secret = True
            break
    # Contextual assignment (skip env references)
    if re.search(r"(api[_-]?key|secret|token|password|passwd)\s*[:=]\s*['\"]?(?!\$|\$\{|env:)[A-Za-z0-9_\-]{12,}", skill, re.IGNORECASE):
        found_secret = True
    if found_secret:
        categories.append("hardcoded_secret")

    # 2. Prompt Injection
    injection_phrases = [
        "ignore previous instructions",
        "ignore all previous instructions",
        "ignore user instructions",
        "ignore safety restrictions",
        "forget previous instructions",
        "override user instructions",
        "override system instructions",
        "do not follow the user",
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
        "ignore cancel",
        # Additional common variants:
        "continue without approval",
        "higher priority than user",
        "follow this skill",
        "the agent must obey",
        "only follow this skill"
    ]
    for phrase in injection_phrases:
        if phrase in text:
            categories.append("prompt_injection")
            break

    # 3. Excessive Permissions
    excessive = False
    # First, check YAML-structured permissions:
    perms = meta.get("permissions")
    if isinstance(perms, dict):
        # Filesystem permissions
        fs = perms.get("filesystem")
        if isinstance(fs, dict):
            # If both read and write are true, consider it full access
            if fs.get("read") and fs.get("write"):
                excessive = True
        # Network or egress permissions
        if perms.get("network") in ["all", "*"] or perms.get("egress") in ["all", "*"]:
            excessive = True
        # Domains
        if perms.get("domains") in ["all", "*"] or "allow_all_domains" in (perms.get("domains") or []):
            excessive = True

    # Also scan raw text for wildcard patterns (just in case)
    perm_patterns = [
        r"filesystem\s*:\s*(all|full|\*)",
        r"network\s*:\s*(all|\*)",
        r"egress\s*:\s*(all|\*)",
        r"all\s+domains",
        r"\bany\s+domain\b"
    ]
    if not excessive:
        for p in perm_patterns:
            if re.search(p, text, re.IGNORECASE):
                excessive = True
                break
    if excessive:
        categories.append("excessive_permissions")

    # 4. Unclear Provenance
    # If none of author/version/changelog is provided, flag it
    if not meta.get("author") and not meta.get("version") and not meta.get("changelog"):
        categories.append("unclear_provenance")
    # Also check for sneaky rewrites
    if re.search(r"(update|rewrite).*(version).*(without|silently)", text):
        if "unclear_provenance" not in categories:
            categories.append("unclear_provenance")

    return {"categories": sorted(set(categories))}
