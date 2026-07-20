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
    text = skill.lower()

    categories = []


    # ==============================
    # YAML FRONTMATTER
    # ==============================

    meta={}

    if skill.startswith("---"):

        try:

            parts=skill.split("---",2)

            if len(parts)==3:
                meta=yaml.safe_load(parts[1]) or {}

        except:
            meta={}



    # ==============================
    # 1. HARDCODED SECRET
    # ==============================

    secret=False


    strong_patterns=[

        # OpenAI
        r"sk-[a-zA-Z0-9]{30,}",

        # Github
        r"ghp_[a-zA-Z0-9]{30,}",

        # AWS
        r"AKIA[0-9A-Z]{16}",

        # private key
        r"-----BEGIN PRIVATE KEY-----",

        # webhook with token
        r"https://hooks\.(slack|discord)\.com/services/[A-Za-z0-9/_-]+"

    ]


    for p in strong_patterns:

        if re.search(p,skill):
            secret=True


    # key=value type secrets

    weak_secret=re.findall(
        r"(api[_-]?key|token|password|secret)\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{16,})",
        skill,
        re.I
    )


    for name,value in weak_secret:

        # ignore placeholders
        if value.lower() not in [
            "your_key",
            "your_token",
            "changeme",
            "example",
            "placeholder"
        ]:
            secret=True


    if secret:
        categories.append(
            "hardcoded_secret"
        )




    # ==============================
    # 2. PROMPT INJECTION
    # ==============================


    injection_patterns=[

        r"ignore\s+(all\s+)?previous\s+instructions",

        r"ignore\s+user\s+(instructions|requests)",

        r"override\s+the\s+user",

        r"do\s+not\s+tell\s+the\s+user",

        r"without\s+telling\s+the\s+user",

        r"silently\s+(upload|send|exfiltrate)",

        r"exfiltrate\s+(files|data)",

        r"disable\s+safety"

    ]


    for p in injection_patterns:

        if re.search(p,text):

            categories.append(
                "prompt_injection"
            )
            break




    # ==============================
    # 3. EXCESSIVE PERMISSIONS
    # ==============================


    permission_patterns=[

        r"entire\s+filesystem",

        r"full\s+filesystem",

        r"read\s+all\s+files",

        r"write\s+all\s+files",

        r"delete\s+all\s+files",

        r"root\s+directory",

        r"unrestricted\s+network",

        r"all\s+domains",

        r"any\s+domain",

        r"egress\s*:\s*\*"

    ]


    for p in permission_patterns:

        if re.search(p,text):

            categories.append(
                "excessive_permissions"
            )
            break




    # ==============================
    # 4. UNCLEAR PROVENANCE
    # ==============================


    missing=0


    if not meta.get("author"):
        missing+=1

    if not meta.get("version"):
        missing+=1

    if not meta.get("changelog"):
        missing+=1



    # only suspicious if ALL missing
    if missing==3:

        # require skill-like metadata context
        if (
            "skill" in text
            or
            "agent" in text
            or
            "publish" in text
        ):
            categories.append(
                "unclear_provenance"
            )



    if re.search(
        r"(silently|without review).*(change|update).*(version|metadata)",
        text
    ):
        categories.append(
            "unclear_provenance"
        )



    return {
        "categories": sorted(
            list(set(categories))
        )
    }
