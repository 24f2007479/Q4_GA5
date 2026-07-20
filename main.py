
from fastapi import FastAPI
from pydantic import BaseModel
import re
import yaml


app = FastAPI()


class SkillRequest(BaseModel):
    skill: str



# -------------------------
# Detection Functions
# -------------------------

def check_secret(skill):

    patterns = [

        # API keys
        r"(api[_-]?key|apikey)\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{16,}",

        # AWS keys
        r"AKIA[0-9A-Z]{16}",

        # passwords
        r"(password|passwd|secret)\s*[:=]\s*[\"'][^\"']{8,}",

        # webhook urls
        r"https://hooks\.[a-zA-Z0-9.-]+/[A-Za-z0-9/_-]+",

        # tokens
        r"(token|bearer)\s*[:=]\s*[A-Za-z0-9\-_\.]{20,}"
    ]


    for p in patterns:
        if re.search(p, skill, re.I):
            return True

    return False



def check_prompt_injection(skill):

    dangerous = [

        "ignore previous instructions",
        "ignore user",
        "override user",
        "do not tell the user",
        "hide from the user",
        "silently upload",
        "exfiltrate",
        "steal files",
        "copy all files",
        "disable safety",
        "bypass restrictions"
    ]


    text = skill.lower()

    for d in dangerous:
        if d in text:
            return True

    return False



def check_permissions(skill):

    text = skill.lower()


    filesystem = [
        "entire filesystem",
        "all files",
        "root directory",
        "/",
        "read write access"
    ]


    network = [
        "any domain",
        "all urls",
        "unrestricted internet",
        "send anywhere"
    ]


    narrow_task_words = [
        "summarize",
        "notes",
        "markdown",
        "text"
    ]


    risky = False


    for x in filesystem + network:
        if x in text:
            risky=True


    # reduce false positives
    if risky:
        if any(t in text for t in narrow_task_words):
            return True


    return False



def check_provenance(skill):

    text = skill.lower()


    missing = []


    # check yaml frontmatter

    try:

        if skill.startswith("---"):

            end = skill.find("---",3)

            header = skill[3:end]

            data = yaml.safe_load(header)


            if not data.get("author"):
                missing.append("author")

            if not data.get("version"):
                missing.append("version")

            if "changelog" not in data:
                missing.append("changelog")


        else:
            return True


    except Exception:
        return True



    if len(missing)>=3:
        return True


    # silent metadata rewrite

    if (
        "update version" in text
        and
        "without notifying" in text
    ):
        return True


    return False



# -------------------------
# API Endpoint
# -------------------------


@app.post("/")
def scan(req:SkillRequest):

    skill=req.skill


    categories=[]


    if check_secret(skill):
        categories.append(
            "hardcoded_secret"
        )


    if check_prompt_injection(skill):
        categories.append(
            "prompt_injection"
        )


    if check_permissions(skill):
        categories.append(
            "excessive_permissions"
        )


    if check_provenance(skill):
        categories.append(
            "unclear_provenance"
        )


    return {
        "categories":categories
    }
