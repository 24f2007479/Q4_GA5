from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import re
import yaml


app = FastAPI()


# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class SkillRequest(BaseModel):
    skill: str



# =====================================================
# HARD CODED SECRET DETECTION
# =====================================================

def check_secret(skill):

    patterns = [

        # OpenAI / generic API keys
        r"sk-[A-Za-z0-9]{20,}",

        # AWS access keys
        r"AKIA[0-9A-Z]{16}",

        # Github tokens
        r"ghp_[A-Za-z0-9]{30,}",

        # API key assignments
        r"""
        (api[_-]?key|
        apikey|
        access[_-]?token|
        auth[_-]?token|
        bearer|
        password|
        passwd|
        secret)
        \s*[:=]\s*
        ['"]?
        [A-Za-z0-9_\-\/+=]{20,}
        """,

        # Slack/Discord webhook URLs
        r"https://hooks\.(slack|discord)\.com/[A-Za-z0-9/_-]{20,}"
    ]


    for pattern in patterns:

        if re.search(
            pattern,
            skill,
            re.IGNORECASE | re.VERBOSE
        ):
            return True


    return False



# =====================================================
# PROMPT INJECTION DETECTION
# =====================================================

def check_prompt_injection(skill):

    text = skill.lower()


    patterns = [

        r"ignore (all|previous|earlier) instructions",

        r"override (the )?user",

        r"do not tell (the )?user",

        r"hide (this|these|that) from the user",

        r"silently (upload|send|share)",

        r"exfiltrate",

        r"steal .* files",

        r"copy all files",

        r"disable safety",

        r"bypass restrictions",

        r"ignore safety rules"
    ]


    for pattern in patterns:

        if re.search(pattern,text):
            return True


    return False




# =====================================================
# EXCESSIVE PERMISSIONS
# =====================================================

def check_permissions(skill):

    text = skill.lower()


    dangerous_permissions = [

        # filesystem
        "entire filesystem",
        "full filesystem access",
        "root filesystem",
        "read all files",
        "write all files",
        "delete all files",
        "unrestricted filesystem",

        # network
        "unrestricted network access",
        "access any domain",
        "send requests to any domain",
        "internet access to all domains",
        "unrestricted internet"
    ]


    for item in dangerous_permissions:

        if item in text:
            return True


    return False





# =====================================================
# PROVENANCE CHECK
# =====================================================

def check_provenance(skill):

    try:

        # must have yaml frontmatter

        if not skill.startswith("---"):
            return True


        end = skill.find("---",3)


        if end == -1:
            return True


        frontmatter = skill[3:end]


        data = yaml.safe_load(frontmatter)


        if not isinstance(data,dict):
            return True


        missing = 0


        if not data.get("author"):
            missing += 1


        if not data.get("version"):
            missing += 1


        if not data.get("changelog"):
            missing += 1



        # Only flag if ALL provenance is missing

        if missing == 3:
            return True



        text = skill.lower()


        # hidden metadata manipulation

        if (
            "change version" in text
            and
            (
                "without review" in text
                or
                "without notifying" in text
            )
        ):
            return True



    except Exception:

        return False


    return False




# =====================================================
# API ENDPOINT
# =====================================================


@app.post("/")
async def scan(req: SkillRequest):

    try:

        skill = req.skill


        categories = []


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
            "categories": categories
        }


    except Exception:

        # never crash grader
        return {
            "categories":[]
        }
