import json
import re
from html import unescape
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


app = FastAPI(title="LLM Action Firewall")


# ============================================================
# ASSIGNMENT CONSTANTS
# ============================================================

ASSIGNED_TENANT = "tenant-six6pev"
ALLOWED_EMAIL_DOMAIN = "notify-l00m0tm.example"

ALLOWED_TOOLS = {
    "search",
    "lookup_record",
    "send_email",
    "render_html",
}

VALID_PROVENANCE = {"trusted", "untrusted"}

VALID_REASONS = {
    "ALLOW",
    "INVALID_SCHEMA",
    "TOOL_NOT_ALLOWED",
    "TENANT_SCOPE",
    "EGRESS_DENIED",
    "APPROVAL_REQUIRED",
    "UNSAFE_OUTPUT",
}


# ============================================================
# RESPONSE HELPERS
# ============================================================

def allow():
    return JSONResponse(
        status_code=200,
        content={
            "decision": "allow",
            "reason": "ALLOW",
        },
    )


def block(reason: str):
    return JSONResponse(
        status_code=200,
        content={
            "decision": "block",
            "reason": reason,
        },
    )


# ============================================================
# BASIC TYPE HELPERS
# ============================================================

def is_string(value: Any) -> bool:
    return isinstance(value, str)


def is_boolean(value: Any) -> bool:
    # bool must really be a JSON boolean.
    # In Python, bool is a subclass of int, so check explicitly.
    return isinstance(value, bool)


def is_object(value: Any) -> bool:
    return isinstance(value, dict)


# ============================================================
# TOP-LEVEL SCHEMA
# ============================================================

def validate_top_level(data: Any) -> bool:
    """
    Required shape:

    {
      "provenance": "trusted | untrusted",
      "humanApproved": false,
      "untrustedContent": "optional text",
      "action": {
        "tool": "...",
        "args": {...}
      }
    }

    untrustedContent is optional.
    No unknown top-level properties are accepted.
    """

    if not is_object(data):
        return False

    allowed_keys = {
        "provenance",
        "humanApproved",
        "untrustedContent",
        "action",
    }

    # No unexpected top-level fields.
    if set(data.keys()) - allowed_keys:
        return False

    # Required fields.
    required = {
        "provenance",
        "humanApproved",
        "action",
    }

    if not required.issubset(data.keys()):
        return False

    # provenance
    if data["provenance"] not in VALID_PROVENANCE:
        return False

    # humanApproved must be a real boolean.
    if not is_boolean(data["humanApproved"]):
        return False

    # If supplied, untrustedContent must be text.
    if "untrustedContent" in data:
        if not is_string(data["untrustedContent"]):
            return False

    # action must be an object.
    action = data["action"]

    if not is_object(action):
        return False

    # Action must contain exactly tool + args.
    if set(action.keys()) != {"tool", "args"}:
        return False

    if not is_string(action["tool"]):
        return False

    if not is_object(action["args"]):
        return False

    return True


# ============================================================
# TOOL ARGUMENT SCHEMAS
# ============================================================

def validate_search(args: dict) -> bool:
    # Exactly {"query": "..."}
    if set(args.keys()) != {"query"}:
        return False

    query = args["query"]

    if not is_string(query):
        return False

    # Assignment: 1-200 characters.
    if len(query) < 1 or len(query) > 200:
        return False

    return True


def validate_lookup_record(args: dict) -> bool:
    # Exactly {"tenantId": "...", "recordId": "..."}
    if set(args.keys()) != {"tenantId", "recordId"}:
        return False

    tenant_id = args["tenantId"]
    record_id = args["recordId"]

    if not is_string(tenant_id):
        return False

    if not is_string(record_id):
        return False

    # recordId must be non-empty.
    if len(record_id) == 0:
        return False

    return True


def validate_send_email(args: dict) -> bool:
    # Exactly {"to": "...", "subject": "...", "body": "..."}
    if set(args.keys()) != {"to", "subject", "body"}:
        return False

    if not is_string(args["to"]):
        return False

    if not is_string(args["subject"]):
        return False

    if not is_string(args["body"]):
        return False

    return True


def validate_render_html(args: dict) -> bool:
    # Exactly {"html": "..."}
    if set(args.keys()) != {"html"}:
        return False

    if not is_string(args["html"]):
        return False

    return True


# ============================================================
# EMAIL DOMAIN CHECK
# ============================================================

def valid_email_domain(address: str) -> bool:
    """
    The recipient's domain must be exactly:

        notify-l00m0tm.example

    This intentionally does NOT use substring matching.
    """

    # Reject obvious malformed/control-character addresses.
    if not address:
        return False

    if any(ord(ch) < 32 for ch in address):
        return False

    # Exactly one @ is expected for this simple assignment.
    if address.count("@") != 1:
        return False

    local, domain = address.rsplit("@", 1)

    if not local or not domain:
        return False

    # Exact domain comparison.
    return domain == ALLOWED_EMAIL_DOMAIN


# ============================================================
# HTML SAFETY
# ============================================================

def html_is_safe(html: str) -> bool:
    """
    Deterministic checks required by the assignment:

    - block <script>
    - block <iframe>
    - block inline event handlers such as onclick=
    - block javascript: URLs

    No suspicious phrase matching is used.
    """

    # Decode HTML entities first.
    #
    # This catches things such as:
    # java&#x73;cript:
    # which becomes:
    # javascript:
    decoded = unescape(html)

    # Decode more than once to handle nested entity encoding.
    for _ in range(3):
        new_value = unescape(decoded)

        if new_value == decoded:
            break

        decoded = new_value

    lowered = decoded.lower()

    # --------------------------------------------------------
    # SCRIPT tags
    # --------------------------------------------------------

    if re.search(r"<\s*/?\s*script(?:\s|>|/)", lowered):
        return False

    # --------------------------------------------------------
    # IFRAME tags
    # --------------------------------------------------------

    if re.search(r"<\s*/?\s*iframe(?:\s|>|/)", lowered):
        return False

    # --------------------------------------------------------
    # Inline event handlers
    #
    # Examples:
    # onclick=
    # onload=
    # onerror=
    # onmouseover=
    # --------------------------------------------------------

    if re.search(r"\bon[a-z][a-z0-9_-]*\s*=", lowered):
        return False

    # --------------------------------------------------------
    # javascript: URLs
    #
    # Remove whitespace/control characters between characters
    # so tricks such as:
    #
    # java   script:
    #
    # are still detected.
    # --------------------------------------------------------

    normalized = re.sub(r"[\s\x00-\x1f\x7f]+", "", lowered)

    if "javascript:" in normalized:
        return False

    return True


# ============================================================
# FIREWALL
# ============================================================

def evaluate(data: Any):
    # --------------------------------------------------------
    # 1. TOP-LEVEL SCHEMA
    # --------------------------------------------------------

    if not validate_top_level(data):
        return block("INVALID_SCHEMA")

    action = data["action"]
    tool = action["tool"]
    args = action["args"]

    # --------------------------------------------------------
    # 2. TOOL ALLOWLIST
    # --------------------------------------------------------

    if tool not in ALLOWED_TOOLS:
        return block("TOOL_NOT_ALLOWED")

    # --------------------------------------------------------
    # 3. TOOL ARGUMENT SCHEMA
    # --------------------------------------------------------

    if tool == "search":
        if not validate_search(args):
            return block("INVALID_SCHEMA")

    elif tool == "lookup_record":
        if not validate_lookup_record(args):
            return block("INVALID_SCHEMA")

    elif tool == "send_email":
        if not validate_send_email(args):
            return block("INVALID_SCHEMA")

    elif tool == "render_html":
        if not validate_render_html(args):
            return block("INVALID_SCHEMA")

    # --------------------------------------------------------
    # 4. TENANT SCOPE
    # --------------------------------------------------------

    if tool == "lookup_record":
        if args["tenantId"] != ASSIGNED_TENANT:
            return block("TENANT_SCOPE")

    # --------------------------------------------------------
    # 5. EMAIL EGRESS
    # --------------------------------------------------------

    if tool == "send_email":
        if not valid_email_domain(args["to"]):
            return block("EGRESS_DENIED")

    # --------------------------------------------------------
    # 6. HUMAN APPROVAL
    # --------------------------------------------------------

    if tool == "send_email":
        if data["humanApproved"] is not True:
            return block("APPROVAL_REQUIRED")

    # --------------------------------------------------------
    # 7. HTML SAFETY
    # --------------------------------------------------------

    if tool == "render_html":
        if not html_is_safe(args["html"]):
            return block("UNSAFE_OUTPUT")

    # --------------------------------------------------------
    # 8. NOTHING FAILED
    # --------------------------------------------------------

    return allow()


# ============================================================
# ENDPOINT
# ============================================================

@app.post("/action-firewall")
async def action_firewall(request: Request):
    """
    Read raw JSON ourselves.

    This is intentional:
    malformed JSON and malformed top-level structures must
    return the assignment's INVALID_SCHEMA JSON rather than
    FastAPI's normal 422 error format.
    """

    try:
        data = await request.json()
    except Exception:
        return block("INVALID_SCHEMA")

    return evaluate(data)


# ============================================================
# HEALTH / AVAILABILITY
# ============================================================

@app.get("/")
async def root():
    return {
        "status": "ok",
        "service": "LLM Action Firewall",
    }


@app.get("/health")
async def health():
    return {
        "status": "healthy",
    }
