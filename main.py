from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field
from typing import Any, Dict, Literal, Optional
from urllib.parse import urlparse
import re

app = FastAPI(title="LLM Action Firewall")

ASSIGNED_TENANT = "tenant-six6pev"
ALLOWED_EMAIL_DOMAIN = "notify-l00m0tm.example"

ALLOWED_TOOLS = {
    "search",
    "lookup_record",
    "send_email",
    "render_html",
}


class Action(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: str
    args: Dict[str, Any]


class FirewallRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provenance: Literal["trusted", "untrusted"]
    humanApproved: bool
    untrustedContent: Optional[str] = None
    action: Action


class FirewallResponse(BaseModel):
    decision: Literal["allow", "block"]
    reason: Literal[
        "ALLOW",
        "INVALID_SCHEMA",
        "TOOL_NOT_ALLOWED",
        "TENANT_SCOPE",
        "EGRESS_DENIED",
        "APPROVAL_REQUIRED",
        "UNSAFE_OUTPUT",
    ]


def block(reason: str):
    return FirewallResponse(decision="block", reason=reason)


def valid_exact_keys(args: Any, keys: set[str]) -> bool:
    return isinstance(args, dict) and set(args.keys()) == keys


def valid_nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and len(value) > 0


def validate_search(args: Any) -> bool:
    if not valid_exact_keys(args, {"query"}):
        return False

    query = args["query"]

    return (
        isinstance(query, str)
        and 1 <= len(query) <= 200
    )


def validate_lookup_record(args: Any) -> bool:
    if not valid_exact_keys(args, {"tenantId", "recordId"}):
        return False

    return (
        isinstance(args["tenantId"], str)
        and isinstance(args["recordId"], str)
        and len(args["recordId"]) > 0
    )


def validate_send_email(args: Any) -> bool:
    if not valid_exact_keys(args, {"to", "subject", "body"}):
        return False

    return all(
        isinstance(args[key], str)
        for key in ("to", "subject", "body")
    )


def validate_render_html(args: Any) -> bool:
    if not valid_exact_keys(args, {"html"}):
        return False

    return isinstance(args["html"], str)


def email_domain_is_allowed(address: str) -> bool:
    """
    Require a normal email address whose domain is exactly
    notify-l00m0tm.example.
    """
    if "@" not in address:
        return False

    local, domain = address.rsplit("@", 1)

    if not local or not domain:
        return False

    return domain == ALLOWED_EMAIL_DOMAIN


def html_is_safe(html: str) -> bool:
    """
    Deterministic HTML safety checks.

    Block:
    - script elements
    - iframe elements
    - inline event handlers such as onclick=
    - javascript: URLs
    """

    lowered = html.lower()

    # Block script tags.
    if re.search(r"<\s*/?\s*script\b", lowered):
        return False

    # Block iframe tags.
    if re.search(r"<\s*/?\s*iframe\b", lowered):
        return False

    # Block inline event handlers such as onclick=, onload=, onerror=.
    if re.search(r"\bon[a-z0-9_-]+\s*=", lowered):
        return False

    # Block javascript: URLs, including whitespace/control-character tricks.
    normalized = re.sub(r"[\s\x00-\x1f]+", "", lowered)

    if "javascript:" in normalized:
        return False

    return True


@app.post("/action-firewall", response_model=FirewallResponse)
def action_firewall(request: FirewallRequest):
    # ---------------------------------------------------------
    # 1. Top-level schema
    # ---------------------------------------------------------
    #
    # FastAPI/Pydantic performs this validation before this
    # function executes. Invalid requests receive a 422.
    #
    # The assignment wants INVALID_SCHEMA as the firewall
    # response, so valid requests continue below.
    # ---------------------------------------------------------

    tool = request.action.tool
    args = request.action.args

    # ---------------------------------------------------------
    # 2. Tool allowlist
    # ---------------------------------------------------------

    if tool not in ALLOWED_TOOLS:
        return block("TOOL_NOT_ALLOWED")

    # ---------------------------------------------------------
    # 3. Selected tool's argument schema
    # ---------------------------------------------------------

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

    # ---------------------------------------------------------
    # 4. Tenant scope
    # ---------------------------------------------------------

    if tool == "lookup_record":
        if args["tenantId"] != ASSIGNED_TENANT:
            return block("TENANT_SCOPE")

    # ---------------------------------------------------------
    # 5. Email egress
    # ---------------------------------------------------------

    if tool == "send_email":
        if not email_domain_is_allowed(args["to"]):
            return block("EGRESS_DENIED")

    # ---------------------------------------------------------
    # 6. Human approval
    # ---------------------------------------------------------

    if tool == "send_email":
        if request.humanApproved is not True:
            return block("APPROVAL_REQUIRED")

    # ---------------------------------------------------------
    # 7. HTML safety
    # ---------------------------------------------------------

    if tool == "render_html":
        if not html_is_safe(args["html"]):
            return block("UNSAFE_OUTPUT")

    # ---------------------------------------------------------
    # 8. Everything passed
    # ---------------------------------------------------------

    return FirewallResponse(
        decision="allow",
        reason="ALLOW",
    )


@app.get("/")
def root():
    return {
        "service": "LLM Action Firewall",
        "status": "ok",
    }


@app.get("/health")
def health():
    return {"status": "healthy"}
