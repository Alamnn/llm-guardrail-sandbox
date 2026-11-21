#!/usr/bin/env python3
"""Input and Output Guardrails for RAG LLM Applications (OWASP LLM Top 10 Mitigations)."""
import re
from dataclasses import dataclass

# OWASP LLM01: Direct & Indirect Prompt Injection signatures
INJECTION_PATTERNS = [
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+(safety\s+)?(instructions|rules|prompts)", "instruction_override"),
    (r"(system\s+instruction\s+override|developer\s+mode|maintenance\s+debug\s+mode|jailbreak|dan\s+mode)", "mode_escalation"),
    (r"(reveal|print|output|show|dump|repeat)\s+(the\s+)?(entire\s+)?(system[_\s]?prompt|hidden\s+instructions|secret|api[_\s]?key)", "prompt_leak_attempt"),
    (r"<!--.*?(ignore|override|system|prompt|secret).*?-->", "hidden_html_injection"),
    (r"(translate|encode|base64)\s+.*?(system\s+prompt|api\s+key|password|ssn)", "encoded_exfiltration"),
]

# OWASP LLM02 & LLM06: Sensitive Information Disclosure & System Prompt Leakage patterns
SECRET_OUTPUT_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "[REDACTED_AWS_KEY]"),
    (r"sk-[a-zA-Z0-9_-]{20,}", "[REDACTED_API_KEY]"),
    (r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]"),
    (r"INTERNAL_DB_PASSWORD\s*=\s*\S+", "INTERNAL_DB_PASSWORD=[REDACTED]"),
    (r"CONFIDENTIAL_SYSTEM_PROMPT_MARKER:[A-Za-z0-9_-]+", "[REDACTED_SYSTEM_PROMPT]"),
]

# OWASP LLM05: Improper Output Handling (XSS / Command execution payloads in LLM output)
UNSAFE_OUTPUT_PATTERNS = [
    r"<\s*script\b",
    r"javascript\s*:",
    r"onerror\s*=",
    r";\s*rm\s+-rf\b",
    r"\$\(.*\)",
]


@dataclass
class GuardrailDecision:
    allowed: bool
    reason: str
    sanitized_text: str


def check_input(user_prompt: str) -> GuardrailDecision:
    """Validate user input against prompt injection and exfiltration patterns."""
    for pattern, label in INJECTION_PATTERNS:
        if re.search(pattern, user_prompt, re.IGNORECASE | re.DOTALL):
            return GuardrailDecision(False, f"Blocked by Input Guardrail ({label})", "")
    return GuardrailDecision(True, "ok", user_prompt)


def sanitize_rag_chunk(doc_name: str, text: str) -> tuple[str, list[str]]:
    """Strip indirect prompt injections embedded in retrieved RAG documents."""
    flags = []
    cleaned = text
    for pattern, label in INJECTION_PATTERNS:
        if re.search(pattern, cleaned, re.IGNORECASE | re.DOTALL):
            flags.append(f"{doc_name}:{label}")
            cleaned = re.sub(pattern, "[REMOVED_INDIRECT_INJECTION]", cleaned, flags=re.IGNORECASE | re.DOTALL)
    # Also strip HTML comments from untrusted KB chunks
    cleaned = re.sub(r"<!--.*?-->", "", cleaned, flags=re.DOTALL)
    return cleaned.strip(), flags


def check_output(response_text: str) -> GuardrailDecision:
    """Redact secrets/PII/system markers and block unsafe executable output."""
    for pat in UNSAFE_OUTPUT_PATTERNS:
        if re.search(pat, response_text, re.IGNORECASE):
            return GuardrailDecision(False, "Blocked by Output Guardrail (LLM05_unsafe_output)", "[BLOCKED_UNSAFE_OUTPUT]")

    redacted = response_text
    triggered = []
    for pat, repl in SECRET_OUTPUT_PATTERNS:
        if re.search(pat, redacted):
            triggered.append(repl)
            redacted = re.sub(pat, repl, redacted)

    if triggered:
        return GuardrailDecision(False, f"Redacted by Output Guardrail ({', '.join(triggered)})", redacted)
    return GuardrailDecision(True, "ok", redacted)
