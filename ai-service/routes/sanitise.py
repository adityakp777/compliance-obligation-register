# routes/sanitise.py
# AI Developer 3 — Input Sanitisation Middleware
# Day 3 — Tool-11 Compliance Obligation Register

import re
from flask import request, jsonify

# ------------------------------------------------------------------ #
# HTML stripping                                                       #
# ------------------------------------------------------------------ #

def strip_html(text: str) -> str:
    """Remove all HTML tags from input text."""
    clean = re.compile(r'<[^>]+>')
    return re.sub(clean, '', text)


# ------------------------------------------------------------------ #
# Prompt injection patterns                                            #
# ------------------------------------------------------------------ #

INJECTION_PATTERNS = [
    r'ignore\s+(all\s+)?previous\s+instructions',
    r'ignore\s+(all\s+)?prior\s+instructions',
    r'disregard\s+(all\s+)?previous',
    r'forget\s+(all\s+)?previous',
    r'system\s+prompt',
    r'you\s+are\s+now',
    r'act\s+as\s+(a\s+)?(?!compliance)',  # allow "act as a compliance officer"
    r'jailbreak',
    r'dan\s+mode',
    r'developer\s+mode',
    r'override\s+(all\s+)?(previous\s+)?instructions',
    r'reveal\s+(your\s+)?(system\s+)?prompt',
    r'print\s+(your\s+)?(system\s+)?prompt',
    r'show\s+(me\s+)?(your\s+)?(system\s+)?instructions',
    r'bypass\s+(all\s+)?(safety|restriction|filter)',
    r'pretend\s+(you\s+are|to\s+be)',
    r'roleplay\s+as',
    r'simulate\s+(a\s+)?(?!compliance)',
]

def contains_injection(text: str) -> bool:
    """Return True if text contains prompt injection patterns."""
    text_lower = text.lower()
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, text_lower):
            return True
    return False


# ------------------------------------------------------------------ #
# Main sanitisation function                                           #
# ------------------------------------------------------------------ #

def sanitise_input(text: str) -> tuple[bool, str, str]:
    """
    Sanitise a single text input.

    Returns:
        (is_safe, cleaned_text, error_message)
        - is_safe: True if input passed all checks
        - cleaned_text: HTML-stripped version of input
        - error_message: non-empty string if is_safe is False
    """
    if not text or not text.strip():
        return False, '', 'Input cannot be empty'

    if len(text) > 5000:
        return False, '', 'Input exceeds maximum length of 5000 characters'

    cleaned = strip_html(text)

    if contains_injection(cleaned):
        return False, '', 'Input contains disallowed content'

    return True, cleaned, ''


# ------------------------------------------------------------------ #
# Flask middleware — call this at the top of every route              #
# ------------------------------------------------------------------ #

def sanitise_request_field(field_name: str) -> tuple[bool, str, str]:
    """
    Extract and sanitise a single field from the incoming JSON request body.

    Usage in a route:
        is_safe, value, error = sanitise_request_field('description')
        if not is_safe:
            return jsonify({'error': error}), 400

    Returns:
        (is_safe, cleaned_value, error_message)
    """
    data = request.get_json(silent=True)

    if not data:
        return False, '', 'Request body must be valid JSON'

    value = data.get(field_name)

    if value is None:
        return False, '', f'Missing required field: {field_name}'

    if not isinstance(value, str):
        return False, '', f'Field {field_name} must be a string'

    return sanitise_input(value)


def sanitise_all_string_fields() -> tuple[bool, dict, str]:
    """
    Extract and sanitise ALL string fields from the incoming JSON request body.

    Usage in a route:
        is_safe, cleaned_data, error = sanitise_all_string_fields()
        if not is_safe:
            return jsonify({'error': error}), 400

    Returns:
        (is_safe, cleaned_data_dict, error_message)
    """
    data = request.get_json(silent=True)

    if not data:
        return False, {}, 'Request body must be valid JSON'

    cleaned_data = {}

    for key, value in data.items():
        if isinstance(value, str):
            is_safe, cleaned, error = sanitise_input(value)
            if not is_safe:
                return False, {}, f'Invalid input in field "{key}": {error}'
            cleaned_data[key] = cleaned
        else:
            cleaned_data[key] = value

    return True, cleaned_data, ''