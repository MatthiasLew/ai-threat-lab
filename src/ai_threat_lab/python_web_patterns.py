"""Literal AST observations for selected Python web APIs; no framework imports."""

import ast


def _false_keyword(node, key):
    return any(
        item.arg == key and isinstance(item.value, ast.Constant) and item.value.value is False
        for item in node.keywords
    )


def _unsigned_jwt(node):
    options = next((item.value for item in node.keywords if item.arg == "options"), None)
    if not isinstance(options, ast.Dict):
        return False
    # Unpacking/computed/duplicate keys can change effective values; do not infer them.
    keys = []
    for key in options.keys:
        if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
            return False
        keys.append(key.value)
    if len(set(keys)) != len(keys):
        return False
    return any(
        key == "verify_signature" and isinstance(value, ast.Constant) and value.value is False
        for key, value in zip(keys, options.values, strict=True)
    )


def web_rule(node, name):
    """Return a candidate rule descriptor for a resolved simple call spelling."""
    if name == "jinja2.Environment" and _false_keyword(node, "autoescape"):
        return (
            "PY010",
            "Medium",
            "Jinja autoescaping explicitly disabled",
            "The constructor explicitly sets autoescape=False. HTML injection depends on "
            "template context and input trust; neither is established here.",
            "For HTML output, enable appropriate autoescaping and review template contexts. "
            "Document intentional non-HTML environments separately.",
        )
    if name in ("django.utils.safestring.mark_safe", "markupsafe.Markup"):
        return (
            "PY011",
            "Medium",
            "Explicit safe-HTML marker requires trust review",
            "This API marks content as safe HTML rather than escaping it. Trusted static "
            "markup can be intentional; this check does not trace content provenance.",
            "Keep untrusted text escaped, use framework escaping/formatting helpers and "
            "review sanitization before explicitly marking HTML as safe.",
        )
    if name in ("jwt.decode", "jwt.decode_complete") and _unsigned_jwt(node):
        return (
            "PY012",
            "High",
            "JWT signature verification explicitly disabled",
            "A literal options dictionary sets verify_signature=False in a PyJWT-style "
            "decode call. Installed library identity and subsequent authorization use "
            "are not established here.",
            "Verify signatures with trusted keys and an explicit allowed-algorithm policy "
            "before trusting claims. Keep intentional unverified inspection separate "
            "from authentication and authorization.",
        )
    return None
