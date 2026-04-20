import re

SIGNATURES = {
    "SQL Injection": re.compile(
        r"(?i)(union\s+select|or\s+1\s*=\s*1|drop\s+table|insert\s+into|select\s+\*)"
    ),
    "Cross-Site Scripting (XSS)": re.compile(
        r"(?i)(<script>|javascript:|alert\(|onerror=|onload=|eval\()"
    ),
    "Path Traversal (LFI/RFI)": re.compile(
        r"(?i)(\.\./|\.\.\\|/etc/passwd|/windows/system32|boot\.ini)"
    ),
    "Command Injection (RCE)": re.compile(
        r"(?i)(;\s*ls|\|\s*cat|`|wget\s+|curl\s+|nc\s+-e|bash\s+-i)"
    )
}

def analyze_payload(payload):
    """
    Analyzes a string payload against all signatures.
    Returns (threat_type, match_string) if found, else (None, None).
    """
    if not payload:
        return None, None
        
    payload_str = str(payload)
    for threat_type, pattern in SIGNATURES.items():
        match = pattern.search(payload_str)
        if match:
            return threat_type, match.group(0)
            
    return None, None

def evaluate_request(path, headers, body):
    """
    Evaluates the full HTTP request context.
    Returns (is_safe, threat_type, details)
    """
    threat, match = analyze_payload(path)
    if threat:
        return False, threat, f"Malicious payload '{match}' found in URL Path"

    for header_name, header_value in headers.items():
        threat, match = analyze_payload(header_value)
        if threat:
            return False, threat, f"Malicious payload '{match}' found in Header '{header_name}'"

    if body:
        threat, match = analyze_payload(body)
        if threat:
            return False, threat, f"Malicious payload '{match}' found in Request Body"

    return True, None, None
