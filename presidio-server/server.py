"""
Local PII Analyzer server — same /analyze API as presidio-analyzer Docker image.
Uses regex pattern matching; no spaCy or Docker required.

Detects: SSN, credit cards, IBAN, phone numbers, email addresses, IP addresses,
         UK NIN, passport numbers, dates of birth, and bank account numbers.

Start: py -3 server.py
"""

import re
from flask import Flask, request, jsonify

app = Flask(__name__)

# ── PII pattern definitions ──────────────────────────────────────────────────
# Each entry: (entity_type, pattern, score)
PATTERNS = [
    # US Social Security Number
    ("US_SSN",        r"\b(?!000|666|9\d{2})\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b", 0.85),

    # Credit / debit card numbers (Visa, MC, Amex, Discover)
    ("CREDIT_CARD",   r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}(?:[- ]?\d{3})?\b", 0.90),

    # IBAN
    ("IBAN_CODE",     r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b", 0.85),

    # Email address
    ("EMAIL_ADDRESS", r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", 0.90),

    # US / international phone number — separators required to avoid matching
    # plain numeric strings like bank account numbers (8821001001 ≠ phone).
    ("PHONE_NUMBER",  r"\b(?:\+?1[-.\s])?(?:\(\d{3}\)[-.\s]|\d{3}[-.\s])\d{3}[-.\s]\d{4}\b", 0.75),

    # IPv4 address
    ("IP_ADDRESS",    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b", 0.80),

    # UK National Insurance Number
    ("UK_NHS",        r"\b(?!BG|GB|NK|KN|TN|NT|ZZ)[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b", 0.80),

    # US passport
    ("US_PASSPORT",   r"\b[A-Z]\d{8}\b", 0.60),

    # Date of birth (common formats)
    ("DATE_TIME",     r"\b(?:0?[1-9]|1[0-2])[\/\-\.](?:0?[1-9]|[12]\d|3[01])[\/\-\.](?:19|20)\d{2}\b", 0.65),

    # US bank routing + account (9-digit routing number)
    ("US_BANK_NUMBER",r"\b\d{9}\b", 0.50),
]

# Pre-compile all patterns
COMPILED = [(entity, re.compile(pattern), score) for entity, pattern, score in PATTERNS]


def analyze_text(text, entities=None):
    results = []
    for entity_type, pattern, base_score in COMPILED:
        if entities and entity_type not in entities:
            continue
        for m in pattern.finditer(text):
            results.append({
                "entity_type": entity_type,
                "start": m.start(),
                "end": m.end(),
                "score": base_score,
            })
    # Sort by start position
    results.sort(key=lambda r: r["start"])
    return results


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "engine": "regex"})


@app.route("/analyze", methods=["POST"])
def analyze():
    body = request.get_json(force=True)
    text = body.get("text", "")
    entities = body.get("entities")  # None → all

    if not text:
        return jsonify([])

    return jsonify(analyze_text(text, entities))


@app.route("/recognizers", methods=["GET"])
def recognizers():
    return jsonify([{"entity_type": e, "pattern": p} for e, p, _ in PATTERNS])


if __name__ == "__main__":
    from waitress import serve
    print("PII Analyzer ready (regex engine) — http://localhost:5001")
    serve(app, host="0.0.0.0", port=5001)
