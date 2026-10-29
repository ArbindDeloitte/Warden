"""
Local PII Analyzer server — same /analyze API as presidio-analyzer Docker image.

Primary engine: presidio-analyzer + spaCy NER (PERSON, ORG, LOC, etc.)
  Workaround: loads spaCy models with exclude=['tokenizer'] to bypass the
  OverflowError in spacy.tokenizer.Tokenizer._flush_specials on Python 3.14+.

Fallback engine: pure regex (used when presidio/spaCy are unavailable).

Detects via regex: SSN, credit cards, IBAN, phone numbers, email, IP, UK NIN,
  passport numbers, dates, bank routing numbers.
Detects via NER: PERSON, ORGANIZATION, LOCATION, and more.

Start: py -3 server.py
"""

import re
import logging
from flask import Flask, request, jsonify

log = logging.getLogger(__name__)
app = Flask(__name__)

# ── Regex PII patterns ────────────────────────────────────────────────────────
PATTERNS = [
    ("US_SSN",         r"\b(?!000|666|9\d{2})\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b", 0.85),
    ("CREDIT_CARD",    r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}(?:[- ]?\d{3})?\b", 0.90),
    ("IBAN_CODE",      r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b", 0.85),
    ("EMAIL_ADDRESS",  r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", 0.90),
    # Separators required to avoid false positives on plain account numbers
    ("PHONE_NUMBER",   r"\b(?:\+?1[-.\s])?(?:\(\d{3}\)[-.\s]|\d{3}[-.\s])\d{3}[-.\s]\d{4}\b", 0.75),
    ("IP_ADDRESS",     r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b", 0.80),
    ("UK_NHS",         r"\b(?!BG|GB|NK|KN|TN|NT|ZZ)[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b", 0.80),
    ("US_PASSPORT",    r"\b[A-Z]\d{8}\b", 0.60),
    ("DATE_TIME",      r"\b(?:0?[1-9]|1[0-2])[\/\-\.](?:0?[1-9]|[12]\d|3[01])[\/\-\.](?:19|20)\d{2}\b", 0.65),
    ("US_BANK_NUMBER", r"\b\d{9}\b", 0.50),
]
COMPILED = [(entity, re.compile(pattern), score) for entity, pattern, score in PATTERNS]


def _analyze_regex(text, entities=None):
    results = []
    for entity_type, pattern, base_score in COMPILED:
        if entities and entity_type not in entities:
            continue
        for m in pattern.finditer(text):
            results.append({"entity_type": entity_type, "start": m.start(), "end": m.end(), "score": base_score})
    results.sort(key=lambda r: r["start"])
    return results


# ── Presidio + spaCy NER engine ───────────────────────────────────────────────
_presidio_analyzer = None
_engine_name = "regex"


def _init_presidio():
    """Try to build a presidio AnalyzerEngine using the spaCy NER workaround."""
    global _presidio_analyzer, _engine_name
    try:
        import spacy
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import SpacyNlpEngine

        # Workaround for Python 3.14: spacy.load() with exclude=['tokenizer']
        # bypasses Tokenizer._flush_specials() which overflows C ssize_t.
        # The blank default tokenizer is used instead; NER/tok2vec are unaffected.
        class _Py314SpacyEngine(SpacyNlpEngine):
            def load(self):
                self.nlp = {}
                for model in self.models:
                    self._validate_model_params(model)
                    self.nlp[model["lang_code"]] = spacy.load(
                        model["model_name"], exclude=["tokenizer"]
                    )

        nlp_engine = _Py314SpacyEngine(
            models=[{"lang_code": "en", "model_name": "en_core_web_sm"}]
        )
        nlp_engine.load()
        _presidio_analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
        _engine_name = "presidio+spacy"
        print(f"PII Analyzer ready ({_engine_name}) — http://localhost:5001")
    except Exception as exc:
        log.warning("presidio/spaCy unavailable (%s) — falling back to regex", exc)
        _engine_name = "regex"
        print(f"PII Analyzer ready ({_engine_name}) — http://localhost:5001")


def _analyze_presidio(text, entities=None):
    """Run presidio; return list of dicts matching the /analyze response schema."""
    kwargs = {"language": "en"}
    if entities:
        kwargs["entities"] = entities
    results = _presidio_analyzer.analyze(text=text, **kwargs)
    return [
        {"entity_type": r.entity_type, "start": r.start, "end": r.end, "score": round(r.score, 4)}
        for r in results
    ]


# ── Flask routes ──────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "engine": _engine_name})


@app.route("/analyze", methods=["POST"])
def analyze():
    body = request.get_json(force=True)
    text = body.get("text", "")
    entities = body.get("entities")  # None → all entities

    if not text:
        return jsonify([])

    if _presidio_analyzer is not None:
        try:
            return jsonify(_analyze_presidio(text, entities))
        except Exception as exc:
            log.warning("presidio analyze failed (%s), using regex fallback", exc)

    return jsonify(_analyze_regex(text, entities))


@app.route("/recognizers", methods=["GET"])
def recognizers():
    base = [{"entity_type": e, "pattern": p} for e, p, _ in PATTERNS]
    if _presidio_analyzer is not None:
        ner_types = ["PERSON", "ORGANIZATION", "LOCATION", "GPE", "NRP", "FACILITY", "URL", "DATE_TIME"]
        base += [{"entity_type": t, "source": "spacy-ner"} for t in ner_types]
    return jsonify(base)


if __name__ == "__main__":
    from waitress import serve
    _init_presidio()
    serve(app, host="0.0.0.0", port=5001)
