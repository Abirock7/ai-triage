# app/core/llm_adapter.py
import os, json
from .llm_mock import generate_triage as mock_generate

def _try_json(text: str):
    # strip code fences if present
    if text.strip().startswith("```"):
        text = text.strip().strip("`")
        # after stripping fences, there may be a language tag; remove first line if it looks like 'json'
        first_nl = text.find("\n")
        if first_nl != -1:
            maybe_lang = text[:first_nl].lower()
            if "json" in maybe_lang:
                text = text[first_nl+1:]
    return json.loads(text)

def generate_triage(parsed: dict) -> dict:
    provider = os.getenv("TRIAGE_PROVIDER", "mock").lower()
    if provider == "openai":
        api_key = os.getenv("OPENAI_API_KEY")
        model = os.getenv("TRIAGE_MODEL", "gpt-4o-mini")
        if not api_key:
            # Fallback to mock if key not set
            return mock_generate(parsed)
        try:
            # lazy import so you don’t need the package unless you use it
            from openai import OpenAI
            client = OpenAI(api_key=api_key)

            system = (
                "You are a security triage assistant. "
                "Given Nmap parsed JSON (hosts -> ports -> service, state), "
                "produce STRICT JSON with keys: summary (string), findings (list), confidence (string). "
                "Each finding has: host, port, service, severity in {Low,Medium,High,Critical}, "
                "evidence (short text), recommendations (list of short steps). Only output JSON."
            )
            user = json.dumps(parsed)

            resp = client.chat.completions.create(
                model=model,
                temperature=0.2,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            )
            text = resp.choices[0].message.content
            return _try_json(text)
        except Exception:
            # Any failure, fall back to mock so demo never breaks
            return mock_generate(parsed)
    else:
        # default/mocked provider
        return mock_generate(parsed)
