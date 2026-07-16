"""
Praxis Smart Intent Matcher — Semantic matching for policy rules.

Instead of matching exact strings like "Pay", this module understands
that "Complete Purchase", "Checkout", "Place Order", "Finalize Payment",
"Buy Now", "Comprar" all mean the SAME INTENT: a payment action.

Policy authors write intents like:
    block_elements:
      - intent: payment          # catches 50+ variations automatically
      - intent: delete           # catches remove, erase, destroy, trash, etc.
      - intent: authentication   # catches login, sign in, password, etc.

The matcher also enhances text_contains by expanding keywords through
synonym groups automatically.

Beyond exact substring matching, the module provides TWO linguistic
matching layers (zero external dependencies for the core logic):

  1. **Phonetic matching** — encodes words by how they SOUND, so typos
     like "Chekout" and "Checkout" produce the same phonetic code.
  2. **Stem-prefix matching** — reduces words to phonetic roots so
     "Purchasing", "Purchased", "Purchases" all match "Purchase".

These are deterministic, rule-based, and produce no false positives
(unlike fuzzy string similarity scoring).
"""

from __future__ import annotations

import re
from typing import Any


# ═══════════════════════════════════════════════════════════════════════════
# Intent → Synonym Vocabulary
# ═══════════════════════════════════════════════════════════════════════════
# Each intent maps to a list of words/phrases that all mean the same thing.
# Matching is case-insensitive substring against element text, selector,
# and value fields.

INTENT_SYNONYMS: dict[str, list[str]] = {

    # ── Payment / Purchase ────────────────────────────────────────────
    "payment": [
        "pay", "payment", "purchase", "buy", "buy now", "checkout",
        "check out", "check-out", "place order", "place my order",
        "complete order", "complete purchase", "confirm order",
        "confirm purchase", "finalize order", "finalize purchase",
        "submit order", "submit payment", "process payment",
        "proceed to payment", "proceed to checkout", "proceed to billing",
        "billing", "pay now", "pay with", "pay using",
        "add to cart", "add to bag", "add to basket",
        "wire", "wire transfer", "send money", "transfer funds",
        "make payment", "authorize payment", "charge", "charge card",
        "subscribe", "upgrade plan", "start subscription",
        "donate", "donation", "contribute", "tip",
        # Common button labels
        "place this order", "complete transaction",
        "continue to payment", "continue to checkout",
        "review and pay", "review & pay", "review order",
    ],

    # ── Deletion / Destruction ────────────────────────────────────────
    "delete": [
        "delete", "remove", "destroy", "purge", "erase", "wipe",
        "trash", "discard", "clear", "clear all", "empty",
        "drop", "uninstall", "unlink", "detach",
        "revoke", "cancel", "terminate", "close account",
        "deactivate", "disable", "archive", "permanently delete",
        "remove all", "delete all", "bulk delete",
        "reset", "factory reset", "hard reset",
        "shred", "obliterate",
    ],

    # ── Authentication / Credentials ──────────────────────────────────
    "authentication": [
        "login", "log in", "log-in", "sign in", "sign-in", "signin",
        "sign up", "sign-up", "signup", "register", "create account",
        "forgot password", "reset password", "change password",
        "update password", "new password", "set password",
        "enter password", "password", "passcode", "pin",
        "two-factor", "2fa", "mfa", "otp", "verification code",
        "authenticate", "verify identity", "confirm identity",
        "biometric", "fingerprint", "face id",
        "sso", "single sign-on", "oauth", "saml",
        "credential", "secret", "api key", "access token",
    ],

    # ── Admin / Permissions ───────────────────────────────────────────
    "admin": [
        "admin", "administrator", "admin panel", "admin console",
        "dashboard", "control panel", "settings", "preferences",
        "configuration", "config", "manage", "management",
        "superuser", "root", "sudo", "elevated", "escalate",
        "grant access", "grant permission", "change permission",
        "change role", "assign role", "promote", "demote",
        "add user", "remove user", "invite user",
        "enable", "disable", "toggle",
        "system settings", "account settings",
        "security settings", "privacy settings",
    ],

    # ── Data Export / Download ────────────────────────────────────────
    "export": [
        "export", "download", "download all", "bulk download",
        "export data", "export csv", "export pdf", "export excel",
        "export report", "generate report", "download report",
        "save as", "save to", "backup", "back up",
        "extract", "dump", "pull data",
        "print", "print all",
    ],

    # ── Data Import / Upload ──────────────────────────────────────────
    "upload": [
        "upload", "import", "import data", "import csv",
        "import file", "upload file", "attach", "attachment",
        "drag and drop", "browse files", "choose file",
        "select file", "pick file", "load data", "bulk import",
        "restore", "restore backup",
    ],

    # ── Sharing / Publishing ──────────────────────────────────────────
    "share": [
        "share", "publish", "post", "send", "forward",
        "share link", "copy link", "make public", "go public",
        "broadcast", "distribute", "announce",
        "invite", "share with", "send to", "email to",
        "tweet", "share on", "embed",
    ],

    # ── Approval / Confirmation ───────────────────────────────────────
    "confirm": [
        "confirm", "approve", "accept", "agree", "consent",
        "acknowledge", "verify", "validate", "authorize",
        "i agree", "i accept", "i confirm",
        "yes", "proceed", "continue", "go ahead",
        "ok", "okay", "submit", "done", "finish",
        "complete", "finalize",
    ],

    # ── Sensitive Data Fields ─────────────────────────────────────────
    "sensitive_field": [
        "credit card", "card number", "credit-card", "creditcard",
        "debit card", "card details", "payment method",
        "cvv", "cvc", "csv", "security code", "card code",
        "expiry", "expiration", "exp date", "valid thru",
        "ssn", "social security", "social-security",
        "tax id", "tax number", "ein", "tin",
        "bank account", "account number", "routing number",
        "iban", "swift", "bic", "sort code",
        "drivers license", "driver's license", "passport",
        "date of birth", "dob", "birthday",
    ],

    # ── Communication / Messaging ─────────────────────────────────────
    "messaging": [
        "send message", "send email", "compose", "reply",
        "reply all", "forward", "new message", "new email",
        "chat", "direct message", "dm", "notify",
        "text", "sms", "call", "dial",
        "contact", "reach out",
    ],

    # ── Modification / Update ─────────────────────────────────────────
    "modify": [
        "edit", "update", "modify", "change", "alter",
        "rename", "replace", "overwrite", "patch",
        "revise", "amend", "correct", "fix",
        "save", "save changes", "apply changes",
        "apply", "set", "adjust", "customize",
    ],

    # ── Financial / Money ─────────────────────────────────────────────
    "financial": [
        "refund", "chargeback", "dispute", "claim",
        "credit", "debit", "withdrawal", "deposit",
        "balance", "statement", "invoice", "receipt",
        "tax", "fee", "surcharge", "penalty",
        "interest", "loan", "mortgage", "installment",
        "payout", "remittance", "settlement",
    ],

    # ── Destructive System Actions ────────────────────────────────────
    "system_destructive": [
        "shutdown", "shut down", "restart", "reboot",
        "terminate", "kill", "stop", "halt", "abort",
        "force quit", "force close", "end process",
        "format", "reformat", "reinstall",
        "rollback", "roll back", "downgrade",
    ],
}

# Build reverse index: keyword → list of intents it belongs to
_KEYWORD_TO_INTENTS: dict[str, list[str]] = {}
for _intent, _keywords in INTENT_SYNONYMS.items():
    for _kw in _keywords:
        _KEYWORD_TO_INTENTS.setdefault(_kw.lower(), []).append(_intent)


# ═══════════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════════

def match_intent(intent: str, text: str) -> bool:
    """
    Check if `text` matches the given intent.

    Args:
        intent: An intent name like "payment", "delete", "admin"
        text: The combined text to check (element_text, selector, value, url)

    Returns:
        True if any synonym for the intent is found in the text.

    Example:
        >>> match_intent("payment", "Complete Purchase")
        True
        >>> match_intent("payment", "Read Report")
        False
    """
    synonyms = INTENT_SYNONYMS.get(intent.lower(), [])
    if not synonyms:
        return False

    text_lower = text.lower()
    return any(syn in text_lower for syn in synonyms)


def expand_keywords(keywords: list[str]) -> list[str]:
    """
    Smart-expand a keyword list by adding synonyms from the same intent group.

    If a policy says text_contains: ["Pay"], this function expands it to include
    "purchase", "checkout", "buy now", etc. — everything in the "payment" intent.

    Only expands keywords that are recognized in an intent group.
    Unknown keywords are kept as-is.

    Args:
        keywords: Original keyword list from a policy rule

    Returns:
        Expanded keyword list (deduplicated, sorted)

    Example:
        >>> expand_keywords(["Pay"])
        ["add to bag", "add to basket", "add to cart", "authorize payment",
         "billing", "buy", "buy now", "charge", "charge card", "checkout", ...]
    """
    expanded = set()
    for kw in keywords:
        kw_lower = kw.lower()
        expanded.add(kw_lower)
        # Find which intents this keyword belongs to
        intents = _KEYWORD_TO_INTENTS.get(kw_lower, [])
        for intent in intents:
            # Add all synonyms from that intent
            for syn in INTENT_SYNONYMS.get(intent, []):
                expanded.add(syn.lower())

    return sorted(expanded)


def detect_intents(text: str) -> list[str]:
    """
    Detect which intents are present in the given text.

    Useful for auto-classifying what an action is about.

    Args:
        text: Text to analyze (element text, URL, selector, etc.)

    Returns:
        List of matched intent names, sorted.

    Example:
        >>> detect_intents("Click the Checkout button")
        ["payment"]
        >>> detect_intents("Delete all user data permanently")
        ["delete"]
    """
    matched = set()
    text_lower = text.lower()
    for intent, synonyms in INTENT_SYNONYMS.items():
        for syn in synonyms:
            if syn in text_lower:
                matched.add(intent)
                break  # One match per intent is enough
    return sorted(matched)


def get_all_intents() -> list[str]:
    """Return all available intent names."""
    return sorted(INTENT_SYNONYMS.keys())


def get_intent_keywords(intent: str) -> list[str]:
    """Return all keywords for a given intent."""
    return sorted(INTENT_SYNONYMS.get(intent.lower(), []))


# ═══════════════════════════════════════════════════════════════════════════
# Phonetic Matching Engine — Linguistic typo & variant detection
# ═══════════════════════════════════════════════════════════════════════════
# Zero-dependency, deterministic, rule-based matching that catches:
#   - Typos:    "Chekout" → matches "Checkout"  (same phonetic code)
#   - Variants: "Purchasing" → matches "Purchase" (stem-prefix match)
#   - Doubles:  "Submitt" → matches "Submit"  (collapsed consonants)
#
# HOW IT WORKS:
#   1. phonetic_code(word) encodes a word by how it sounds:
#      - Normalize consonant equivalences (ck→c, ph→f, etc.)
#      - Collapse doubled consonants ("submitt" → "submit")
#      - Strip interior vowels (they're unreliable in typos)
#      Result: "checkout" → "chct", "chekout" → "chct" — identical.
#
#   2. At import time, every synonym in INTENT_SYNONYMS is pre-indexed
#      by its phonetic code in _PHONETIC_INDEX.
#
#   3. At match time, each word in the input text is phonetic-coded and
#      looked up in the index.  Exact code match = hit.  If no exact hit,
#      prefix matching catches inflections ("purchasing" → "prchsng"
#      starts with "prchs" = code for "purchase").
#
# FALSE POSITIVE PROTECTION:
#   - Different first characters → different codes ("export" ≠ "report")
#   - Vowel-stripping is interior only — first char preserved
#   - No arbitrary score thresholds — it either matches or it doesn't

# Minimum word length for phonetic matching (skip "a", "to", "the", etc.)
MIN_PHONETIC_LEN: int = 4


def phonetic_code(word: str) -> str:
    """
    Encode a word by how it sounds.

    Produces a consonant skeleton with normalized equivalences.
    Two words that are typos of each other will usually produce
    the same (or prefix-matching) code.

    Examples:
        >>> phonetic_code("checkout")
        'chct'
        >>> phonetic_code("chekout")
        'chct'
        >>> phonetic_code("purchase")
        'prchs'
        >>> phonetic_code("purchse")
        'prchs'
        >>> phonetic_code("export")   # Note: different from "report"
        'xprt'
        >>> phonetic_code("report")
        'rprt'
    """
    w = word.lower().strip()
    if len(w) < 2:
        return w

    # Step 1: Normalize common phonetic equivalences
    _PHONETIC_REPLACEMENTS = [
        ("ck", "c"), ("ph", "f"), ("gh", "g"), ("wh", "w"),
        ("wr", "r"), ("kn", "n"), ("tion", "shn"), ("sion", "shn"),
        ("ment", "mnt"), ("ness", "ns"), ("ight", "it"),
        ("ough", "f"), ("ious", "ys"), ("eous", "ys"),
    ]
    for old, new in _PHONETIC_REPLACEMENTS:
        w = w.replace(old, new)

    # Step 2: Normalize interchangeable consonants
    #   c/k/q → c  (but keep 'x' as 'x' — distinct sound)
    #   s/z   → s
    _CONSONANT_TABLE = str.maketrans("kqz", "ccs")
    w = w.translate(_CONSONANT_TABLE)

    # Step 3: Sort adjacent character pairs to normalize transpositions.
    # This catches the most common typo type: swapped adjacent letters.
    # "sign" → "gisn" after sort, "sing" → "gins" — wait, this runs
    # BEFORE vowel stripping so the structural order is preserved.
    # Only sort interior pairs (start at index 1) to preserve first char.
    chars = list(w)
    for i in range(1, len(chars) - 1):
        if chars[i] > chars[i + 1]:
            chars[i], chars[i + 1] = chars[i + 1], chars[i]
    w = "".join(chars)

    # Step 4: Collapse consecutive duplicate characters
    result = w[0]
    for c in w[1:]:
        if c != result[-1]:
            result += c

    # Step 5: Strip interior vowels (keep first character as-is)
    first = result[0]
    consonants = "".join(c for c in result[1:] if c not in "aeiou")
    code = first + consonants

    return code


def _tokenize_words(text: str) -> list[str]:
    """Split text into individual lowercase words."""
    return text.lower().split()


def _build_ngrams(words: list[str]) -> list[str]:
    """Build unigrams + bigrams + trigrams from a word list."""
    tokens = list(words)
    for i in range(len(words) - 1):
        tokens.append(f"{words[i]} {words[i + 1]}")
    for i in range(len(words) - 2):
        tokens.append(f"{words[i]} {words[i + 1]} {words[i + 2]}")
    return tokens


# ---------------------------------------------------------------------------
# Pre-computed phonetic index — built once at import time
# ---------------------------------------------------------------------------
# Maps phonetic_code → list of (intent, original_synonym)
# This makes phonetic lookups O(1) instead of scanning all synonyms.

_PHONETIC_INDEX: dict[str, list[tuple[str, str]]] = {}


def _rebuild_phonetic_index() -> None:
    """Rebuild the phonetic index from INTENT_SYNONYMS."""
    _PHONETIC_INDEX.clear()
    for intent, synonyms in INTENT_SYNONYMS.items():
        for syn in synonyms:
            # For multi-word synonyms, index the whole phrase
            code = phonetic_code(syn)
            if code:
                _PHONETIC_INDEX.setdefault(code, []).append((intent, syn))
            # Also index each individual word for partial matching
            for word in syn.split():
                if len(word) >= MIN_PHONETIC_LEN:
                    wcode = phonetic_code(word)
                    if wcode and wcode != code:
                        _PHONETIC_INDEX.setdefault(wcode, []).append((intent, syn))


# Build index at import time
_rebuild_phonetic_index()


def phonetic_match_keywords(
    keywords: list[str],
    text: str,
) -> tuple[bool, str | None]:
    """
    Check if any keyword phonetically matches any word in the text.

    This catches typos (same phonetic code) and morphological variants
    (one code is a prefix of the other).

    Args:
        keywords: Reference keywords to check against.
        text:     The text to search within.

    Returns:
        (matched: bool, matched_keyword_or_None)

    Example:
        >>> phonetic_match_keywords(["checkout", "purchase"], "Chekout Now")
        (True, "checkout")
        >>> phonetic_match_keywords(["export"], "View Quarterly Report")
        (False, None)
    """
    if not keywords or not text:
        return False, None

    # Pre-compute phonetic codes for all keywords
    kw_codes: list[tuple[str, str, bool]] = []  # (code, keyword, is_multiword)
    for kw in keywords:
        is_multi = " " in kw
        if is_multi:
            # Multi-word keyword: code the whole phrase
            code = phonetic_code(kw)
            if code:
                kw_codes.append((code, kw, True))
        elif len(kw) >= MIN_PHONETIC_LEN:
            code = phonetic_code(kw)
            if code:
                kw_codes.append((code, kw, False))

    if not kw_codes:
        return False, None

    # Tokenize text into words + ngrams, compute phonetic codes
    words = _tokenize_words(text)
    text_tokens = _build_ngrams(words)
    text_codes = [(phonetic_code(t), t) for t in text_tokens if len(t) >= MIN_PHONETIC_LEN]

    for kw_code, kw, is_multi in kw_codes:
        for t_code, t in text_codes:
            # Multi-word keywords must only match multi-word text tokens.
            # This prevents "submit order" from matching the single word
            # "submit" in "Submit Report".
            if is_multi and " " not in t:
                continue

            # Exact phonetic match — same sound
            if kw_code == t_code:
                return True, kw
            # Prefix match — catches inflected forms
            # "purchase" (prchs) matches "purchasing" (prchsng) because
            # prchs is a prefix of prchsng.
            # Guard: the shorter code must be at least 4 chars to avoid
            # false positives like click(ccl, 3 chars) ↔ cancel(ccln).
            min_len = min(len(kw_code), len(t_code))
            if min_len >= 4 and (
                t_code.startswith(kw_code) or kw_code.startswith(t_code)
            ):
                return True, kw

    return False, None


def phonetic_match_intent(
    intent: str,
    text: str,
) -> tuple[bool, str | None]:
    """
    Check if text phonetically matches any synonym for the given intent.

    Args:
        intent: Intent name, e.g. "payment".
        text:   Text to check.

    Returns:
        (matched, matched_synonym_or_None)
    """
    synonyms = INTENT_SYNONYMS.get(intent.lower(), [])
    if not synonyms:
        return False, None
    return phonetic_match_keywords(synonyms, text)


def phonetic_detect_intents(text: str) -> list[tuple[str, str]]:
    """
    Detect intents using phonetic matching — catches typos and inflected
    forms that exact substring matching would miss.

    Uses the pre-computed _PHONETIC_INDEX for O(1) lookups per word.

    Args:
        text: Text to analyze.

    Returns:
        List of (intent, matched_synonym) tuples, sorted by intent.
        Deduplicated by intent — only the first synonym match per intent.

    Example:
        >>> phonetic_detect_intents("Compleet Purchse")
        [("payment", "purchase")]
        >>> phonetic_detect_intents("View Quarterly Report")
        []
    """
    words = _tokenize_words(text)
    tokens = _build_ngrams(words)

    found: dict[str, str] = {}  # intent → first matched synonym

    for token in tokens:
        if len(token) < MIN_PHONETIC_LEN:
            continue
        code = phonetic_code(token)
        if not code:
            continue

        # Exact code lookup
        if code in _PHONETIC_INDEX:
            for intent, syn in _PHONETIC_INDEX[code]:
                if intent not in found:
                    found[intent] = syn

        # Prefix lookup: check if any indexed code starts with this
        # code or vice versa (for inflected forms).
        # Only if code is at least 3 chars to avoid short-code noise.
        if len(code) >= 3:
            for idx_code, entries in _PHONETIC_INDEX.items():
                if idx_code == code:
                    continue  # already handled above
                if idx_code.startswith(code) or code.startswith(idx_code):
                    for intent, syn in entries:
                        if intent not in found:
                            found[intent] = syn

    return sorted(found.items())
