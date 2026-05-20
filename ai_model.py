import numpy as np
import math
import re
from sklearn.ensemble import GradientBoostingClassifier

KNOWN_SECRET_PREFIXES = [
    "AKIA", "ghp_", "gho_", "ghs_", "xoxb-", "xoxp-",
    "sk_live_", "pk_live_", "SG.", "AIza", "eyJ", "SK"
]

COMMON_WORDS = {
    "hello", "world", "test", "example", "sample", "foo", "bar",
    "lorem", "ipsum", "true", "false", "null", "none", "undefined"
}

def entropy(text):
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    n = len(text)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())

def extract_features(text):
    length = len(text)
    digit_ratio = sum(c.isdigit() for c in text) / max(length, 1)
    upper_ratio = sum(c.isupper() for c in text) / max(length, 1)
    lower_ratio = sum(c.islower() for c in text) / max(length, 1)
    special_ratio = sum(not c.isalnum() for c in text) / max(length, 1)
    unique_ratio = len(set(text)) / max(length, 1)
    shannon_entropy = entropy(text)
    has_known_prefix = int(any(text.startswith(p) for p in KNOWN_SECRET_PREFIXES))
    is_common_word = int(text.lower() in COMMON_WORDS)
    has_only_alpha = int(text.isalpha())
    mixed_case = int(upper_ratio > 0 and lower_ratio > 0)
    long_token = int(length > 20)
    very_long = int(length > 40)
    has_numbers = int(digit_ratio > 0)
    high_entropy = int(shannon_entropy > 3.5)
    alphanumeric_only = int(bool(re.match(r'^[a-zA-Z0-9]+$', text)))

    return [
        length, digit_ratio, upper_ratio, lower_ratio, special_ratio,
        unique_ratio, shannon_entropy, has_known_prefix, is_common_word,
        has_only_alpha, mixed_case, long_token, very_long, has_numbers,
        high_entropy, alphanumeric_only
    ]

TRAINING_DATA = [
    ("AKIA1234567890ABCDEF", 1),
    ("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef123456", 1),
    ("sk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZabcd", 1),
    ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", 1),
    ("SG.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456", 1),
    ("AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg", 1),
    ("xoxb-1234567890-1234567890-ABCDEFabcdef", 1),
    ("password123", 1),
    ("s3cr3tK3y!2024", 1),
    ("P@ssw0rd!XYZ99", 1),
    ("3nkR9xLmZpQ7wT2YvU8bFsAjHdNcE5oi", 1),
    ("kQ3mP9xLnR7wT2Y", 1),
    ("hello", 0),
    ("world", 0),
    ("example", 0),
    ("12345", 0),
    ("foo", 0),
    ("test", 0),
    ("localhost", 0),
    ("username", 0),
    ("admin", 0),
    ("file.txt", 0),
    ("index.html", 0),
    ("main", 0),
    ("true", 0),
    ("false", 0),
]

X_train = [extract_features(text) for text, _ in TRAINING_DATA]
y_train = [label for _, label in TRAINING_DATA]

model = GradientBoostingClassifier(n_estimators=100, learning_rate=0.1, max_depth=4, random_state=42)
model.fit(X_train, y_train)

def predict_secret(text: str) -> bool:
    if len(text) < 6:
        return False
    if text.lower() in COMMON_WORDS:
        return False
    features = np.array(extract_features(text)).reshape(1, -1)
    prediction = model.predict(features)[0]
    confidence = model.predict_proba(features)[0][1]
    return bool(prediction == 1 and confidence > 0.65)

def predict_secret_with_confidence(text: str):
    if len(text) < 6 or text.lower() in COMMON_WORDS:
        return False, 0.0
    features = np.array(extract_features(text)).reshape(1, -1)
    prediction = model.predict(features)[0]
    confidence = float(model.predict_proba(features)[0][1])
    is_secret = bool(prediction == 1 and confidence > 0.65)
    return is_secret, round(confidence * 100, 1)
