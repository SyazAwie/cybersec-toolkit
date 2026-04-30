import re
import math
from zxcvbn import zxcvbn

def calculate_entropy(password: str) -> dict:
    """Basic character set checks + length"""
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_symbol = bool(re.search(r'[^A-Za-z0-9]', password))

    charset_size = 0
    if has_lower: charset_size += 26
    if has_upper: charset_size += 26
    if has_digit: charset_size += 10
    if has_symbol: charset_size += 32 # approx common symbols

    entropy = len(password) * math.log2(charset_size) if charset_size > 0 else 0

    return {
        "entropy": entropy,
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digit": has_digit,
        "has_symbol": has_symbol
    }

def analyze_password(password: str):
    """
    Returns: entropy, score 0-4, list of tips, crack_time_display
    Uses zxcvbn for real-world crack time + dictionary checks.
    """
    if not password:
        return 0, 0, ["Password is empty"], "Instant"

    # zxcvbn analysis
    result = zxcvbn(password)
    score = result['score'] # 0-4
    crack_time = result['crack_times_display']['offline_slow_hashing_1e4_per_second']
    feedback = result['feedback']['suggestions']

    # Add custom basic checks
    basic = calculate_entropy(password)
    entropy = basic['entropy']

    if len(password) < 12:
        feedback.append("Use at least 12 characters. Longer is stronger.")
    if not basic['has_lower'] or not basic['has_upper']:
        feedback.append("Mix uppercase and lowercase letters.")
    if not basic['has_digit']:
        feedback.append("Add numbers to increase complexity.")
    if not basic['has_symbol']:
        feedback.append("Add symbols like ! @ # $ % to boost entropy.")
    if re.search(r'(.)\1{2,}', password):
        feedback.append("Avoid repeated characters like 'aaa' or '111'.")
    if re.search(r'(012|123|234|345|456|567|678|789|890|abc|password|qwerty)', password.lower()):
        feedback.append("Avoid common sequences or dictionary words.")

    return entropy, score, feedback, crack_time

def get_strength_color(score: int) -> str:
    """Maps zxcvbn score 0-4 to Streamlit color"""
    return ["red", "red", "orange", "green", "green"][score]