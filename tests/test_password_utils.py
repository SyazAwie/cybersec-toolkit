import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from password_utils import calculate_entropy, analyze_password

def test_entropy_calculation():
    res = calculate_entropy("a")
    assert res["entropy"] > 0
    assert res["has_lower"] == True
    assert res["has_upper"] == False

def test_weak_password_score():
    entropy, score, feedback, _ = analyze_password("12345")
    assert score <= 1 # Very weak
    assert len(feedback) > 0
    assert "Use at least 12 characters" in " ".join(feedback)

def test_strong_password_score():
    entropy, score, feedback, _ = analyze_password("G9$kL!mP2@vQ8zX3")
    assert score >= 3 # Strong or Very Strong
    assert entropy > 80

def test_empty_password():
    entropy, score, feedback, crack_time = analyze_password("")
    assert score == 0
    assert "empty" in feedback[0].lower()