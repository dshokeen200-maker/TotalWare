"""
test_database.py — tests for the database layer (users, scans, votes, API keys, orgs).

Run from the project root:
    pip install pytest SQLAlchemy Flask-Login
    pytest test_database.py -v

Uses a throwaway SQLite file (test_totalware.db) so your real totalware.db is untouched.
"""

import os
import tempfile

# Point the DB at a throwaway file BEFORE importing the database module.
_TEST_DB = os.path.join(tempfile.gettempdir(), "totalware_test.db")
if os.path.exists(_TEST_DB):
    os.remove(_TEST_DB)
os.environ["DATABASE_URL"] = "sqlite:///" + _TEST_DB.replace("\\", "/")

from modules import database as db  # noqa: E402

db.init_db()


def _clean_result(name="sample.apk", verdict="CLEAN", score=10, sha="a" * 64):
    return {
        "filename": name,
        "size_bytes": 12345,
        "hashes": {"md5": "m", "sha1": "s", "sha256": sha},
        "risk_assessment": {"verdict": verdict, "final_score": score},
        "virustotal": {"stats": {"malicious": 0, "total_engines": 70}},
    }


# ─────────────────────────── USERS ───────────────────────────

def test_create_and_login_user():
    ok, res = db.create_user("alice", "alice@example.com", "secret123")
    assert ok, res
    assert res["username"] == "alice"

    # correct password
    assert db.verify_login("alice", "secret123") is not None
    # login by email, case-insensitive
    assert db.verify_login("ALICE@EXAMPLE.COM", "secret123") is not None
    # wrong password
    assert db.verify_login("alice", "wrong") is None


def test_duplicate_and_weak_password():
    db.create_user("bob", "bob@example.com", "secret123")
    ok, msg = db.create_user("bob", "bob2@example.com", "secret123")   # duplicate username
    assert not ok
    ok, msg = db.create_user("charlie", "c@example.com", "123")        # too short
    assert not ok


# ─────────────────────────── SCANS ───────────────────────────

def test_save_and_list_scans_per_user():
    ok, alice = db.create_user("scanuser", "scan@example.com", "secret123")
    uid = alice["id"]
    sid = db.save_scan(_clean_result("a.apk", "CLEAN", 10, "b" * 64), user_id=uid)
    db.save_scan(_clean_result("b.apk", "MALICIOUS", 90, "c" * 64), user_id=uid)

    mine = db.list_scans(user_id=uid)
    assert len(mine) == 2
    names = {s["filename"] for s in mine}
    assert names == {"a.apk", "b.apk"}

    # a different user sees none of these
    ok, other = db.create_user("other", "other@example.com", "secret123")
    assert db.list_scans(user_id=other["id"]) == []

    # ownership on get_scan
    assert db.get_scan(sid, user_id=uid) is not None
    assert db.get_scan(sid, user_id=other["id"]) is None


def test_stats_and_delete():
    ok, u = db.create_user("statsuser", "stats@example.com", "secret123")
    uid = u["id"]
    db.save_scan(_clean_result("x.apk", "MALICIOUS", 90, "d" * 64), user_id=uid)
    sid = db.save_scan(_clean_result("y.apk", "CLEAN", 5, "e" * 64), user_id=uid)

    stats = db.get_stats(user_id=uid)
    assert stats["total"] == 2
    assert stats["malicious"] == 1
    assert stats["clean"] == 1

    assert db.delete_scan(sid, user_id=uid) is True
    assert db.get_stats(user_id=uid)["total"] == 1


# ─────────────────────────── API KEYS ───────────────────────────

def test_api_key_lifecycle():
    ok, u = db.create_user("keyuser", "key@example.com", "secret123")
    uid = u["id"]
    created = db.create_api_key(uid, "my-script")
    raw = created["key"]
    assert raw.startswith("tw_live_")

    # verify works, updates last_used, returns the owning user
    who = db.verify_api_key(raw)
    assert who is not None and who["id"] == uid

    # listed (without the raw key)
    keys = db.list_api_keys(uid)
    assert len(keys) == 1
    assert "key" not in keys[0]

    # revoke -> verify now fails
    assert db.revoke_api_key(created["id"], uid) is True
    assert db.verify_api_key(raw) is None
    assert db.list_api_keys(uid) == []


def test_bad_api_key():
    assert db.verify_api_key("not-a-key") is None
    assert db.verify_api_key("") is None


# ─────────────────────────── COMMUNITY VOTES ───────────────────────────

def test_voting():
    ok, u1 = db.create_user("voter1", "v1@example.com", "secret123")
    ok, u2 = db.create_user("voter2", "v2@example.com", "secret123")
    sha = "f" * 64

    db.cast_vote(u1["id"], sha, 1)    # malicious
    db.cast_vote(u2["id"], sha, -1)   # safe
    s = db.get_vote_summary(sha)
    assert s["malicious"] == 1 and s["safe"] == 1 and s["total"] == 2

    # re-voting updates (does not add a second vote)
    db.cast_vote(u1["id"], sha, -1)
    s = db.get_vote_summary(sha, user_id=u1["id"])
    assert s["malicious"] == 0 and s["safe"] == 2
    assert s["my_vote"] == -1


# ─────────────────────────── ORGANIZATIONS ───────────────────────────

def test_org_create_join_dashboard():
    ok, owner = db.create_user("orgowner", "own@example.com", "secret123")
    ok, member = db.create_user("orgmember", "mem@example.com", "secret123")

    org, err = db.create_org(owner["id"], "Acme Security")
    assert err is None
    assert org["invite_code"]

    # member joins via invite code
    joined, err = db.join_org(member["id"], org["invite_code"])
    assert err is None and joined["id"] == org["id"]

    # bad invite code
    _, err = db.join_org(member["id"], "wrong-code")
    assert err is not None

    # both see the org
    assert len(db.get_user_orgs(owner["id"])) == 1
    assert len(db.get_user_orgs(member["id"])) == 1

    # a member scan shows up in the dashboard
    db.save_scan(_clean_result("team.apk", "MALICIOUS", 88, "1" * 64), user_id=member["id"])
    dash = db.get_org_dashboard(org["id"], owner["id"])
    assert dash is not None
    assert dash["stats"]["members"] == 2
    assert dash["stats"]["malicious"] >= 1
    assert len(dash["alerts"]) >= 1

    # a non-member cannot view the dashboard
    ok, outsider = db.create_user("outsider", "out@example.com", "secret123")
    assert db.get_org_dashboard(org["id"], outsider["id"]) is None
