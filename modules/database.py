"""
database.py — TotalWare scan history + users (SQLAlchemy ORM)
============================================================
Every scan is stored here. Login is optional — a logged-in user's scans
are linked to their account; guest scans are saved with user_id = NULL.

Currently SQLite (totalware.db). For production, set the DATABASE_URL env
variable to point at Postgres.
"""

import os
import json
import hashlib
import secrets
from datetime import datetime, timezone

from sqlalchemy import (
    create_engine, Column, Integer, String, Text, DateTime, ForeignKey, func, UniqueConstraint
)


def _utcnow():
    """Timezone-aware UTC now (datetime.utcnow() is deprecated in Python 3.12+)."""
    return datetime.now(timezone.utc)
from sqlalchemy.orm import declarative_base, sessionmaker
from werkzeug.security import generate_password_hash, check_password_hash

# ── Engine / session ─────────────────────────────────
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///totalware.db")
_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=_connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)
Base = declarative_base()


# ── User model ───────────────────────────────────────
class User(Base):
    __tablename__ = "users"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    created_at    = Column(DateTime, default=_utcnow)
    username      = Column(String(64), unique=True, index=True, nullable=False)
    email         = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)

    # ── The four attributes Flask-Login needs ──
    @property
    def is_authenticated(self): return True
    @property
    def is_active(self): return True
    @property
    def is_anonymous(self): return False
    def get_id(self): return str(self.id)

    def summary(self):
        return {"id": self.id, "username": self.username, "email": self.email}


# ── Scan model ───────────────────────────────────────
class Scan(Base):
    __tablename__ = "scans"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    created_at  = Column(DateTime, default=_utcnow, index=True)
    user_id     = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)  # guest = NULL

    filename    = Column(String(512), index=True)
    file_type   = Column(String(32))
    size_bytes  = Column(Integer, default=0)

    md5         = Column(String(32))
    sha1        = Column(String(40))
    sha256      = Column(String(64), index=True)

    verdict     = Column(String(32), index=True)
    score       = Column(Integer, default=0, index=True)
    engines_detected = Column(Integer, default=0)

    result_json = Column(Text)

    def summary(self):
        return {
            "id": self.id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "filename": self.filename,
            "file_type": self.file_type,
            "size_bytes": self.size_bytes or 0,
            "sha256": self.sha256,
            "verdict": self.verdict,
            "score": self.score or 0,
            "engines_detected": self.engines_detected or 0,
        }
    

    # ── API Key model ────────────────────────────────────
class ApiKey(Base):
    __tablename__ = "api_keys"

    id           = Column(Integer, primary_key=True, autoincrement=True)
    user_id      = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    created_at   = Column(DateTime, default=_utcnow)
    last_used_at = Column(DateTime, nullable=True)

    name         = Column(String(64))          # user-provided label, e.g. "my-script"
    key_prefix   = Column(String(16), index=True)   # for display, e.g. "tw_live_a3f9"
    key_hash     = Column(String(64), unique=True, index=True)  # sha256(full key)
    revoked      = Column(Integer, default=0)  # 0 = active, 1 = revoked

    def summary(self):
        return {
            "id": self.id,
            "name": self.name,
            "key_prefix": self.key_prefix,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "revoked": bool(self.revoked),
        }
    

    # ── Community Vote model ─────────────────────────────
class Vote(Base):
    __tablename__ = "votes"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    user_id    = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    sha256     = Column(String(64), index=True, nullable=False)
    vote       = Column(Integer, nullable=False)   # 1 = malicious, -1 = safe
    created_at = Column(DateTime, default=_utcnow)

    __table_args__ = (UniqueConstraint("user_id", "sha256", name="uq_user_file_vote"),)


# ── Organization models ──────────────────────────────
class Organization(Base):
    __tablename__ = "organizations"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    name        = Column(String(128), nullable=False)
    owner_id    = Column(Integer, ForeignKey("users.id"), nullable=False)
    invite_code = Column(String(16), unique=True, index=True)
    created_at  = Column(DateTime, default=_utcnow)

    def summary(self):
        return {"id": self.id, "name": self.name, "owner_id": self.owner_id,
                "invite_code": self.invite_code,
                "created_at": self.created_at.isoformat() if self.created_at else None}


class OrgMember(Base):
    __tablename__ = "org_members"

    id        = Column(Integer, primary_key=True, autoincrement=True)
    org_id    = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    user_id   = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    role      = Column(String(16), default="member")   # owner / member
    joined_at = Column(DateTime, default=_utcnow)

    __table_args__ = (UniqueConstraint("org_id", "user_id", name="uq_org_member"),)


# ── Init ─────────────────────────────────────────────
def init_db():
    Base.metadata.create_all(engine)


# ══════════════════════════════════════════════════════
#  USERS
# ══════════════════════════════════════════════════════
def create_user(username, email, password):
    """Create a new user. Returns (ok, msg_or_user_dict)."""
    session = SessionLocal()
    try:
        username = (username or "").strip()
        email = (email or "").strip().lower()
        if not username or not email or not password:
            return False, "Username, email, and password are all required"
        if len(password) < 6:
            return False, "Password must be at least 6 characters"

        exists = session.query(User).filter(
            (User.username == username) | (User.email == email)
        ).first()
        if exists:
            return False, "That username or email is already registered"

        user = User(
            username=username, email=email,
            password_hash=generate_password_hash(password),
        )
        session.add(user)
        session.commit()
        return True, user.summary()
    finally:
        session.close()


def verify_login(identifier, password):
    """Verify a username/email + password. Returns a user dict or None."""
    session = SessionLocal()
    try:
        ident = (identifier or "").strip().lower()
        user = session.query(User).filter(
            (func.lower(User.username) == ident) | (func.lower(User.email) == ident)
        ).first()
        if user and check_password_hash(user.password_hash, password or ""):
            return user.summary()
        return None
    finally:
        session.close()


def get_user_by_id(user_id):
    """For the Flask-Login user_loader — returns a detached User object."""
    session = SessionLocal()
    try:
        return session.get(User, int(user_id))
    finally:
        session.close()


# ══════════════════════════════════════════════════════
#  SCANS
# ══════════════════════════════════════════════════════
def _ext_of(filename):
    if not filename or "." not in filename:
        return "unknown"
    return filename.rsplit(".", 1)[-1].lower()


def save_scan(result, user_id=None):
    """Save a scan result (user_id optional — NULL for guests). Returns the row id."""
    hashes = result.get("hashes", {}) or {}
    risk   = result.get("risk_assessment", {}) or {}
    vt     = result.get("virustotal", {}) or {}
    vt_det = (vt.get("stats", {}) or {}).get("malicious", 0)

    session = SessionLocal()
    try:
        row = Scan(
            user_id=user_id,
            filename=result.get("filename", "unknown"),
            file_type=_ext_of(result.get("filename", "")),
            size_bytes=result.get("size_bytes", 0) or 0,
            md5=hashes.get("md5"),
            sha1=hashes.get("sha1"),
            sha256=hashes.get("sha256"),
            verdict=risk.get("verdict", "UNKNOWN"),
            score=risk.get("final_score", 0) or 0,
            engines_detected=vt_det or 0,
            result_json=json.dumps(result, ensure_ascii=False),
        )
        session.add(row)
        session.commit()
        return row.id
    finally:
        session.close()


def update_scan_result(scan_id, result, user_id=None):
    session = SessionLocal()
    try:
        row = session.get(Scan, scan_id)
        if not row:
            return False
        # If user_id is given, only the owner may update their own scan
        if user_id is not None and row.user_id is not None and row.user_id != user_id:
            return False
        risk = result.get("risk_assessment", {}) or {}
        row.verdict = risk.get("verdict", row.verdict)
        row.score = risk.get("final_score", row.score) or row.score
        row.result_json = json.dumps(result, ensure_ascii=False)
        session.commit()
        return True
    finally:
        session.close()


def list_scans(limit=100, offset=0, search=None, verdict=None, user_id=None):
    """History list — if user_id is given, only that user's scans."""
    session = SessionLocal()
    try:
        q = session.query(Scan)
        if user_id is not None:
            q = q.filter(Scan.user_id == user_id)
        if search:
            like = f"%{search}%"
            q = q.filter((Scan.filename.ilike(like)) | (Scan.sha256.ilike(like)))
        if verdict and verdict.upper() != "ALL":
            q = q.filter(Scan.verdict == verdict.upper())
        q = q.order_by(Scan.created_at.desc()).offset(offset).limit(limit)
        return [r.summary() for r in q.all()]
    finally:
        session.close()


def get_scan(scan_id, user_id=None):
    """Full result of one scan. If user_id is given, only their own scan can be opened."""
    session = SessionLocal()
    try:
        row = session.get(Scan, scan_id)
        if not row:
            return None
        if user_id is not None and row.user_id is not None and row.user_id != user_id:
            return None   # cannot open another user's scan
        data = row.summary()
        try:
            data["result"] = json.loads(row.result_json) if row.result_json else {}
        except Exception:
            data["result"] = {}
        return data
    finally:
        session.close()


def delete_scan(scan_id, user_id=None):
    session = SessionLocal()
    try:
        row = session.get(Scan, scan_id)
        if not row:
            return False
        if user_id is not None and row.user_id is not None and row.user_id != user_id:
            return False
        session.delete(row)
        session.commit()
        return True
    finally:
        session.close()


def get_stats(user_id=None):
    session = SessionLocal()
    try:
        q = session.query(func.count(Scan.id))
        if user_id is not None:
            q = q.filter(Scan.user_id == user_id)
        total = q.scalar() or 0

        qm = session.query(func.count(Scan.id)).filter(Scan.verdict.in_(["MALICIOUS", "SUSPICIOUS"]))
        qc = session.query(func.count(Scan.id)).filter(Scan.verdict.in_(["CLEAN", "POTENTIALLY UNWANTED"]))
        if user_id is not None:
            qm = qm.filter(Scan.user_id == user_id)
            qc = qc.filter(Scan.user_id == user_id)
        return {"total": total, "malicious": qm.scalar() or 0, "clean": qc.scalar() or 0}
    finally:
        session.close()


# ══════════════════════════════════════════════════════
#  API KEYS
# ══════════════════════════════════════════════════════
def _hash_key(raw):
    return hashlib.sha256(raw.encode()).hexdigest()


def create_api_key(user_id, name="default"):
    """Create a new API key. The raw key is returned ONLY here (never shown again)."""
    raw = "tw_live_" + secrets.token_urlsafe(32)
    session = SessionLocal()
    try:
        row = ApiKey(
            user_id=user_id,
            name=(name or "default").strip()[:64],
            key_prefix=raw[:12],
            key_hash=_hash_key(raw),
            revoked=0,
        )
        session.add(row)
        session.commit()
        summ = row.summary()
        summ["key"] = raw          # raw key — shown only once
        return summ
    finally:
        session.close()


def list_api_keys(user_id):
    session = SessionLocal()
    try:
        rows = session.query(ApiKey).filter(
            ApiKey.user_id == user_id, ApiKey.revoked == 0
        ).order_by(ApiKey.created_at.desc()).all()
        return [r.summary() for r in rows]
    finally:
        session.close()


def revoke_api_key(key_id, user_id):
    session = SessionLocal()
    try:
        row = session.get(ApiKey, key_id)
        if not row or row.user_id != user_id:
            return False
        row.revoked = 1
        session.commit()
        return True
    finally:
        session.close()


def verify_api_key(raw):
    """Verify a raw key. If valid, returns the user dict and updates last_used."""
    if not raw or not raw.startswith("tw_"):
        return None
    session = SessionLocal()
    try:
        row = session.query(ApiKey).filter(
            ApiKey.key_hash == _hash_key(raw), ApiKey.revoked == 0
        ).first()
        if not row:
            return None
        row.last_used_at = _utcnow()
        session.commit()
        user = session.get(User, row.user_id)
        return user.summary() if user else None
    finally:
        session.close()


# ══════════════════════════════════════════════════════
#  COMMUNITY VOTES
# ══════════════════════════════════════════════════════
def get_vote_summary(sha256, user_id=None):
    """Return vote counts for a file (and the current user's vote, if any)."""
    session = SessionLocal()
    try:
        mal = session.query(func.count(Vote.id)).filter(
            Vote.sha256 == sha256, Vote.vote == 1).scalar() or 0
        safe = session.query(func.count(Vote.id)).filter(
            Vote.sha256 == sha256, Vote.vote == -1).scalar() or 0
        my = None
        if user_id is not None:
            r = session.query(Vote).filter(
                Vote.user_id == user_id, Vote.sha256 == sha256).first()
            my = r.vote if r else None
        return {"malicious": mal, "safe": safe, "total": mal + safe, "my_vote": my}
    finally:
        session.close()


def cast_vote(user_id, sha256, vote):
    """Cast or update a user's vote (1 = malicious, -1 = safe)."""
    if vote not in (1, -1) or not sha256:
        return None
    session = SessionLocal()
    try:
        row = session.query(Vote).filter(
            Vote.user_id == user_id, Vote.sha256 == sha256).first()
        if row:
            row.vote = vote
        else:
            session.add(Vote(user_id=user_id, sha256=sha256, vote=vote))
        session.commit()
    finally:
        session.close()
    return get_vote_summary(sha256, user_id)


def community_feed(limit=50):
    """Recent malicious/suspicious samples with community vote counts (deduped by sha256)."""
    session = SessionLocal()
    try:
        rows = session.query(Scan).filter(
            Scan.verdict.in_(["MALICIOUS", "SUSPICIOUS"])
        ).order_by(Scan.created_at.desc()).limit(limit * 4).all()
        seen, feed = set(), []
        for r in rows:
            if r.sha256 in seen:
                continue
            seen.add(r.sha256)
            item = r.summary()
            mal = session.query(func.count(Vote.id)).filter(
                Vote.sha256 == r.sha256, Vote.vote == 1).scalar() or 0
            safe = session.query(func.count(Vote.id)).filter(
                Vote.sha256 == r.sha256, Vote.vote == -1).scalar() or 0
            item["votes"] = {"malicious": mal, "safe": safe, "total": mal + safe}
            feed.append(item)
            if len(feed) >= limit:
                break
        return feed
    finally:
        session.close()


# ══════════════════════════════════════════════════════
#  ORGANIZATIONS
# ══════════════════════════════════════════════════════
def create_org(owner_id, name):
    name = (name or "").strip()
    if not name:
        return None, "Organization name required"
    session = SessionLocal()
    try:
        org = Organization(name=name[:128], owner_id=owner_id,
                           invite_code=secrets.token_urlsafe(6))
        session.add(org)
        session.commit()
        session.add(OrgMember(org_id=org.id, user_id=owner_id, role="owner"))
        session.commit()
        return org.summary(), None
    finally:
        session.close()


def join_org(user_id, invite_code):
    session = SessionLocal()
    try:
        org = session.query(Organization).filter(
            Organization.invite_code == (invite_code or "").strip()).first()
        if not org:
            return None, "Invalid invite code"
        exists = session.query(OrgMember).filter(
            OrgMember.org_id == org.id, OrgMember.user_id == user_id).first()
        if not exists:
            session.add(OrgMember(org_id=org.id, user_id=user_id, role="member"))
            session.commit()
        return org.summary(), None
    finally:
        session.close()


def get_user_orgs(user_id):
    session = SessionLocal()
    try:
        rows = session.query(Organization).join(
            OrgMember, OrgMember.org_id == Organization.id).filter(
            OrgMember.user_id == user_id).order_by(Organization.created_at.desc()).all()
        return [o.summary() for o in rows]
    finally:
        session.close()


def get_org_dashboard(org_id, user_id, scan_limit=30):
    session = SessionLocal()
    try:
        org = session.get(Organization, org_id)
        is_member = session.query(OrgMember).filter(
            OrgMember.org_id == org_id, OrgMember.user_id == user_id).first() is not None
        if not org or not is_member:
            return None

        members = session.query(OrgMember, User).join(
            User, User.id == OrgMember.user_id).filter(
            OrgMember.org_id == org_id).all()
        member_list = [{"username": u.username, "email": u.email, "role": m.role,
                        "joined_at": m.joined_at.isoformat() if m.joined_at else None}
                       for m, u in members]
        member_ids = [u.id for m, u in members]

        scan_rows = session.query(Scan).filter(
            Scan.user_id.in_(member_ids)).order_by(Scan.created_at.desc()).limit(scan_limit).all()
        scans = [s.summary() for s in scan_rows]

        total = session.query(func.count(Scan.id)).filter(Scan.user_id.in_(member_ids)).scalar() or 0
        mal = session.query(func.count(Scan.id)).filter(
            Scan.user_id.in_(member_ids),
            Scan.verdict.in_(["MALICIOUS", "SUSPICIOUS"])).scalar() or 0

        alerts = [s for s in scans if s.get("verdict") in ("MALICIOUS", "SUSPICIOUS")][:10]
        return {
            "org": org.summary(),
            "is_owner": org.owner_id == user_id,
            "members": member_list,
            "stats": {"total": total, "malicious": mal, "clean": total - mal, "members": len(member_ids)},
            "scans": scans,
            "alerts": alerts,
        }
    finally:
        session.close()