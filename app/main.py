import os, hashlib, base64, re, html, json, secrets
from collections import Counter
from datetime import datetime, timezone
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, Request
from fastapi.responses import Response, HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, LargeBinary, or_
from sqlalchemy.orm import declarative_base, sessionmaker
from cryptography.fernet import Fernet
from pydantic import BaseModel

SECRET = os.getenv("SECRET_KEY", "dev-secret-change-me")
DBURL = os.getenv("DATABASE_URL", "sqlite:///dems.db").replace("postgres://", "postgresql://", 1)
fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(SECRET.encode()).digest()))  # encrypts files at rest
engine = create_engine(DBURL, pool_pre_ping=True, connect_args={"check_same_thread": False} if DBURL.startswith("sqlite") else {})
Session = sessionmaker(engine)
Base = declarative_base()
MAX_MB = 25
DEPTS = ["Forensic", "Cyber", "Ballistics", "Medical", "CCTV & Surveillance", "Financial", "Witness & Statements", "General"]
TYPES = ["Image", "Video", "Audio", "Document", "Email", "CCTV Footage", "Other"]
PRIOS = ["Critical", "High", "Medium", "Low"]
now = lambda: datetime.now(timezone.utc).replace(tzinfo=None)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True); username = Column(String(50), unique=True); name = Column(String(100))
    role = Column(String(20)); pw = Column(String(200))  # role: admin | investigator | viewer
class Case(Base):
    __tablename__ = "cases"
    id = Column(Integer, primary_key=True); number = Column(String(40), unique=True); title = Column(String(200))
    crime_type = Column(String(60)); description = Column(Text, default=""); status = Column(String(20), default="Open")
    created_by = Column(String(50)); created_at = Column(DateTime, default=now)
class Evidence(Base):
    __tablename__ = "evidence"
    id = Column(Integer, primary_key=True); eid = Column(String(30), unique=True, index=True)
    case_id = Column(Integer, index=True); title = Column(String(200)); description = Column(Text, default="")
    etype = Column(String(30)); dept = Column(String(40)); priority = Column(String(10))
    collected_at = Column(DateTime); uploaded_at = Column(DateTime, default=now)
    collected_by = Column(String(100), default=""); location = Column(String(200), default=""); tags = Column(Text, default="")
    filename = Column(String(255)); mime = Column(String(100)); size = Column(Integer); sha256 = Column(String(64))
    holder = Column(String(50)); meta = Column(Text, default="{}"); data = Column(LargeBinary)
class Log(Base):  # one table: rows with evidence_id = chain of custody, all rows = audit log
    __tablename__ = "logs"
    id = Column(Integer, primary_key=True); ts = Column(DateTime, default=now); user = Column(String(50))
    action = Column(String(40)); evidence_id = Column(String(30), index=True); case_id = Column(Integer); detail = Column(Text, default="")
Base.metadata.create_all(engine)

def hash_pw(p, salt=None):
    salt = salt or secrets.token_hex(8)
    return salt + "$" + hashlib.scrypt(p.encode(), salt=salt.encode(), n=2**14, r=8, p=1).hex()
def check_pw(p, stored):
    return secrets.compare_digest(hash_pw(p, stored.split("$")[0]), stored)
with Session() as s:
    if not s.query(User).first():
        pw = os.getenv("ADMIN_PASSWORD", "admin123")
        s.add(User(username=os.getenv("ADMIN_USER", "admin"), name="Administrator", role="admin", pw=hash_pw(pw))); s.commit()

app = FastAPI(title="DEMS")
app.add_middleware(SessionMiddleware, secret_key=SECRET, https_only=bool(os.getenv("RENDER")), same_site="strict", max_age=8 * 3600)

def db():
    with Session() as s: yield s
def me(request: Request, s=Depends(db)):
    u = s.get(User, request.session.get("uid") or 0)
    if not u: raise HTTPException(401, "Please log in")
    return u
def need(*roles):  # role-based access control
    def dep(u=Depends(me)):
        if u.role not in roles: raise HTTPException(403, f"Your role ({u.role}) cannot do this")
        return u
    return dep
def log(s, u, action, ev=None, case=None, detail=""):
    s.add(Log(user=u if isinstance(u, str) else u.username, action=action, evidence_id=ev, case_id=case, detail=detail))

def guess(filename, mime):
    ext = os.path.splitext(filename)[1].lower()
    if mime.startswith("image/"): t = "Image"
    elif mime.startswith("video/"): t = "CCTV Footage" if re.search(r"cctv|cam|surv", filename, re.I) else "Video"
    elif mime.startswith("audio/"): t = "Audio"
    elif ext in (".eml", ".msg", ".mbox"): t = "Email"
    elif ext in (".pdf", ".doc", ".docx", ".txt", ".xls", ".xlsx", ".csv", ".ppt", ".pptx"): t = "Document"
    else: t = "Other"
    d = {"Image": "Forensic", "Video": "CCTV & Surveillance", "CCTV Footage": "CCTV & Surveillance", "Email": "Cyber", "Audio": "Witness & Statements", "Document": "General"}.get(t, "General")
    return t, d

def extract_meta(raw, filename, mime):  # simple rule-based "AI": metadata + keyword extraction
    m = {}
    if mime.startswith("image/"):
        try:
            import io
            from PIL import Image
            im = Image.open(io.BytesIO(raw)); m["dimensions"] = f"{im.width}x{im.height}"
            ex = im.getexif()
            if ex.get(272) or ex.get(271): m["camera"] = f"{ex.get(271,'')} {ex.get(272,'')}".strip()
            if ex.get(306): m["photo_taken"] = str(ex.get(306))
        except Exception: pass
    if mime.startswith("text/") or filename.lower().endswith((".txt", ".eml", ".csv", ".log")):
        words = re.findall(r"[a-zA-Z]{5,}", raw[:200000].decode("utf-8", "ignore").lower())
        m["keywords"] = [w for w, _ in Counter(words).most_common(8)]
    return m

def ev_dict(e, full=False):
    d = {k: getattr(e, k) for k in ("eid", "case_id", "title", "description", "etype", "dept", "priority", "collected_by", "location", "tags", "filename", "mime", "size", "sha256", "holder")}
    d["collected_at"] = e.collected_at.isoformat(); d["uploaded_at"] = e.uploaded_at.isoformat(); d["meta"] = json.loads(e.meta or "{}")
    return d
def get_ev(s, eid):
    e = s.query(Evidence).filter_by(eid=eid).first()
    if not e: raise HTTPException(404, "Evidence not found")
    return e
def plain(e): return fernet.decrypt(e.data)

class LoginIn(BaseModel): username: str; password: str
class CaseIn(BaseModel): number: str; title: str; crime_type: str; description: str = ""
class UserIn(BaseModel): username: str; name: str; password: str; role: str
class TransferIn(BaseModel): to: str; reason: str

@app.post("/api/login")
def login(b: LoginIn, request: Request, s=Depends(db)):
    u = s.query(User).filter_by(username=b.username).first()
    if not u or not check_pw(b.password, u.pw):
        log(s, b.username[:50], "LOGIN_FAILED"); s.commit(); raise HTTPException(401, "Wrong username or password")
    request.session["uid"] = u.id; log(s, u, "LOGIN"); s.commit()
    return {"username": u.username, "name": u.name, "role": u.role}
@app.post("/api/logout")
def logout(request: Request): request.session.clear(); return {"ok": True}
@app.get("/api/me")
def whoami(u=Depends(me)): return {"username": u.username, "name": u.name, "role": u.role, "depts": DEPTS, "types": TYPES, "prios": PRIOS}

@app.get("/api/users")
def users(u=Depends(me), s=Depends(db)): return [{"username": x.username, "name": x.name, "role": x.role} for x in s.query(User)]
@app.post("/api/users")
def add_user(b: UserIn, u=Depends(need("admin")), s=Depends(db)):
    if b.role not in ("admin", "investigator", "viewer"): raise HTTPException(400, "Role must be admin, investigator or viewer")
    if len(b.password) < 8: raise HTTPException(400, "Password needs 8+ characters")
    if s.query(User).filter_by(username=b.username).first(): raise HTTPException(400, "Username already exists")
    s.add(User(username=b.username, name=b.name, role=b.role, pw=hash_pw(b.password))); log(s, u, "USER_CREATED", detail=f"{b.username} ({b.role})"); s.commit()
    return {"ok": True}

@app.get("/api/cases")
def cases(u=Depends(me), s=Depends(db)):
    n = dict(Counter(e.case_id for e in s.query(Evidence.case_id)))
    return [{"id": c.id, "number": c.number, "title": c.title, "crime_type": c.crime_type, "description": c.description, "status": c.status, "created_at": c.created_at.isoformat(), "evidence_count": n.get(c.id, 0)} for c in s.query(Case).order_by(Case.id.desc())]
@app.post("/api/cases")
def add_case(b: CaseIn, u=Depends(need("admin", "investigator")), s=Depends(db)):
    if s.query(Case).filter_by(number=b.number).first(): raise HTTPException(400, "Case number already exists")
    c = Case(number=b.number, title=b.title, crime_type=b.crime_type, description=b.description, created_by=u.username); s.add(c); s.flush()
    log(s, u, "CASE_CREATED", case=c.id, detail=b.number); s.commit(); return {"id": c.id}

@app.post("/api/evidence")
async def upload(file: UploadFile = File(...), case_id: int = Form(...), title: str = Form(...), description: str = Form(""), etype: str = Form("Auto"),
                 dept: str = Form("Auto"), priority: str = Form("Medium"), collected_at: str = Form(...), collected_by: str = Form(""),
                 location: str = Form(""), tags: str = Form(""), u=Depends(need("admin", "investigator")), s=Depends(db)):
    if not s.get(Case, case_id): raise HTTPException(400, "Choose a valid case")
    raw = await file.read()
    if len(raw) > MAX_MB * 1024 * 1024: raise HTTPException(413, f"File is over {MAX_MB} MB")
    if not raw: raise HTTPException(400, "File is empty")
    try: col = datetime.fromisoformat(collected_at)
    except ValueError: raise HTTPException(400, "Invalid collection date")
    mime = file.content_type or "application/octet-stream"
    gt, gd = guess(file.filename, mime)
    meta = extract_meta(raw, file.filename, mime); meta["auto_classified"] = {"type": etype == "Auto", "dept": dept == "Auto"}
    n = s.query(Evidence).count() + 1
    e = Evidence(eid=f"EV-{now().year}-{n:05d}", case_id=case_id, title=title, description=description, etype=gt if etype == "Auto" else etype,
                 dept=gd if dept == "Auto" else dept, priority=priority, collected_at=col, collected_by=collected_by or u.name, location=location,
                 tags=tags, filename=file.filename, mime=mime, size=len(raw), sha256=hashlib.sha256(raw).hexdigest(), holder=u.username,
                 meta=json.dumps(meta), data=fernet.encrypt(raw))
    s.add(e); log(s, u, "UPLOADED", e.eid, case_id, f"SHA-256 {e.sha256}"); s.commit()
    return ev_dict(e)

@app.get("/api/evidence")
def search(case_id: int = None, dept: str = None, etype: str = None, priority: str = None, q: str = None, date_from: str = None, date_to: str = None,
           u=Depends(me), s=Depends(db)):
    qs = s.query(Evidence)
    if case_id: qs = qs.filter(Evidence.case_id == case_id)
    if dept: qs = qs.filter(Evidence.dept == dept)
    if etype: qs = qs.filter(Evidence.etype == etype)
    if priority: qs = qs.filter(Evidence.priority == priority)
    if date_from: qs = qs.filter(Evidence.collected_at >= datetime.fromisoformat(date_from))
    if date_to: qs = qs.filter(Evidence.collected_at <= datetime.fromisoformat(date_to + "T23:59:59"))
    if q:
        like = f"%{q}%"; qs = qs.filter(or_(Evidence.eid.ilike(like), Evidence.title.ilike(like), Evidence.description.ilike(like), Evidence.tags.ilike(like), Evidence.filename.ilike(like), Evidence.meta.ilike(like)))
    return [ev_dict(e) for e in qs.order_by(Evidence.collected_at)]

@app.get("/api/evidence/{eid}")
def detail(eid: str, u=Depends(me), s=Depends(db)):
    e = get_ev(s, eid); log(s, u, "VIEWED", eid, e.case_id); s.commit()
    chain = s.query(Log).filter_by(evidence_id=eid).order_by(Log.ts).all()
    return {**ev_dict(e), "custody": [{"ts": l.ts.isoformat(), "user": l.user, "action": l.action, "detail": l.detail} for l in chain]}
@app.get("/api/evidence/{eid}/file")
def file(eid: str, download: int = 0, u=Depends(me), s=Depends(db)):
    e = get_ev(s, eid); log(s, u, "DOWNLOADED" if download else "PREVIEWED", eid, e.case_id); s.commit()
    safe = re.sub(r'[^\w.\- ]', "_", e.filename)
    return Response(plain(e), media_type=e.mime, headers={"Content-Disposition": f'{"attachment" if download else "inline"}; filename="{safe}"',
                    "X-Content-Type-Options": "nosniff", "Content-Security-Policy": "sandbox"})
@app.post("/api/evidence/{eid}/verify")
def verify(eid: str, u=Depends(need("admin", "investigator")), s=Depends(db)):
    e = get_ev(s, eid); now_hash = hashlib.sha256(plain(e)).hexdigest(); ok = now_hash == e.sha256
    log(s, u, "INTEGRITY_OK" if ok else "INTEGRITY_FAILED", eid, e.case_id, f"Recomputed SHA-256 {now_hash}"); s.commit()
    return {"ok": ok, "stored": e.sha256, "current": now_hash}
@app.post("/api/evidence/{eid}/transfer")
def transfer(eid: str, b: TransferIn, u=Depends(need("admin", "investigator")), s=Depends(db)):
    e = get_ev(s, eid)
    if not s.query(User).filter_by(username=b.to).first(): raise HTTPException(400, "Unknown user")
    log(s, u, "TRANSFERRED", eid, e.case_id, f"{e.holder} -> {b.to}. Reason: {b.reason}"); e.holder = b.to; s.commit(); return {"ok": True}

@app.get("/api/stats")
def stats(u=Depends(me), s=Depends(db)):
    ev = s.query(Evidence.dept, Evidence.priority, Evidence.etype).all()
    return {"total": len(ev), "cases": s.query(Case).count(), "by_dept": Counter(x[0] for x in ev), "by_priority": Counter(x[1] for x in ev), "by_type": Counter(x[2] for x in ev)}
@app.get("/api/audit")
def audit(u=Depends(need("admin")), s=Depends(db)):
    return [{"ts": l.ts.isoformat(), "user": l.user, "action": l.action, "evidence_id": l.evidence_id, "detail": l.detail} for l in s.query(Log).order_by(Log.id.desc()).limit(500)]

@app.get("/api/cases/{cid}/report", response_class=HTMLResponse)
def report(cid: int, u=Depends(me), s=Depends(db)):
    c = s.get(Case, cid)
    if not c: raise HTTPException(404, "Case not found")
    h = html.escape; log(s, u, "REPORT_GENERATED", case=cid); s.commit()
    rows = ""
    for e in s.query(Evidence).filter_by(case_id=cid).order_by(Evidence.collected_at):
        ch = "<br>".join(f"{l.ts:%Y-%m-%d %H:%M} {h(l.user)} {l.action} {h(l.detail)}" for l in s.query(Log).filter_by(evidence_id=e.eid).order_by(Log.ts))
        rows += f"<tr><td>{e.eid}<br>{e.priority}</td><td>{e.collected_at:%Y-%m-%d %H:%M}</td><td><b>{h(e.title)}</b><br>{h(e.etype)} / {h(e.dept)}<br>{h(e.filename)}</td><td style='font-family:monospace;font-size:10px;word-break:break-all'>{e.sha256}</td><td style='font-size:11px'>{ch}</td></tr>"
    return f"""<meta charset=utf-8><title>Report {h(c.number)}</title><style>body{{font:13px sans-serif;margin:30px}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #999;padding:6px;vertical-align:top;text-align:left}}</style>
<button onclick=print() style="float:right">Print / Save as PDF</button><h1>Investigation Report: {h(c.number)}</h1><p><b>{h(c.title)}</b> ({h(c.crime_type)}, {c.status})<br>{h(c.description)}<br>Generated {now():%Y-%m-%d %H:%M} UTC by {h(u.username)}</p>
<table><tr><th>Evidence</th><th>Collected</th><th>Details</th><th>SHA-256</th><th>Chain of custody</th></tr>{rows}</table>"""

app.mount("/", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "..", "static"), html=True), name="static")
