"""Adds sample cases, users and evidence for testing.  Run:  python seed.py
Safe to run twice: cases that already exist are skipped."""
import io, json, wave, math, struct, hashlib, mimetypes, re, textwrap
from datetime import timedelta
import random, sys
from PIL import Image, ImageDraw, ImageFont, ImageOps
from app.main import Session, Case, Evidence, User, Log, fernet, hash_pw, extract_meta, now

USERS = [("inspector.rao", "Inspector Rao", "investigator"), ("analyst.sen", "Analyst Sen", "investigator"), ("auditor.mehta", "Auditor Mehta", "viewer")]
PW = "Test@1234"
# title, description, type, department, priority, hours after case start, location, tags, file kind
CASES = [
 ("MUR-2026-001", "Riverside Apartment Homicide", "Murder", 30, "Male victim found in flat 4B. Forced entry ruled out.", [
  ("Living room scene photo", "Overturned table and blood pool near sofa.", "Image", "Forensic", "Critical", 1, "Flat 4B", "scene,blood", "img"),
  ("Kitchen knife photo", "Knife recovered from sink, sent for DNA.", "Image", "Forensic", "Critical", 2, "Flat 4B kitchen", "weapon,dna", "img"),
  ("Fingerprint lift report", "Partial prints on door handle and glass.", "Document", "Forensic", "High", 9, "Forensic lab", "fingerprint", "txt"),
  ("Preliminary autopsy report", "Cause of death: sharp force trauma.", "Document", "Medical", "Critical", 20, "City mortuary", "autopsy", "txt"),
  ("Toxicology results", "No alcohol. Sedative traces found.", "Document", "Medical", "High", 40, "State lab", "toxicology", "txt"),
  ("Lobby CCTV 22:14", "Unknown male enters building.", "CCTV Footage", "CCTV & Surveillance", "High", 5, "Building lobby", "cctv,suspect", "img"),
  ("Parking CCTV 22:41", "Same male leaves in a dark hatchback.", "CCTV Footage", "CCTV & Surveillance", "High", 6, "Parking lot", "cctv,vehicle", "img"),
  ("Neighbour statement recording", "Heard shouting around 22:20.", "Audio", "Witness & Statements", "Medium", 12, "Flat 4A", "witness", "wav"),
  ("Emergency call recording", "Caller reports screams from flat 4B.", "Audio", "Witness & Statements", "High", 3, "Control room", "call112", "wav"),
  ("Victim phone chat export", "Messages with an unknown number.", "Document", "Cyber", "High", 30, "Victim phone", "chat,phone", "csv"),
  ("Threat email to victim", "Email received 3 days before the incident.", "Email", "Cyber", "Medium", 33, "Victim mailbox", "threat,email", "eml"),
  ("Bank statement, last 30 days", "Large cash withdrawal two days earlier.", "Document", "Financial", "Low", 50, "Bank records", "bank", "csv")]),
 ("THF-2026-014", "Jewellery Store Burglary", "Theft", 20, "Night burglary at a jewellery shop. Gold and diamonds stolen.", [
  ("Broken shutter lock photo", "Lock cut with a hydraulic cutter.", "Image", "Forensic", "High", 2, "Shop front", "lock,entry", "img"),
  ("Footprint cast photo", "Size 9 boot print in the rear alley.", "Image", "Forensic", "Medium", 4, "Rear alley", "footprint", "img"),
  ("Shop front CCTV 02:10", "Two masked persons at the shutter.", "CCTV Footage", "CCTV & Surveillance", "High", 1, "Shop front", "cctv,masked", "img"),
  ("Alley CCTV 02:31", "Suspects leave with bags, one limping.", "CCTV Footage", "CCTV & Surveillance", "Critical", 1, "Rear alley", "cctv,escape", "img"),
  ("Stolen inventory list", "42 items, total value 38 lakh.", "Document", "Financial", "High", 10, "Shop office", "inventory,value", "csv"),
  ("Insurance valuation", "Insurer report on declared stock.", "Document", "Financial", "Low", 70, "Insurer", "insurance", "txt"),
  ("Alarm system log", "Alarm disabled remotely at 02:04.", "Document", "Cyber", "Medium", 8, "Alarm panel", "alarm,log", "csv"),
  ("Owner written statement", "Owner lists missing items and staff.", "Document", "Witness & Statements", "Medium", 6, "Police station", "owner", "txt"),
  ("Security guard interview", "Guard says he left post for tea at 02:00.", "Audio", "Witness & Statements", "Medium", 14, "Police station", "guard,interview", "wav"),
  ("Pawn shop tip email", "Email says someone is selling gold bars.", "Email", "Cyber", "Medium", 96, "Tip line", "tip,pawn", "eml"),
  ("Glove fibre analysis", "Wool fibres found on the shutter.", "Document", "Forensic", "High", 48, "Forensic lab", "fibre", "txt"),
  ("Getaway vehicle sighting photo", "Van seen near the market.", "Image", "General", "Low", 30, "Market road", "vehicle,van", "img")]),
 ("CYB-2026-007", "Bank Phishing Campaign", "Cybercrime", 12, "Fake bank site stole login details of 63 customers.", [
  ("Original phishing email", "Email asking users to update KYC.", "Email", "Cyber", "Critical", 1, "Customer inbox", "phishing,email", "eml"),
  ("Email header analysis", "Sent from a relay server in another country.", "Document", "Cyber", "High", 8, "Cyber cell", "headers,ip", "txt"),
  ("Fake website screenshot", "Copy of the bank login page.", "Image", "Cyber", "High", 3, "Fake domain", "website,screenshot", "img"),
  ("Server access logs", "Login attempts from 12 IP addresses.", "Document", "Cyber", "Critical", 15, "Hosting server", "logs,ip", "csv"),
  ("Victim complaint statement", "Customer lost 1.2 lakh.", "Document", "Witness & Statements", "Medium", 2, "Cyber cell", "victim", "txt"),
  ("Transaction trail", "Money moved through 5 accounts in 40 minutes.", "Document", "Financial", "Critical", 20, "Bank records", "transactions", "csv"),
  ("Mule account KYC documents", "Accounts opened with forged IDs.", "Document", "Financial", "High", 26, "Bank branch", "mule,kyc", "txt"),
  ("Scammer call recording", "Caller poses as bank officer.", "Audio", "Witness & Statements", "High", 5, "Victim phone", "call,voice", "wav"),
  ("Malware sample report", "Credential stealer found on fake site.", "Document", "Cyber", "High", 30, "Malware lab", "malware", "txt"),
  ("Domain registration record", "Domain registered 4 days before the attack.", "Document", "Cyber", "Medium", 10, "Registrar", "domain,whois", "txt"),
  ("SMS lure screenshot", "SMS with the shortened link.", "Image", "General", "Medium", 4, "Victim phone", "sms,link", "img"),
  ("Bank internal alert email", "Fraud team raised the alert.", "Email", "Financial", "Low", 6, "Bank", "alert", "eml"),
  ("Suspect laptop imaging report", "Disk image hash and tool details.", "Document", "Forensic", "High", 60, "Cyber lab", "laptop,imaging", "txt")]),
 ("HNR-2026-021", "Highway Hit-and-Run", "Hit and Run", 5, "Pedestrian hit on the bypass road. Vehicle fled.", [
  ("Skid marks photo", "Braking marks 18 metres long.", "Image", "Forensic", "High", 1, "Bypass road km 14", "skid,road", "img"),
  ("Paint fragment photo", "Silver paint chips on the road.", "Image", "Forensic", "High", 2, "Bypass road km 14", "paint,vehicle", "img"),
  ("Dashcam frame", "Silver sedan, partial plate visible.", "CCTV Footage", "CCTV & Surveillance", "Critical", 3, "Passing truck", "dashcam,plate", "img"),
  ("Toll plaza CCTV", "Same sedan passes toll 12 minutes later.", "CCTV Footage", "CCTV & Surveillance", "High", 4, "Toll plaza", "toll,cctv", "img"),
  ("Victim medical report", "Multiple fractures, ICU admission.", "Document", "Medical", "Critical", 6, "City hospital", "medical,injury", "txt"),
  ("Injury photographs", "Photos for medico-legal record.", "Image", "Medical", "High", 7, "City hospital", "injury", "img"),
  ("Witness call recording", "Caller saw a silver car speed away.", "Audio", "Witness & Statements", "Medium", 2, "Control room", "witness,call", "wav"),
  ("Witness written statement", "Shopkeeper statement.", "Document", "Witness & Statements", "Medium", 10, "Police station", "witness", "txt"),
  ("Vehicle registration trace", "Plate matches 3 possible owners.", "Document", "General", "Medium", 18, "Transport office", "rto,plate", "txt"),
  ("Mobile tower location data", "Suspect phone near the spot at 21:50.", "Document", "Cyber", "High", 40, "Telecom", "tower,location", "csv"),
  ("Garage repair invoice", "Front bumper repaired the next day.", "Document", "Financial", "Medium", 52, "Auto garage", "garage,invoice", "txt"),
  ("Fuel station receipt photo", "Receipt shows suspect vehicle after the incident.", "Image", "Financial", "Low", 20, "Fuel station", "receipt", "img"),
  ("Accident reconstruction note", "Estimated speed 80 km/h.", "Document", "Forensic", "High", 45, "Forensic lab", "reconstruction", "txt")])]

def F(n):
    try: return ImageFont.load_default(size=n)
    except TypeError: return ImageFont.load_default()
def save(im):
    b = io.BytesIO(); im.save(b, "PNG"); return b.getvalue()
def cctv(label, seed, col):  # night-vision style CCTV frame
    r = random.Random(seed); W, H = 640, 400
    sc = Image.new("L", (W, H), 55); d = ImageDraw.Draw(sc)
    d.polygon([(0, 250), (W, 250), (W, H), (0, H)], fill=95)
    d.rectangle([80, 90, 180, 250], fill=30); d.rectangle([440, 60, 580, 170], fill=120)
    for _ in range(r.randint(1, 2)):
        x = r.randint(200, 500); h = r.randint(130, 170); y = r.randint(335, 365)
        d.ellipse([x - 15, y - h, x + 15, y - h + 30], fill=12); d.rectangle([x - 24, y - h + 30, x + 24, y - 55], fill=12)
        d.rectangle([x - 20, y - 55, x - 4, y], fill=12); d.rectangle([x + 4, y - 55, x + 20, y], fill=12)
    im = Image.blend(sc, Image.effect_noise((W, H), 40), 0.3)
    im = ImageOps.colorize(im, (0, 8, 0), (150, 255, 150)); d = ImageDraw.Draw(im)
    for y in range(0, H, 4): d.line([(0, y), (W, y)], fill=(0, 30, 0))
    d.text((16, 12), "CAM 03", font=F(24), fill=(220, 255, 220)); d.text((W - 90, 12), "REC", font=F(24), fill=(255, 70, 70))
    d.text((16, 44), label, font=F(16), fill=(220, 255, 220)); d.text((16, H - 38), col.strftime("%d-%m-%Y  %H:%M:%S"), font=F(24), fill=(220, 255, 220))
    return save(im)
def photo(label, seed, col):  # scene photo with numbered evidence markers
    r = random.Random(seed); W, H = 640, 400
    im = Image.new("RGB", (W, H)); d = ImageDraw.Draw(im)
    top = (120 + r.randint(0, 60), 130 + r.randint(0, 60), 140 + r.randint(0, 60))
    for y in range(H): d.line([(0, y), (W, y)], fill=tuple(int(c * (1 - 0.5 * y / H)) for c in top))
    d.rectangle([0, 230, W, H], fill=(88, 80, 72))
    for _ in range(6):
        x, y = r.randint(20, 560), r.randint(250, 340); d.ellipse([x, y, x + r.randint(20, 60), y + r.randint(8, 20)], fill=(70, 62, 56))
    for n in range(r.randint(1, 3)):
        x = 100 + n * 170 + r.randint(0, 40); d.polygon([(x, 320), (x + 38, 320), (x + 31, 265), (x + 7, 265)], fill=(245, 200, 40)); d.text((x + 13, 280), str(n + 1), font=F(24), fill=(20, 20, 20))
    d.rectangle([0, H - 80, W, H], fill=(20, 28, 48))
    d.text((16, H - 76), "\n".join(textwrap.wrap(label, 40)), font=F(20), fill=(255, 255, 255))
    d.text((16, H - 22), "Exhibit photo  " + col.strftime("%d-%m-%Y %H:%M"), font=F(14), fill=(255, 220, 90))
    d.text((W - 190, 12), "SAMPLE - FOR TESTING", font=F(14), fill=(255, 255, 255))
    return save(im)
def wav():
    b = io.BytesIO()
    with wave.open(b, "wb") as w:
        w.setnchannels(1); w.setsampwidth(2); w.setframerate(8000)
        w.writeframes(b"".join(struct.pack("<h", int(8000 * math.sin(2 * math.pi * 330 * i / 8000))) for i in range(16000)))
    return b.getvalue()
def make(kind, et, title, desc, case_no, i, col):
    if kind == "img": return (cctv if et == "CCTV Footage" else photo)(title, i, col), "png"
    if kind == "wav": return wav(), "wav"
    if kind == "csv": return f"time,source,note\n2026-01-01 10:00,{case_no},{desc}\n2026-01-01 10:05,{case_no},{title}\n2026-01-01 10:09,{case_no},entry {i}\n".encode(), "csv"
    if kind == "eml": return f"From: unknown@example.com\nTo: officer@example.com\nSubject: {title}\n\n{desc} Case {case_no}. This is sample data for testing.\n".encode(), "eml"
    return f"{title}\nCase: {case_no}\n\n{desc}\nThis is sample text for testing. Findings were recorded by the investigating team and reviewed. Findings need follow up.\n".encode(), "txt"

with Session() as s:
    for u, n, r in USERS:
        if not s.query(User).filter_by(username=u).first(): s.add(User(username=u, name=n, role=r, pw=hash_pw(PW)))
    s.commit()
    team = ["admin", "inspector.rao", "analyst.sen"]; total = 0
    if "--reset" in sys.argv:  # remove old sample cases first
        for no, *_ in CASES:
            c = s.query(Case).filter_by(number=no).first()
            if c: s.query(Log).filter_by(case_id=c.id).delete(); s.query(Evidence).filter_by(case_id=c.id).delete(); s.delete(c)
        s.commit()
    for no, title, crime, days_ago, about, items in CASES:
        if s.query(Case).filter_by(number=no).first(): print("skip", no); continue
        start = now() - timedelta(days=days_ago)
        c = Case(number=no, title=title, crime_type=crime, description=about, created_by="inspector.rao", created_at=start); s.add(c); s.flush()
        s.add(Log(ts=start, user="inspector.rao", action="CASE_CREATED", case_id=c.id, detail=no))
        for i, (t, desc, et, dept, pr, hrs, loc, tags, kind) in enumerate(items):
            col = start + timedelta(hours=hrs); raw, ext = make(kind, et, t, desc, no, i + days_ago, col)
            fn = re.sub(r"[^a-z0-9]+", "_", t.lower()).strip("_") + "." + ext
            mime = mimetypes.guess_type(fn)[0] or "application/octet-stream"
            who = team[i % 3]; col = start + timedelta(hours=hrs); up = col + timedelta(hours=2)
            n = s.query(Evidence).count() + 1
            while s.query(Evidence).filter_by(eid=f"EV-{now().year}-{n:05d}").first(): n += 1
            eid = f"EV-{now().year}-{n:05d}"
            sha = hashlib.sha256(raw).hexdigest()
            e = Evidence(eid=eid, case_id=c.id, title=t, description=desc, etype=et, dept=dept, priority=pr, collected_at=col, uploaded_at=up,
                         collected_by=who, location=loc, tags=tags, filename=fn, mime=mime, size=len(raw), sha256=sha, holder=who,
                         meta=json.dumps(extract_meta(raw, fn, mime)), data=fernet.encrypt(raw))
            s.add(e); s.add(Log(ts=up, user=who, action="UPLOADED", evidence_id=eid, case_id=c.id, detail=f"SHA-256 {sha}"))
            if i % 3 == 0: s.add(Log(ts=up + timedelta(hours=3), user="analyst.sen", action="VIEWED", evidence_id=eid, case_id=c.id))
            if i % 4 == 1:
                s.add(Log(ts=up + timedelta(hours=5), user=who, action="TRANSFERRED", evidence_id=eid, case_id=c.id, detail=f"{who} -> analyst.sen. Reason: lab analysis"))
                s.add(Log(ts=up + timedelta(hours=6), user="analyst.sen", action="INTEGRITY_OK", evidence_id=eid, case_id=c.id, detail=f"Recomputed SHA-256 {sha}")); e.holder = "analyst.sen"
            s.flush(); total += 1
        s.commit()
    print(f"Added {total} evidence items. Test users (password {PW}):", ", ".join(u[0] for u in USERS))
