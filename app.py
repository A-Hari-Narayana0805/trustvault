import os, sqlite3, secrets, hashlib, hmac, json, mimetypes
from pathlib import Path
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, session, redirect, url_for, flash, abort, send_file, render_template_string, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE=Path(__file__).resolve().parent
DB=Path(os.getenv("DATABASE_PATH", BASE/"trustvault.db"))
FILES=Path(os.getenv("FILE_STORAGE_PATH", BASE/"storage")); FILES.mkdir(parents=True,exist_ok=True)
MAX=int(os.getenv("MAX_UPLOAD_BYTES",15*1024*1024)); ALLOWED={"pdf","txt","png","jpg","jpeg","docx","xlsx","csv"}
app=Flask(__name__); app.secret_key=os.getenv("FLASK_SECRET_KEY","dev-secret-change-before-deploy")
KEY=os.getenv("AUDIT_HMAC_KEY","dev-audit-change-before-deploy").encode()

def now(): return datetime.now(timezone.utc).isoformat()
def db():
    if "db" not in g:
        g.db=sqlite3.connect(DB); g.db.row_factory=sqlite3.Row; g.db.execute("PRAGMA foreign_keys=ON")
    return g.db
@app.teardown_appcontext
def close(e):
    c=g.pop("db",None)
    if c: c.close()
def init():
    with sqlite3.connect(DB) as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE,password TEXT,role TEXT,active INTEGER DEFAULT 1);
        CREATE TABLE IF NOT EXISTS docs(id INTEGER PRIMARY KEY,owner INTEGER REFERENCES users(id),title TEXT,category TEXT,filename TEXT,stored TEXT UNIQUE,mime TEXT,size INTEGER,created TEXT,deleted INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS grants(id INTEGER PRIMARY KEY,doc INTEGER REFERENCES docs(id),uid INTEGER REFERENCES users(id),perm TEXT,UNIQUE(doc,uid));
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,actor INTEGER,action TEXT,doc INTEGER,target INTEGER,details TEXT,created TEXT,prev TEXT,hash TEXT);
        """)
        for u,p,role in [("admin","Admin-Demo-2026!","admin"),("owner","Owner-Demo-2026!","owner"),("viewer","Viewer-Demo-2026!","viewer")]:
            c.execute("INSERT OR IGNORE INTO users(username,password,role) VALUES(?,?,?)",(u,generate_password_hash(p),role))
def audit(actor,action,doc=None,target=None,details=None):
    c=db(); last=c.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone(); prev=last["hash"] if last else "GENESIS"
    ev={"actor":actor,"action":action,"doc":doc,"target":target,"details":details or {},"created":now(),"prev":prev}
    raw=json.dumps(ev,sort_keys=True,separators=(",",":")); sig=hmac.new(KEY,raw.encode(),hashlib.sha256).hexdigest()
    c.execute("INSERT INTO audit(actor,action,doc,target,details,created,prev,hash) VALUES(?,?,?,?,?,?,?,?)",(actor,action,doc,target,json.dumps(details or {}),ev["created"],prev,sig)); c.commit()
def user():
    if session.get("uid"): return db().execute("SELECT * FROM users WHERE id=? AND active=1",(session["uid"],)).fetchone()
def login_required(fn):
    @wraps(fn)
    def w(*a,**k):
        if not user(): return redirect("/login")
        return fn(*a,**k)
    return w
def roles(*rs):
    def deco(fn):
        @wraps(fn)
        @login_required
        def w(*a,**k):
            if user()["role"] not in rs: abort(403)
            return fn(*a,**k)
        return w
    return deco
def csrf():
    t=session.get("csrf"); s=request.form.get("_csrf") or request.headers.get("X-CSRF-Token")
    if not t or not s or not hmac.compare_digest(t,s): abort(400,"Invalid CSRF token")
def access(docid,perm="read"):
    u=user(); d=db().execute("SELECT * FROM docs WHERE id=? AND deleted=0",(docid,)).fetchone()
    if not d:
        audit(u["id"],"access_denied",docid,details={"operation":perm,"reason":"not_found_or_deleted"})
        abort(404)
    if d["owner"]==u["id"]: return d
    gnt=db().execute("SELECT perm FROM grants WHERE doc=? AND uid=?",(docid,u["id"])).fetchone()
    if not gnt or (perm=="edit" and gnt["perm"]!="edit"):
        audit(u["id"],"access_denied",docid,details={"operation":perm,"reason":"missing_grant_or_insufficient_permission"})
        abort(404)
    return d
CSS="""<style>
body{margin:0;background:#0b1020;color:#edf2ff;font:15px system-ui}header{padding:20px 6%;border-bottom:1px solid #293653;display:flex;justify-content:space-between}a{color:#91adff;text-decoration:none}main{max-width:1050px;margin:36px auto;padding:0 20px}.panel{background:#131e33;border:1px solid #2a3958;border-radius:16px;padding:22px;margin:16px 0}.hero{display:flex;justify-content:space-between;align-items:center;gap:20px}.muted{color:#9eabc4}.btn,button{background:#91adff;color:#081126;border:0;padding:11px 15px;border-radius:9px;font-weight:bold;cursor:pointer}input,select{display:block;width:100%;max-width:480px;padding:11px;margin:7px 0 15px;background:#0b1426;color:white;border:1px solid #33415d;border-radius:8px}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:12px;border-bottom:1px solid #2a3958}.pill{background:#283a5b;padding:4px 9px;border-radius:15px}.flash{padding:12px;background:#174238;border-radius:8px}.grid{display:flex;gap:14px;flex-wrap:wrap}.grid .panel{flex:1;min-width:160px}.stat{font-size:26px;font-weight:bold}
</style>"""
def page(title, body):
    u = user()

    if u:
        csrf_value = session.get("csrf", "")
        logout_form = (
            f'<form method="post" action="/logout" style="display:inline">'
            f'<input type="hidden" name="_csrf" value="{csrf_value}">'
            f'<button type="submit">Sign out</button>'
            f'</form>'
        )

        nav = (
            f'{u["username"]} · {u["role"]}　'
            f'<a href="/">Workspace</a>　'
            + ('<a href="/admin">Admin</a>　' if u["role"] == "admin" else '')
            + logout_form
        )
    else:
        nav = '<a href="/login">Sign in</a>'

    return render_template_string(
        """<!doctype html><html><head>
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <title>{{title}} · TrustVault</title>""" + CSS +
        """</head><body><header>
        <b>Trust<span style="color:#91adff">Vault</span></b>
        <nav>""" + nav + """</nav></header>
        <main>{% for m in get_flashed_messages() %}
        <p class="flash">{{m}}</p>{% endfor %}""" + body +
        """</main></body></html>""",
        title=title,
        csrf=session.get("csrf")
    )
@app.before_request
def token():
    if "csrf" not in session: session["csrf"]=secrets.token_urlsafe(32)
@app.get("/login")
def login_get(): return page("Sign in",'<div class="panel"><h1>Secure sign in</h1><form method="post"><input type="hidden" name="_csrf" value="{{csrf}}"><label>Username</label><input name="username" required><label>Password</label><input name="password" type="password" required><button>Sign in</button></form><p class="muted">Demo accounts are in README.md.</p></div>')
@app.post("/login")
def login_post():
    csrf(); u=db().execute("SELECT * FROM users WHERE username=?",(request.form.get("username",""),)).fetchone()
    if u and u["active"] and check_password_hash(u["password"],request.form.get("password","")):
        session.clear();session["uid"]=u["id"];session["csrf"]=secrets.token_urlsafe(32);audit(u["id"],"login");return redirect("/")
    flash("Invalid credentials.");return redirect("/login")
@app.post("/logout")
@login_required
def logout():
    csrf()
    audit(user()["id"], "logout")
    session.clear()
    return redirect("/login")
@app.get("/")
@login_required
def home():
    u=user(); q=request.args.get("q",""); category=request.args.get("category",""); date=request.args.get("date","")
    rows=db().execute("""SELECT DISTINCT d.*,x.username ownername FROM docs d JOIN users x ON x.id=d.owner LEFT JOIN grants g ON g.doc=d.id WHERE d.deleted=0 AND (d.owner=? OR g.uid=?) ORDER BY d.id DESC""",(u["id"],u["id"])).fetchall()
    rows=[d for d in rows if q.lower() in (d["title"]+" "+d["ownername"]).lower() and category.lower() in d["category"].lower() and (not date or d["created"].startswith(date))]
    trs="".join(f'<tr><td><a href="/docs/{d["id"]}">{d["title"]}</a><br><small>{d["filename"]}</small></td><td>{d["ownername"]}</td><td>{d["category"]}</td><td><a href="/docs/{d["id"]}">Open</a></td></tr>' for d in rows)
    own=db().execute("SELECT count(*) n FROM docs WHERE owner=? AND deleted=0",(u["id"],)).fetchone()["n"]
    upload='<a class="btn" href="/upload">＋ Upload document</a>' if u["role"]=="owner" else ""
    return page("Workspace",f'<div class="hero"><div><p class="muted">SECURE DOCUMENT WORKSPACE</p><h1>Your documents, under control.</h1><p class="muted">Private by default · Permission checked on every request</p></div>{upload}</div><div class="grid"><div class="panel">Documents owned<div class="stat">{own}</div></div><div class="panel">Your role<div class="stat">{u["role"].title()}</div></div><div class="panel">Security model<div class="stat">Zero trust</div></div></div><div class="panel"><form><input name="q" placeholder="Search title or owner" value="{q}"><input name="category" placeholder="Category" value="{category}"><input type="date" name="date" value="{date}"><button>Search</button></form><h2>Accessible documents</h2><table><tr><th>Document</th><th>Owner</th><th>Category</th><th></th></tr>{trs or "<tr><td colspan=4>No documents available.</td></tr>"}</table></div>')
@app.route("/upload",methods=["GET","POST"])
@roles("owner")
def upload():
    if request.method=="POST":
        csrf(); f=request.files.get("file"); title=request.form.get("title","").strip(); cat=request.form.get("category","General").strip()[:60]
        if not f or not f.filename or not title: abort(400)
        name=secure_filename(f.filename); ext=name.rsplit(".",1)[-1].lower() if "." in name else ""
        if ext not in ALLOWED: abort(400,"File type not allowed")
        data=f.read(MAX+1)
        if not data or len(data)>MAX: abort(400,"Empty or oversized file")
        sig={"pdf":data.startswith(b"%PDF"),"png":data.startswith(b"\\x89PNG\\r\\n\\x1a\\n"),"jpg":data.startswith(b"\\xff\\xd8"),"jpeg":data.startswith(b"\\xff\\xd8")}
        if ext in sig and not sig[ext]: abort(400,"File signature mismatch")
        stored=secrets.token_hex(24);(FILES/stored).write_bytes(data)
        cur=db().execute("INSERT INTO docs(owner,title,category,filename,stored,mime,size,created) VALUES(?,?,?,?,?,?,?,?)",(user()["id"],title[:180],cat,name,stored,mimetypes.guess_type(name)[0] or "application/octet-stream",len(data),now()));db().commit()
        audit(user()["id"],"upload",cur.lastrowid,details={"filename":name,"size":len(data)})
        flash("Document uploaded.");return redirect(f'/docs/{cur.lastrowid}')
    return page("Upload",'<div class="panel"><h1>Upload document</h1><form method="post" enctype="multipart/form-data"><input type="hidden" name="_csrf" value="{{csrf}}"><label>Title</label><input name="title" required><label>Category</label><input name="category" value="General"><label>File (PDF, TXT, PNG, JPG, DOCX, XLSX, CSV; 15 MB max)</label><input type="file" name="file" required><button>Upload securely</button></form></div>')
@app.route("/docs/<int:did>",methods=["GET","POST"])
@login_required
def detail(did):
    d=access(did); u=user()
    if request.method=="POST":
        csrf();access(did,"edit"); title=request.form.get("title","").strip();cat=request.form.get("category","").strip()
        if not title: abort(400)
        db().execute("UPDATE docs SET title=?,category=? WHERE id=?",(title[:180],cat[:60],did));db().commit();audit(u["id"],"metadata_changed",did);flash("Saved.");return redirect(f"/docs/{did}")
    owner=d["owner"]==u["id"]
    grants=db().execute("SELECT g.uid,g.perm,x.username FROM grants g JOIN users x ON x.id=g.uid WHERE g.doc=?",(did,)).fetchall()
    grant_html="".join(f'<tr><td>{x["username"]}</td><td>{x["perm"]}</td><td><form method="post" action="/docs/{did}/revoke"><input type="hidden" name="_csrf" value="{session["csrf"]}"><input type="hidden" name="uid" value="{x["uid"]}"><button>Revoke</button></form></td></tr>' for x in grants)
    manage=f'<div class="panel"><h2>Manage permissions</h2><form method="post" action="/docs/{did}/grant"><input type="hidden" name="_csrf" value="{session["csrf"]}"><input name="username" placeholder="Exact username" required><select name="perm"><option>read</option><option>edit</option></select><button>Grant</button></form><table><tr><th>User</th><th>Permission</th><th></th></tr>{grant_html}</table></div>' if owner else ""
    canedit=owner or db().execute("SELECT 1 FROM grants WHERE doc=? AND uid=? AND perm='edit'",(did,u["id"])).fetchone()
    edit=f'<div class="panel"><h2>Edit metadata</h2><form method="post"><input type="hidden" name="_csrf" value="{session["csrf"]}"><label>Title</label><input name="title" value="{d["title"]}"><label>Category</label><input name="category" value="{d["category"]}"><button>Save</button></form></div>' if canedit else ""
    delete=f'<form method="post" action="/docs/{did}/delete"><input type="hidden" name="_csrf" value="{session["csrf"]}"><button>Delete document</button></form>' if owner else ""
    return page("Document",f'<div class="hero"><div><p class="muted">DOCUMENT DETAIL</p><h1>{d["title"]}</h1><p class="muted">{d["filename"]} · {d["size"]} bytes · {d["category"]}</p></div><a class="btn" href="/docs/{did}/download">Download</a></div><div class="panel">Private file storage · Owner ID {d["owner"]} · Uploaded {d["created"]}{delete}</div>{edit}{manage}')
@app.post("/docs/<int:did>/grant")
@roles("owner")
def grant(did):
    csrf();d=access(did,"edit");u=user()
    if d["owner"]!=u["id"]:abort(403)
    target=db().execute("SELECT * FROM users WHERE username=? AND active=1",(request.form.get("username",""),)).fetchone();perm=request.form.get("perm")
    if not target or target["id"]==u["id"] or perm not in ("read","edit"):flash("Invalid user or permission")
    else:
        db().execute("INSERT INTO grants(doc,uid,perm) VALUES(?,?,?) ON CONFLICT(doc,uid) DO UPDATE SET perm=excluded.perm",(did,target["id"],perm));db().commit();audit(u["id"],"permission_granted",did,target["id"],{"permission":perm});flash("Access granted")
    return redirect(f"/docs/{did}")
@app.post("/docs/<int:did>/revoke")
@roles("owner")
def revoke(did):
    csrf();d=access(did,"edit");u=user()
    if d["owner"]!=u["id"]:abort(403)
    tid=request.form.get("uid","");db().execute("DELETE FROM grants WHERE doc=? AND uid=?",(did,tid));db().commit();audit(u["id"],"permission_revoked",did,int(tid) if tid.isdigit() else None);flash("Access revoked immediately for subsequent requests");return redirect(f"/docs/{did}")
@app.get("/docs/<int:did>/download")
@login_required
def download(did):
    d=access(did);p=FILES/d["stored"]
    if not p.is_file():abort(404)
    audit(user()["id"],"download",did,details={"filename":d["filename"]})
    return send_file(p,as_attachment=True,download_name=d["filename"],mimetype="application/octet-stream")
@app.post("/docs/<int:did>/delete")
@roles("owner")
def delete(did):
    csrf();d=access(did,"edit")
    if d["owner"]!=user()["id"]:abort(403)
    db().execute("UPDATE docs SET deleted=1 WHERE id=?",(did,));db().commit();audit(user()["id"],"document_deleted",did);flash("Document deleted (soft delete).");return redirect("/")
@app.get("/admin")
@roles("admin")
def admin():
    c=db();events=c.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 100").fetchall()
    trs="".join(f'<tr><td>{e["created"][:19]}</td><td>{e["actor"]}</td><td>{e["action"]}</td><td>{e["doc"] or "—"}</td><td>{e["hash"][:18]}…</td></tr>' for e in events)
    return page("Admin",f'<h1>Security overview</h1><div class="panel"><p>Active documents: {c.execute("SELECT count(*) n FROM docs WHERE deleted=0").fetchone()["n"]}</p><p>Active users: {c.execute("SELECT count(*) n FROM users WHERE active=1").fetchone()["n"]}</p><h2>Recent audit events</h2><table><tr><th>Time UTC</th><th>Actor</th><th>Event</th><th>Doc</th><th>HMAC</th></tr>{trs}</table><p class="muted">HMAC chain key must be stored separately from the database. DB+key compromise can forge records.</p></div>')
@app.errorhandler(403)
def forbidden(e):return page("Denied","<div class='panel'><h1>Access denied</h1><a href='/'>Back</a></div>"),403
@app.errorhandler(404)
def missing(e):return page("Not found","<div class='panel'><h1>Not found</h1><p>Resource missing or not accessible.</p><a href='/'>Back</a></div>"),404
with app.app_context():init()
if __name__=="__main__":app.run(host="0.0.0.0",port=int(os.getenv("PORT",5000)),debug=False)
