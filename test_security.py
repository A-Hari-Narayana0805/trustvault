import io, importlib, pytest, sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
@pytest.fixture
def client(tmp_path,monkeypatch):
    monkeypatch.setenv("DATABASE_PATH",str(tmp_path/"db.sqlite"))
    monkeypatch.setenv("FILE_STORAGE_PATH",str(tmp_path/"files"))
    monkeypatch.setenv("FLASK_SECRET_KEY","test-secret")
    monkeypatch.setenv("AUDIT_HMAC_KEY","test-audit")
    import app as m; importlib.reload(m);m.app.config["TESTING"]=True
    with m.app.test_client() as c: yield c,m

def token(c):
    c.get("/login")
    with c.session_transaction() as s:
        return s["csrf"]

def login(c,u,p):return c.post("/login",data={"_csrf":token(c),"username":u,"password":p},follow_redirects=True)
def upload(c):
    return c.post("/upload",data={"_csrf":token(c),"title":"Private","category":"Test","file":(io.BytesIO(b"%PDF test"),"private.pdf")},content_type="multipart/form-data")
def test_ungranted_user_cannot_read_or_download(client):
    c,m=client;login(c,"owner","Owner-Demo-2026!");upload(c);did=m.db().execute("select id from docs").fetchone()["id"]
    c.get("/logout");login(c,"viewer","Viewer-Demo-2026!")
    assert c.get(f"/docs/{did}").status_code==404
    assert c.get(f"/docs/{did}/download").status_code==404
def test_revocation_immediate(client):
    c,m=client;login(c,"owner","Owner-Demo-2026!");upload(c);did=m.db().execute("select id from docs").fetchone()["id"]
    c.post(f"/docs/{did}/grant",data={"_csrf":token(c),"username":"viewer","perm":"read"})
    c.get("/logout");login(c,"viewer","Viewer-Demo-2026!")
    assert c.get(f"/docs/{did}/download").status_code==200
    c.get("/logout");login(c,"owner","Owner-Demo-2026!")
    uid=m.db().execute("select id from users where username='viewer'").fetchone()["id"]
    c.post(f"/docs/{did}/revoke",data={"_csrf":token(c),"uid":str(uid)})
    c.get("/logout");login(c,"viewer","Viewer-Demo-2026!")
    assert c.get(f"/docs/{did}/download").status_code==404
def test_viewer_cannot_upload(client):
    c,m=client;login(c,"viewer","Viewer-Demo-2026!")
    assert c.get("/upload").status_code==403
