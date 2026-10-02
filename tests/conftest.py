import os, sys, tempfile
os.environ.setdefault('ONC_BCRYPT_ROUNDS', '4')
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pytest
from fastapi.testclient import TestClient
from opennetcontrol.config import Settings
from opennetcontrol.core import Core
from opennetcontrol.app import create_app

PW = {"admin": "Adm1n-Test#2026!", "admin2": "Adm1n2-Test#2026!", "operator": "Oper4tor-Test#2026", "viewer": "View3r-Test#2026"}


@pytest.fixture(autouse=True)
def _reset_clocks():
    """The simulator clock and the DB time source are process-global; never let one test leak into the next."""
    from opennetcontrol import db as _db
    from opennetcontrol.sim.clock import CLOCK
    _db.set_clock(None); CLOCK.reset()
    yield
    _db.set_clock(None); CLOCK.reset()


def mk_settings(**kw):
    d = dict(data_dir=tempfile.mkdtemp(), allow_sim=True, demo=True, admin_password=PW["admin"], poll_interval=3600,
             login_max_fails=5, rate_per_min=100000, demo_history_h=0)
    d.update(kw)
    return Settings(**d)


@pytest.fixture()
def core():
    c = Core(mk_settings())
    c.seed_demo()
    return c


@pytest.fixture()
def client():
    os.environ["ONC_DEMO_OPERATOR_PASSWORD"] = PW["operator"]
    os.environ["ONC_DEMO_VIEWER_PASSWORD"] = PW["viewer"]
    app = create_app(mk_settings())
    with TestClient(app) as c:
        c.core = app.state.core
        c.core.auth.create_user("admin2", PW["admin2"], "admin")
        yield c


def login(client, user):
    r = client.post("/api/auth/login", json={"username": user, "password": PW[user]})
    assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["token"]}


@pytest.fixture()
def H(client):
    return {u: login(client, u) for u in ("admin", "admin2", "operator", "viewer")}
