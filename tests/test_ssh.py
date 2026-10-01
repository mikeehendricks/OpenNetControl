"""Real SSH transport against paramiko-served simulators (auth, prompts, pagination, host-key pinning)."""
import os, sys, socket, time
import paramiko, pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lab"))
import ssh_lab
from opennetcontrol.lab import build_lab, LAB
from opennetcontrol.drivers import DRIVERS
from opennetcontrol.transport import SSHSession, HostKeyMismatch
from opennetcontrol.models import DriverError
from opennetcontrol.core import Core
from conftest import mk_settings


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


@pytest.fixture()
def servers():
    build_lab()
    socks, ports = [], {}
    for name, sim in LAB.items():
        p = free_port(); socks.append(ssh_lab.start(sim, p)); ports[name] = p
    time.sleep(0.3)
    yield ports
    for s in socks: s.close()


@pytest.mark.parametrize("name", ["hq-fw1", "hq-fw2", "hq-core1", "hq-dc1", "hq-dist1", "hq-dist2", "davao-rtr1", "hq-ap1", "hq-ap2"])
def test_collect_over_real_ssh_every_platform(servers, name):
    sim = LAB[name]; drv = DRIVERS[sim.platform]
    with SSHSession("127.0.0.1", servers[name], "admin", "lab-password", drv.prompt_re, allow_loopback=True) as ses:
        for c in drv.paging: ses.run(c)
        f = drv.collect(ses)
        assert f.hostname == name and f.version and f.interfaces


def test_bad_password_and_closed_port(servers):
    drv = DRIVERS["cisco_iosxe"]
    with pytest.raises(DriverError):
        SSHSession("127.0.0.1", servers["hq-core1"], "admin", "WRONG", drv.prompt_re, allow_loopback=True)
    with pytest.raises(DriverError):
        SSHSession("127.0.0.1", free_port(), "admin", "x", drv.prompt_re, allow_loopback=True, timeout=2)


def test_loopback_blocked_unless_allowed(servers):
    with pytest.raises(Exception):
        SSHSession("127.0.0.1", servers["hq-core1"], "admin", "lab-password", DRIVERS["cisco_iosxe"].prompt_re)


def test_multiline_command_refused(servers):
    drv = DRIVERS["cisco_iosxe"]
    with SSHSession("127.0.0.1", servers["hq-core1"], "admin", "lab-password", drv.prompt_re, allow_loopback=True) as ses:
        with pytest.raises(DriverError):
            ses.run("show version\nreload")
    assert not LAB["hq-core1"].reloaded


def test_host_key_pinning_detects_mitm(servers):
    drv = DRIVERS["cisco_iosxe"]
    with SSHSession("127.0.0.1", servers["hq-core1"], "admin", "lab-password", drv.prompt_re, allow_loopback=True) as ses:
        fp = ses.host_key
    assert fp.startswith("SHA256:")
    with SSHSession("127.0.0.1", servers["hq-core1"], "admin", "lab-password", drv.prompt_re, pinned_key=fp, allow_loopback=True):
        pass
    evil = ssh_lab.start(LAB["hq-core1"], free_port(), hostkey=paramiko.RSAKey.generate(2048))      # attacker with another key
    port = evil.getsockname()[1]; time.sleep(0.2)
    with pytest.raises(HostKeyMismatch):
        SSHSession("127.0.0.1", port, "admin", "lab-password", drv.prompt_re, pinned_key=fp, allow_loopback=True)
    evil.close()


def test_full_change_over_ssh_and_hostkey_alert(servers):
    c = Core(mk_settings(allow_loopback_targets=True, allow_sim=False))
    cid = c.add_credential("lab", "admin", "lab-password")
    for n in ("hq-core1", "hq-fw1"):
        c.add_device("t", n, "127.0.0.1", LAB[n].platform, port=servers[n], credential_id=cid, mgmt_ip=LAB[n].ip)
    c.poll_all()
    assert c.overview()["reachable"] == 2
    ids = [d["id"] for d in c.devices()]
    chg = c.propose_change("operator", "block_ip", {"prefix": "203.0.113.50/32"}, ids)
    c.decide(chg, "admin", True)
    res = c.execute(chg, "admin")
    assert res["status"] == "completed", res["results"]
    assert "203.0.113.50" in "".join(LAB["hq-core1"].running_config()) and any("203.0.113.50" in l for l in LAB["hq-fw1"].running)
    # swap the host key behind hq-core1's address -> must raise a critical alert and refuse to talk
    d = c.db.one("SELECT id FROM devices WHERE name='hq-core1'")
    c.db.x("UPDATE devices SET host_key='SHA256:AAAAAAAA' WHERE id=?", (d["id"],))
    c.poll_all()
    assert any(a["kind"] == "hostkey_changed" for a in c.alerts())
