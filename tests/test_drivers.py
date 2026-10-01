"""Every platform: collect -> every supported op applies, verifies, and reverts cleanly."""
import json
import pytest
from opennetcontrol.drivers import DRIVERS
from opennetcontrol.lab import build_lab, LAB
from opennetcontrol.transport import SimSession
from opennetcontrol.models import UnsupportedOperation, ApplyError
from opennetcontrol.ops import validate_op
from opennetcontrol.policy import check_lines

SAMPLE = {
    "create_vlan": {"vlan_id": 321, "vlan_name": "onc-test"},
    "set_interface_description": {"interface": None, "description": "onc description"},
    "interface_admin": {"interface": None, "enabled": False},
    "block_ip": {"prefix": "198.18.5.7/32"},
    "add_static_route": {"prefix": "10.99.0.0/24", "nexthop": "10.0.0.254"},
    "set_ntp": {"server": "192.0.2.123"},
    "disable_telnet": {},
    "set_ssid_state": {"ssid": None, "enabled": False},
}


def first_sim(platform):
    build_lab()
    for s in LAB.values():
        if s.platform == platform:
            return s
    pytest.skip("no sim for " + platform)


def session(sim, drv):
    ses = SimSession(sim)
    for c in drv.paging:
        ses.run(c)
    return ses


@pytest.mark.parametrize("platform", sorted(DRIVERS))
def test_collect_facts(platform):
    sim = first_sim(platform); drv = DRIVERS[platform]
    with session(sim, drv) as ses:
        f = drv.collect(ses)
    assert f.hostname == sim.name
    assert f.model and f.version and f.serial
    assert f.uptime_s > 86400 * 10
    assert 0 < f.cpu_pct < 100 and 0 < f.mem_pct < 100
    assert f.interfaces
    assert f.telnet_enabled in (True, False)


@pytest.mark.parametrize("platform", sorted(DRIVERS))
def test_every_capability_roundtrip(platform):
    sim = first_sim(platform); drv = DRIVERS[platform]
    for op in sorted(drv.capabilities):
        with session(sim, drv) as ses:
            f0 = drv.collect(ses)
            p = dict(SAMPLE[op])
            if "interface" in p:
                ifs = [i for i in f0.interfaces if i.ip == "" or True]
                p["interface"] = [i.name for i in f0.interfaces if not re_mgmt(i)][-1]
            if "ssid" in p:
                p["ssid"] = next(iter(f0.ssids))
            p = validate_op(op, p)
            if op == "disable_telnet":
                sim.telnet = True
                if hasattr(sim, "allow"):
                    sim.allow["port1"] = ["ping", "https", "ssh", "telnet"]
                if hasattr(sim, "services"):
                    sim.services["telnet"] = True
                f0 = drv.collect(ses)
            apply, undo = drv.render(op, p, f0)
            check_lines(apply); check_lines(undo)
            drv.apply(ses, apply)
            f1 = drv.collect(ses); c1 = drv.get_config(ses)
            assert drv.verify(op, p, f1, c1), f"{platform}:{op} not verified after apply"
            drv.apply(ses, undo, ignore_errors=True)
            f2 = drv.collect(ses); c2 = drv.get_config(ses)
            assert drv.verify(op, p, f2, c2, undo=True), f"{platform}:{op} not reverted by undo"


def re_mgmt(i):
    return False


@pytest.mark.parametrize("platform", sorted(DRIVERS))
def test_unsupported_ops_raise(platform):
    drv = DRIVERS[platform]
    for op in set(SAMPLE) - drv.capabilities:
        with pytest.raises(UnsupportedOperation):
            drv.render(op, SAMPLE[op])


def test_cisco_syntax_reject_detected():
    sim = first_sim("cisco_iosxe"); drv = DRIVERS["cisco_iosxe"]
    with session(sim, drv) as ses:
        with pytest.raises(ApplyError):
            drv.apply(ses, ["bogus command"])
        assert sim.ctx == []   # driver always leaves config mode


def test_panos_requires_commit():
    sim = first_sim("paloalto_panos"); drv = DRIVERS["paloalto_panos"]
    with session(sim, drv) as ses:
        ses.run("configure"); ses.run("set address X ip-netmask 1.1.1.1/32"); ses.run("exit")
        assert "1.1.1.1" not in drv.get_config(ses)       # candidate only
        drv.apply(ses, ["set address Y ip-netmask 2.2.2.2/32"])
        assert "2.2.2.2" in drv.get_config(ses)           # driver commits


def test_fortios_telnet_uses_facts():
    sim = first_sim("fortinet_fortios"); drv = DRIVERS["fortinet_fortios"]
    with session(sim, drv) as ses:
        f = drv.collect(ses)
    assert f.telnet_enabled and f.extra["telnet_ifaces"]
    apply, undo = drv.render("disable_telnet", {}, f)
    assert any("allowaccess ping https ssh" in l for l in apply)
