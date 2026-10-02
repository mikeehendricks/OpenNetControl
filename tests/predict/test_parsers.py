"""Telemetry parsers: every platform round-trips through its simulator, and hostile device output is survivable."""
import random
import string

import pytest

from opennetcontrol import lab
from opennetcontrol.drivers import DRIVERS, get_driver
from opennetcontrol.drivers import telemetry as T
from opennetcontrol.models import DriverError
from opennetcontrol.sim.clock import CLOCK
from opennetcontrol.transport import SimSession

PLATFORMS = sorted(DRIVERS)


@pytest.fixture(scope="module")
def fleet():
    lab.build_lab()
    CLOCK.advance(1800)
    return {s.platform: s for s in lab.LAB.values()}.copy(), lab.LAB


def test_all_nine_platforms_have_a_counters_parser():
    assert len(PLATFORMS) == 9
    for p in PLATFORMS:
        assert (p, "counters") in T.PARSERS and "counters" in T.COMMANDS[p]


@pytest.mark.parametrize("platform", PLATFORMS)
def test_roundtrip_against_simulator(fleet, platform):
    by_platform, allsims = fleet
    sim = next(s for s in allsims.values() if s.platform == platform)
    with SimSession(sim) as ses:
        got = get_driver(platform).collect_telemetry(ses)
    assert got, f"no interfaces parsed for {platform}"
    names = {i["name"] for i in sim.ifaces}
    assert {c.name for c in got} == names
    for c in got:
        assert c.in_octets > 0 and c.out_octets >= 0
        assert c.in_errors >= 0 and c.resets >= 0


@pytest.mark.parametrize("platform", ["cisco_iosxe", "cisco_nxos", "ruckus_icx", "aruba_aoscx"])
def test_optics_decorate_transceiver_ports(fleet, platform):
    sim = next(s for s in fleet[1].values() if s.platform == platform)
    with SimSession(sim) as ses:
        got = get_driver(platform).collect_telemetry(ses)
    assert any(c.rx_dbm is not None and -10 < c.rx_dbm < 0 for c in got)
    assert all(c.rx_dbm is None for c in got if not sim.traffic.ifs[c.name].p.has_optic)


def test_module_thresholds_parsed_where_reported(fleet):
    for platform, expect in (("cisco_iosxe", True), ("cisco_nxos", True), ("aruba_aoscx", True), ("ruckus_icx", False)):
        sim = next(s for s in fleet[1].values() if s.platform == platform)
        with SimSession(sim) as ses:
            got = [c for c in get_driver(platform).collect_telemetry(ses) if c.rx_dbm is not None]
        assert all((c.rx_low_alarm == -14.0 and c.rx_low_warn == -12.0) == expect for c in got), platform


def test_degradation_is_visible_through_the_real_parser(fleet):
    sim = fleet[1]["hq-core1"]
    lab.degrade("hq-core1", "TenGigabitEthernet1/1/3", "errors", per_min=50, growth_per_h=0)
    drv = get_driver("cisco_iosxe")
    with SimSession(sim) as ses:
        a = {c.name: c for c in drv.collect_telemetry(ses)}["TenGigabitEthernet1/1/3"]
        CLOCK.advance(600)
        b = {c.name: c for c in drv.collect_telemetry(ses)}["TenGigabitEthernet1/1/3"]
    assert b.in_errors - a.in_errors > 200
    lab.heal("hq-core1", "TenGigabitEthernet1/1/3")


@pytest.mark.parametrize("platform", PLATFORMS)
def test_hostile_and_garbage_output_never_raises(platform):
    r = random.Random(platform)
    junk = ["", "\x00" * 50, "A" * 100000, "% Invalid input", "\n" * 1000, "if=" * 500, "interface: \n" * 600,
            "Port  In Octets\n" + "x " * 5000, "Flags\n NAME RX-BYTE\n" + "9" * 200 + "\n",
            "".join(r.choice(string.printable) for _ in range(5000)), bytes(r.randrange(256) for _ in range(4000)).decode("latin1")]
    for kind in ("counters", "optics"):
        fn = T.PARSERS.get((platform, kind))
        if not fn:
            continue
        for j in junk:
            out = fn(j)
            assert isinstance(out, list) and len(out) <= T.MAX_IFACES
            for c in out:
                assert T._ok(c.name) and 0 <= c.in_octets <= T.MAX_COUNTER


def test_huge_and_negative_numbers_are_clamped():
    txt = "Gi1 is up, line protocol is up\n  MTU 1500 bytes, BW 99999999999999999999999 Kbit/sec\n  5 packets input, " + "9" * 40 + " bytes, 0 no buffer\n"
    c = T.iosxe_counters(txt)
    assert c and c[0].in_octets == T.MAX_COUNTER
    assert T._n("-5") == 0 and T._f("nan") is None and T._f("1e999") is None and T._f("-999") == -60.0


def test_interface_flood_is_capped_and_names_validated():
    txt = "\n".join(f"if=port{i} family=00 type=1\nstat: rxb=1 txb=1 rxe=0 txe=0 rxd=0 txd=0" for i in range(3000))
    assert len(T.forti_counters(txt)) == T.MAX_IFACES
    evil = "if=<script>alert(1)</script> x\nstat: rxb=1\nif=../../etc/passwd x\nstat: rxb=1\nif=ok1 x\nstat: rxb=2"
    assert [c.name for c in T.forti_counters(evil)] == ["ok1"]


def test_error_reply_from_device_is_rejected_not_parsed():
    class S:
        def run(self, c):
            return "% Invalid input detected at '^' marker."
    with pytest.raises(DriverError):
        get_driver("cisco_iosxe").collect_telemetry(S())


def test_optics_failure_is_tolerated():
    class S:
        def run(self, c):
            if "transceiver" in c:
                raise DriverError("unsupported")
            lab.build_lab()
            return SimSession(lab.LAB["hq-core1"]).run(c)
    assert get_driver("cisco_iosxe").collect_telemetry(S())


def test_parsers_do_bounded_work_on_multi_megabyte_hostile_input():
    """Audit V-PRED-01b: parsers must stay fast (and linear) whatever a compromised device streams."""
    import time
    N = 2_000_000
    cases = ["if=p1 x\n" * (N // 8), "if=" + "a" * N, "stat: rxb=" + "9" * N, "\n" * N, "Port  In Octets" + " " * N + "\n" + "1 " * (N // 2),
             ("Gi1 is up, line protocol is up\n" + " " * 50 + "\n") * (N // 80), " NAME RX-BYTE\n" + ("0 R ether1 " + "1 " * 30 + "\n") * (N // 80)]
    for (plat, kind), fn in T.PARSERS.items():
        for txt in cases:
            t = time.time(); fn(txt)
            assert time.time() - t < 2.0, (plat, kind)
