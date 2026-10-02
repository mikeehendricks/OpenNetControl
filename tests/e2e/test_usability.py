"""Browser-driven usability / UX / front-end security tests (Playwright + headless Chromium)."""
import os, subprocess, sys, tempfile, time, socket, urllib.request
import pytest
from playwright.sync_api import sync_playwright, expect

PORT = 8099
BASE = f"http://127.0.0.1:{PORT}"
PW = {"admin": "Adm1n-E2E#2026!", "operator": "Oper4tor-E2E#2026", "viewer": "View3r-E2E#2026"}
if os.path.isdir("/tmp/libs"):   # sandbox-only: locally extracted chromium libs
    os.environ["LD_LIBRARY_PATH"] = "/tmp/libs/usr/lib/x86_64-linux-gnu:/tmp/libs/lib/x86_64-linux-gnu:" + os.environ.get("LD_LIBRARY_PATH", "")


@pytest.fixture(scope="module")
def server():
    env = dict(os.environ, ONC_DATA_DIR=tempfile.mkdtemp(), ONC_DEMO="1", ONC_ALLOW_SIM="1", ONC_ADMIN_PASSWORD=PW["admin"], ONC_BCRYPT_ROUNDS="4",
               ONC_DEMO_OPERATOR_PASSWORD=PW["operator"], ONC_DEMO_VIEWER_PASSWORD=PW["viewer"], ONC_PORT=str(PORT), ONC_RATE_PER_MIN="100000", ONC_LOGIN_RATE_PER_MIN="100000", ONC_POLL_INTERVAL="3600")
    p = subprocess.Popen([sys.executable, "-m", "opennetcontrol"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=os.path.join(os.path.dirname(__file__), "..", ".."))
    for _ in range(60):
        try:
            urllib.request.urlopen(BASE + "/api/health", timeout=1); break
        except Exception:
            time.sleep(0.5)
    yield
    p.terminate()


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as pw:
        b = pw.chromium.launch(); yield b; b.close()


class Page:
    def __init__(self, browser, user=None, size=(1440, 900)):
        self.ctx = browser.new_context(viewport={"width": size[0], "height": size[1]})
        self.pg = self.ctx.new_page()
        self.errors = []
        self.pg.on("console", lambda m: self.errors.append(m.text) if m.type == "error" else None)
        self.pg.on("pageerror", lambda e: self.errors.append(str(e)))
        self.pg.goto(BASE)
        if user:
            self.login(user)

    def login(self, user, pw=None):
        self.pg.fill("#u", user); self.pg.fill("#p", pw or PW[user]); self.pg.keyboard.press("Enter")
        self.pg.wait_for_selector(".shell", timeout=8000)

    def nav(self, page):
        self.pg.click(f"button[data-page={page}]"); time.sleep(0.4)


def test_login_flow_and_errors(server, browser):
    p = Page(browser)
    expect(p.pg.locator("#u")).to_be_focused()                     # autofocus
    p.pg.fill("#u", "admin"); p.pg.fill("#p", "wrong-password"); p.pg.keyboard.press("Enter")
    expect(p.pg.locator(".err")).to_contain_text("invalid credentials")
    assert "wrong-password" not in p.pg.content()
    p.errors.clear()                                   # the browser logs the intentional 401
    p.login("admin")
    assert p.pg.locator("h1#title").inner_text() == "Overview"
    assert p.errors == []


def test_all_pages_load_fast_without_errors(server, browser):
    p = Page(browser, "admin")
    for page in ["overview", "inventory", "topology", "incidents", "ai", "compliance", "changes", "platforms", "audit"]:
        t = time.time(); p.nav(page)
        p.pg.wait_for_selector("#content *", timeout=5000)
        assert time.time() - t < 3.0, page
        assert "Error:" not in p.pg.locator("#content").inner_text(), page
    assert p.errors == [], p.errors


def test_inventory_search_filter_and_drawer_escape(server, browser):
    p = Page(browser, "admin"); p.nav("inventory")
    assert p.pg.locator("tbody tr").count() == 15
    p.pg.fill("input[aria-label='Search inventory']", "fortigate"); time.sleep(0.2)
    assert p.pg.locator("tbody tr").count() == 2
    p.pg.fill("input[aria-label='Search inventory']", "zzzz"); time.sleep(0.2)
    assert p.pg.locator("tbody tr").count() == 0
    p.pg.fill("input[aria-label='Search inventory']", "")
    p.pg.select_option("#fv", "mikrotik"); time.sleep(0.2)
    assert p.pg.locator("tbody tr").count() == 2
    p.pg.locator("tbody tr").first.click()
    p.pg.wait_for_selector(".drawer")
    p.pg.keyboard.press("Escape"); time.sleep(0.3)
    assert p.pg.locator(".drawer").count() == 0, "Escape should close the detail drawer"


def test_topology_nodes_and_keyboard(server, browser):
    p = Page(browser, "admin"); p.nav("topology")
    assert p.pg.locator("svg.topo g.node").count() == 15
    p.pg.locator("svg.topo g.node").first.focus(); p.pg.keyboard.press("Enter")
    p.pg.wait_for_selector(".drawer")


def test_ai_chat_ux(server, browser):
    p = Page(browser, "admin"); p.nav("ai")
    box = p.pg.locator("input[aria-label=Message]")
    box.press("Enter"); assert p.pg.locator(".msg.u").count() == 0     # empty submit ignored
    box.fill("How many devices do we have?"); box.press("Enter")
    p.pg.wait_for_selector(".msg.a:has-text('15')", timeout=5000)
    assert "Thinking" not in p.pg.locator(".msgs").inner_text()
    box.fill("reload all devices"); box.press("Enter")
    p.pg.wait_for_selector(".msg.a:has-text(\"can't do that\")", timeout=5000)
    p.pg.locator(".chips button", has_text="unreachable").click()
    p.pg.wait_for_selector(".msg.a:has-text('reachable')", timeout=5000)
    p.nav("inventory"); p.nav("ai")                                    # conversation survives navigation
    assert p.pg.locator(".msg.u").count() == 3


def test_xss_resistance(server, browser):
    p = Page(browser, "admin"); p.nav("ai")
    payloads = ["<img src=x onerror=window.__pwned=1>", "<script>window.__pwned=1</script>", "\"><svg onload=window.__pwned=1>", "javascript:window.__pwned=1", "**<b onmouseover=window.__pwned=1>x</b>**"]
    box = p.pg.locator("input[aria-label=Message]")
    for x in payloads:
        box.fill(x); box.press("Enter"); time.sleep(0.5)
    p.nav("inventory"); p.pg.fill("input[aria-label='Search inventory']", payloads[0]); time.sleep(0.3)
    assert p.pg.evaluate("window.__pwned") is None
    assert p.pg.locator("#content img, #content script, #content svg[onload], #content b[onmouseover]").count() == 0
    assert p.pg.evaluate("document.querySelectorAll('[onerror],[onload],[onmouseover]').length") == 0


def test_viewer_sees_read_only_ui(server, browser):
    p = Page(browser, "viewer")
    p.nav("inventory"); assert p.pg.get_by_text("Refresh all").count() == 0
    p.nav("changes"); assert p.pg.get_by_text("New change request").count() == 0
    p.nav("audit"); assert "administrators only" in p.pg.locator("#content").inner_text()
    p.nav("ai"); box = p.pg.locator("input[aria-label=Message]")
    box.fill("create vlan 99 named test on all aruba switches"); box.press("Enter")
    p.pg.wait_for_selector(".msg.a:has-text('read-only')", timeout=5000)


def test_end_to_end_change_workflow_with_four_eyes(server, browser):
    op = Page(browser, "operator"); op.nav("ai")
    box = op.pg.locator("input[aria-label=Message]")
    box.fill("create vlan 120 named guests on all aruba switches"); box.press("Enter")
    op.pg.wait_for_selector("button:has-text('Review change')", timeout=5000)
    op.pg.click("button:has-text('Review change')"); op.pg.wait_for_selector(".drawer")
    assert op.pg.get_by_text("Approve", exact=True).count() == 0          # operators cannot approve
    assert "vlan 120" in op.pg.locator(".drawer").inner_text()
    ad = Page(browser, "admin"); ad.nav("changes")
    ad.pg.locator("tbody tr").first.click(); ad.pg.wait_for_selector(".drawer")
    ad.pg.click(".drawer button:has-text('Approve')"); ad.pg.wait_for_selector(".drawer .chip:has-text('approved')", timeout=5000)
    ad.pg.click(".drawer button:has-text('Execute now')"); ad.pg.wait_for_selector(".drawer .chip:has-text('completed')", timeout=15000)
    assert ad.pg.locator(".drawer .st-applied").count() == 2
    ad.pg.click(".drawer button:has-text('Roll back')"); ad.pg.wait_for_selector(".drawer .chip:has-text('rolled back')", timeout=15000)
    assert ad.errors == [] and op.errors == []


def test_admin_cannot_approve_own_change_ui_message(server, browser):
    ad = Page(browser, "admin"); ad.nav("ai")
    box = ad.pg.locator("input[aria-label=Message]")
    box.fill("add ntp server 10.10.0.123 on hq-dist2"); box.press("Enter")
    ad.pg.wait_for_selector("button:has-text('Review change')", timeout=5000)
    ad.pg.click("button:has-text('Review change')"); ad.pg.wait_for_selector(".drawer")
    ad.pg.click(".drawer button:has-text('Approve')")
    ad.pg.wait_for_selector(".toast.bad:has-text('four-eyes')", timeout=5000)


def test_incident_flow_and_recovery(server, browser):
    ad = Page(browser, "admin"); ad.nav("overview")
    ad.pg.click("button:has-text('Power off hq-dist1')"); time.sleep(1.5)
    ad.nav("incidents")
    ad.pg.wait_for_selector("text=hq-dist1 unreachable", timeout=5000)
    assert "Probable root cause" in ad.pg.locator("#content").inner_text()
    assert ad.pg.locator("#b-inc").is_visible()
    ad.pg.click("button:has-text('Investigate with AI')"); ad.pg.wait_for_selector(".msg.a:has-text('unreachable')", timeout=8000)
    ad.nav("topology"); assert ad.pg.locator("line.edge.down").count() >= 1
    ad.nav("overview"); ad.pg.click("button:has-text('Power on hq-dist1')"); time.sleep(1.5)
    ad.nav("incidents"); assert "No open incidents" in ad.pg.locator("#content").inner_text()


def test_session_expiry_returns_to_login(server, browser):
    p = Page(browser, "viewer"); p.nav("inventory")
    p.pg.evaluate("sessionStorage.setItem('onc_token','garbage')")
    p.pg.reload(); p.pg.wait_for_selector("#u", timeout=5000)


def test_mobile_layout(server, browser):
    p = Page(browser, "admin", size=(390, 844)); time.sleep(0.5)
    overflow = p.pg.evaluate("document.documentElement.scrollWidth - window.innerWidth")
    assert overflow <= 4, f"page scrolls horizontally by {overflow}px on mobile"
    p.nav("inventory"); p.pg.wait_for_selector("tbody tr")
    assert p.pg.evaluate("document.documentElement.scrollWidth - window.innerWidth") <= 4
    p.nav("ai")
    assert p.pg.locator("input[aria-label=Message]").is_visible()


def test_accessibility_basics(server, browser):
    p = Page(browser, "admin")
    for page in ["overview", "inventory", "topology", "ai", "changes", "compliance", "platforms"]:
        p.nav(page)
        bad = p.pg.evaluate("""() => [...document.querySelectorAll('button,input,select,textarea')].filter(e => {
            const n = (e.getAttribute('aria-label')||'') + (e.innerText||'') + (e.getAttribute('placeholder')||'') + (e.id && document.querySelector('label[for='+e.id+']') ? 'x':'');
            return !n.trim(); }).map(e => e.outerHTML.slice(0,80))""")
        assert bad == [], (page, bad)
        assert p.pg.evaluate("document.documentElement.lang") == "en"
        assert p.pg.evaluate("document.querySelectorAll('th:not([scope])').length") == 0, page
    p.pg.keyboard.press("Tab"); assert p.pg.evaluate("document.activeElement.tagName") != "BODY"


def test_hash_navigation_and_back(server, browser):
    p = Page(browser, "admin"); p.nav("inventory"); p.nav("compliance")
    p.pg.go_back(); time.sleep(0.5)
    assert p.pg.locator("h1#title").inner_text() == "Inventory"


# ====================================================================== predictive monitoring UI
def test_predictive_page_lists_early_warnings_with_badge(server, browser):
    p = Page(browser, "viewer")
    p.nav("predictive")
    expect(p.pg.locator("h1#title")).to_have_text("Predictive")
    assert p.pg.locator("tbody tr.click").count() >= 6
    expect(p.pg.locator("#b-pred")).not_to_be_hidden()
    assert int(p.pg.locator("#b-pred").inner_text()) >= 6
    body = p.pg.inner_text("#content")
    for s in ("Rising interface errors", "Optical signal degrading", "Link heading for saturation", "Interface instability", "Traffic dropped"):
        assert s in body, s
    assert "Both ends of the link" in body
    assert not p.errors, p.errors


def test_prediction_drawer_charts_forecast_and_keyboard(server, browser):
    p = Page(browser, "viewer")
    p.nav("predictive")
    row = p.pg.locator("tbody tr.click").nth(2)
    row.focus(); p.pg.keyboard.press("Enter")
    p.pg.wait_for_selector(".drawer svg.chart", timeout=5000)
    charts = p.pg.locator(".drawer svg.chart")
    assert charts.count() >= 2
    for i in range(charts.count()):
        assert charts.nth(i).get_attribute("aria-label")
    assert p.pg.locator(".drawer path.forecast").count() >= 1
    assert "Evidence" in p.pg.inner_text(".drawer")
    assert p.pg.locator(".drawer button:has-text('Mute')").count() == 0          # viewer: read-only
    p.pg.keyboard.press("Escape")
    assert p.pg.locator(".drawer").count() == 0
    assert not p.errors, p.errors


def test_operator_can_mute_and_unmute_from_ui(server, browser):
    p = Page(browser, "operator")
    p.nav("predictive")
    p.pg.locator("tbody tr.click").last.click()
    p.pg.wait_for_selector(".drawer")
    p.pg.click(".drawer button:has-text('Mute')")
    p.pg.wait_for_selector(".toast")
    time.sleep(0.6)
    assert "muted" in p.pg.inner_text("#content")
    p.pg.locator("tbody tr.click").last.click()
    p.pg.wait_for_selector(".drawer")
    p.pg.click(".drawer button:has-text('Unmute')")
    time.sleep(0.6)
    assert "muted" not in p.pg.inner_text("#content").split("Interface health map")[0].lower().replace("read-only", "")


def test_interface_health_map_opens_interface_drawer(server, browser):
    p = Page(browser, "viewer")
    p.nav("predictive")
    cells = p.pg.locator(".ifcell")
    assert cells.count() >= 40
    assert p.pg.locator(".ifcell.risk-high").count() >= 5
    assert p.pg.locator(".ifcell.risk-ok").count() >= 25
    cells.first.click()
    p.pg.wait_for_selector(".drawer svg.chart")
    assert "Last 12 hours" in p.pg.inner_text(".drawer")


def test_overview_and_topology_surface_predictions(server, browser):
    p = Page(browser, "viewer")
    expect(p.pg.locator("#content")).to_contain_text("Early warnings")
    assert p.pg.locator("#content tbody tr.click").count() >= 5
    p.nav("topology")
    assert p.pg.locator("line.edge.risk").count() >= 1


def test_predictive_page_is_responsive_on_mobile(server, browser):
    p = Page(browser, "viewer", size=(390, 800))
    p.nav("predictive")
    w = p.pg.evaluate("document.documentElement.scrollWidth")
    assert w <= 400 + 10 or p.pg.evaluate("getComputedStyle(document.querySelector('.tablewrap')).overflowX") in ("auto", "scroll")


def test_ai_assistant_answers_predictive_question_in_ui(server, browser):
    p = Page(browser, "viewer")
    p.nav("ai")
    p.pg.fill("input[aria-label=Message]", "which interfaces are at risk?"); p.pg.keyboard.press("Enter")
    p.pg.wait_for_selector(".msg.a table", timeout=8000)
    assert "before any outage" in p.pg.inner_text(".msgs")


def test_zz_fast_forward_turns_prediction_into_outage(server, browser):
    p = Page(browser, "admin")
    p.pg.wait_for_selector("button:has-text('Fast-forward 6 h')")
    p.pg.click("button:has-text('Fast-forward 6 h')")
    p.pg.wait_for_selector(".toast", timeout=60000)
    time.sleep(1)
    p.nav("predictive")
    p.pg.wait_for_selector("text=Predictions that came true")
    came_true = p.pg.locator(".kpi:has-text('came true') .v").inner_text()
    assert int(came_true) >= 1
    p.nav("incidents")
    assert "hq-dist2" in p.pg.inner_text("#content")
    assert not [e for e in p.errors if "401" not in e]
