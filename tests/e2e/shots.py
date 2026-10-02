"""Capture README screenshots from a running *demo* instance:  python tests/e2e/shots.py http://localhost:8080"""
import os, sys, time
from playwright.sync_api import sync_playwright

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "docs", "screenshots")
os.makedirs(OUT, exist_ok=True)
if os.path.isdir("/tmp/libs"):
    os.environ["LD_LIBRARY_PATH"] = "/tmp/libs/usr/lib/x86_64-linux-gnu:/tmp/libs/lib/x86_64-linux-gnu:" + os.environ.get("LD_LIBRARY_PATH", "")
ADMIN = os.environ.get("ONC_ADMIN_PASSWORD", "Adm1n-Demo#2026")
OPER = os.environ.get("ONC_DEMO_OPERATOR_PASSWORD", "Oper4tor-Demo#2026")

def fault(pg, **body):
    pg.evaluate("""async (b) => { await fetch('/api/lab/fault', {method:'POST', headers:{'Content-Type':'application/json','Authorization':'Bearer '+sessionStorage.getItem('onc_token')}, body: JSON.stringify(b)}) }""", body)

with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_page(viewport={"width": 1440, "height": 900})
    errors = []
    pg.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    pg.goto(BASE); pg.fill("#u", "admin"); pg.fill("#p", ADMIN); pg.keyboard.press("Enter")
    pg.wait_for_selector(".shell"); time.sleep(1)
    def shot(name, wait=0.8):
        time.sleep(wait); pg.screenshot(path=f"{OUT}/{name}.png")
    def nav(page): pg.click(f"button[data-page={page}]"); time.sleep(0.5)
    nav("predictive"); pg.wait_for_selector("text=Early warnings"); shot("09-predictive", 1.0)
    pg.locator("tr.click", has_text="hq-dist2").first.click(); pg.wait_for_selector(".drawer .chart"); shot("10-predictive-detail", 0.8)
    pg.keyboard.press("Escape")
    fault(pg, action="power_off", device="hq-dist1"); fault(pg, action="cpu", device="cebu-fw1", value=96)
    nav("overview"); pg.reload(); pg.wait_for_selector(".shell"); shot("01-overview", 1.2)
    nav("incidents"); shot("02-incident-root-cause")
    nav("topology"); shot("03-topology")
    fault(pg, action="power_on", device="hq-dist1"); fault(pg, action="cpu", device="cebu-fw1", value=30)
    nav("inventory"); pg.reload(); pg.wait_for_selector(".shell"); time.sleep(0.8)
    pg.locator("tbody tr", has_text="hq-fw1").first.click(); pg.wait_for_selector(".drawer"); shot("04-inventory-device", 0.8)
    pg.keyboard.press("Escape"); shot("04b-inventory", 0.3)
    nav("ai")
    for q in ["Which devices still have telnet enabled?", "Block IP 203.0.113.9 on all firewalls"]:
        pg.fill("input[aria-label=Message]", q); pg.keyboard.press("Enter"); time.sleep(1.2)
    shot("05-ai-assistant", 0.8)
    pg.click("button:has-text('Review change')"); pg.wait_for_selector(".drawer"); shot("06-change-approval", 0.8)
    pg.keyboard.press("Escape")
    nav("compliance"); shot("07-compliance")
    nav("platforms"); shot("08-platforms")
    print("console errors:", errors)
    b.close()
