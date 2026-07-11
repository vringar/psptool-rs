import re, time, sys
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup

HUB = "http://localhost:4444/wd/hub"


def make_driver():
    opts = Options()
    for a in ["--no-sandbox", "--disable-dev-shm-usage",
              "--disable-blink-features=AutomationControlled",
              "--window-size=1400,1000", "--lang=en-US"]:
        opts.add_argument(a)
    opts.add_experimental_option("excludeSwitches", ["enable-automation"])
    opts.add_experimental_option("useAutomationExtension", False)
    d = webdriver.Remote(command_executor=HUB, options=opts)
    d.set_page_load_timeout(35)
    try:
        d.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument",
            {"source": "Object.defineProperty(navigator,'webdriver',{get:()=>undefined})"})
    except Exception:
        pass
    return d


d = make_driver()

LIST = ("https://www.asrockrack.com/general/products-ajax.asp?Model=&Type={t}"
        "&CPU=AMD&Category=&Usage=&Socket=&CPUnum=&DIMM=&Form=&BuildingBlocks="
        "&Bricks=&Form2=&Acc=&Life=&p=")

# warm up Incapsula cookie once
d.get(LIST.format(t="Server") + "1"); time.sleep(6)
d.get(LIST.format(t="Server") + "1"); time.sleep(4)

names = []
for t in ("Server", "WS"):
    prev = None
    for page in range(1, 13):
        d.get(LIST.format(t=t) + str(page)); time.sleep(2.5)
        cur = [m.get_text(strip=True) for m in
               BeautifulSoup(d.page_source, "html.parser").find_all("div", class_="ModelName")]
        if not cur or cur == prev:
            break
        for n in cur:
            if n not in names:
                names.append(n)
        prev = cur
print(f"TOTAL AMD server/WS models: {len(names)}", flush=True)
for n in names:
    print("  MODEL:", n)

FAM = re.compile(r"(GENOA|TURIN|BERGAMO|SIENA|SORANO)", re.I)
targets = [n for n in names if FAM.search(n)]
print(f"\nZen 4/5 (SP5/SP6) targets: {len(targets)}", flush=True)

DL = "https://www.asrockrack.com/general/productdetail-download.asp?Model={}&OS=BIOS"
print("\n=== newest BIOS link per Zen 4/5 board ===", flush=True)
for name in targets:
    try:
        d.get(DL.format(name.replace("/", ""))); time.sleep(3)
        soup = BeautifulSoup(d.page_source, "html.parser")
        rows = soup.tbody.find_all("tr")[1:] if soup.tbody else []
        best = None
        for entry in rows:
            cols = entry.find_all("td")
            if len(cols) < 8:
                continue
            ver = cols[0].get_text(strip=True)
            a = cols[7].find("a")
            link = a.get("href") if a else None
            if link and not str(link).startswith("http"):
                m = re.search(r"(http[^'\"]+)", a.get("onclick") or "")
                link = m.group(0) if m else None
            if link:
                best = (ver, link)
                break
        print(f"{name} :: {best[0] if best else 'NO-LINK'} :: {best[1] if best else ''}", flush=True)
    except Exception as e:
        print(f"{name} :: ERROR {type(e).__name__}: {e}", flush=True)
d.quit()
