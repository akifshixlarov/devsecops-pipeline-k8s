import json
import os
import subprocess
import time
import base64
import requests
import websocket

EDGE_PATH = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
OUTPUT_DIR = r"E:\Main Programs\dell\Projects\devsecops-pipeline-k8s\evidence\defectdojo"
PROFILE_DIR = r"C:\temp\edge_cdp_profile"

def get_auth_cookies():
    dd_url = os.environ.get("DD_URL", "http://localhost:8080").rstrip("/")
    username = os.environ.get("DD_USERNAME", "admin")
    password = os.environ.get("DD_PASSWORD", "")
    if not password:
        raise RuntimeError("DD_PASSWORD environment variable is required")

    print("Obtaining DefectDojo session cookies via login API...")
    s = requests.Session()
    r = s.get(f"{dd_url}/login", timeout=10)
    csrf = s.cookies.get("csrftoken", "")
    login_data = {
        "username": username,
        "password": password,
        "csrfmiddlewaretoken": csrf,
    }
    r = s.post(f"{dd_url}/login", data=login_data, headers={"Referer": f"{dd_url}/login"}, timeout=10)
    cookies = dict(s.cookies)
    print(f"Login response status: {r.status_code}, cookies obtained: {list(cookies.keys())}")
    return cookies

def cdp_request(ws, method, params=None, req_id=1):
    msg = {"id": req_id, "method": method}
    if params:
        msg["params"] = params
    ws.send(json.dumps(msg))
    while True:
        res = json.loads(ws.recv())
        if res.get("id") == req_id:
            return res

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(PROFILE_DIR, exist_ok=True)

    cookies = get_auth_cookies()
    sessionid = cookies.get("sessionid")
    csrftoken = cookies.get("csrftoken")
    if not sessionid:
        raise RuntimeError("Failed to obtain sessionid cookie")

    # Start Edge with remote debugging
    print("Starting Edge in headless mode with remote debugging...")
    proc = subprocess.Popen([
        EDGE_PATH,
        "--headless=new",
        "--remote-debugging-port=9222",
        "--remote-allow-origins=*",
        f"--user-data-dir={PROFILE_DIR}",
        "--window-size=1920,1080",
        "--disable-gpu",
        "--no-sandbox",
        "about:blank"
    ])

    try:
        # Wait for CDP endpoint
        ws_url = None
        for _ in range(15):
            time.sleep(1)
            try:
                tabs = requests.get("http://localhost:9222/json", timeout=2).json()
                for tab in tabs:
                    if tab.get("type") == "page":
                        ws_url = tab.get("webSocketDebuggerUrl")
                        break
                if ws_url:
                    break
            except Exception:
                pass

        if not ws_url:
            raise RuntimeError("Failed to connect to Edge CDP endpoint")

        print(f"Connected to CDP: {ws_url}")
        ws = websocket.create_connection(ws_url, timeout=15)

        # Enable Network and Page domains
        cdp_request(ws, "Network.enable", req_id=1)
        cdp_request(ws, "Page.enable", req_id=2)

        # Set Cookies
        print("Injecting authentication cookies...")
        cdp_request(ws, "Network.setCookie", {
            "name": "sessionid",
            "value": sessionid,
            "domain": "localhost",
            "path": "/"
        }, req_id=3)
        cdp_request(ws, "Network.setCookie", {
            "name": "csrftoken",
            "value": csrftoken,
            "domain": "localhost",
            "path": "/"
        }, req_id=4)

        pages = [
            ("http://localhost:8080/dashboard", "dashboard.png"),
            ("http://localhost:8080/engagement/1", "engagement.png"),
            ("http://localhost:8080/finding?test__engagement=1", "findings.png")
        ]

        req_id = 10
        for url, filename in pages:
            print(f"Navigating to {url}...")
            req_id += 1
            cdp_request(ws, "Page.navigate", {"url": url}, req_id=req_id)
            time.sleep(4)  # Wait for charts/tables to render

            print(f"Capturing screenshot for {filename}...")
            req_id += 1
            res = cdp_request(ws, "Page.captureScreenshot", {"format": "png"}, req_id=req_id)
            img_data = base64.b64decode(res["result"]["data"])

            target_path = os.path.join(OUTPUT_DIR, filename)
            with open(target_path, "wb") as fh:
                fh.write(img_data)
            print(f"Saved: {target_path} ({len(img_data)} bytes)")

        ws.close()
        print("All 3 screenshots successfully generated!")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

if __name__ == "__main__":
    main()
