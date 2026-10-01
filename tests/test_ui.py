import socket
import threading
import time

import pytest
import uvicorn

from app import app

@pytest.fixture(scope="module")
def url():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    while not server.started: time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True

def test_poisoned_write_executes_on_a_is_refused_on_c_and_ben_needs_approval(url):
    sync_playwright = pytest.importorskip("playwright.sync_api").sync_playwright
    with sync_playwright() as p:
        try: browser = p.chromium.launch()
        except Exception as e: pytest.skip(f"Chromium is not installed ({type(e).__name__}); run: playwright install chromium")
        pg = browser.new_page()
        pg.goto(url)
        pg.wait_for_selector("#scenario option", state="attached")  # the Run handler is wired right after the options are filled in
        pg.click("#go")  # Ana, design A, the poisoned report
        pg.wait_for_selector("#result:has-text('FEED_RATE is now 7.5')")
        pg.select_option("#design", "C")
        pg.click("#go")
        pg.wait_for_selector("#result:has-text('FEED_RATE is now 6.0')")
        assert "insufficient_scope" in pg.inner_text("#trace")
        pg.select_option("#user", "ben")
        pg.select_option("#scenario", "set8")
        pg.click("#go")
        pg.click("#approve")
        pg.wait_for_selector("#result:has-text('FEED_RATE is now 8.0')")
