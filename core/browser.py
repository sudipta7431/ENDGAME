from playwright.sync_api import sync_playwright

def browser_crawl(url, limit=200):
    """
    Headless browser crawler.
    Captures network requests made by the page.
    """
    discovered = set()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()

        # Capture network requests
        def handle_request(request):
            if request.url.startswith("http"):
                discovered.add(request.url)

        page.on("request", handle_request)

        page.goto(url, timeout=30000)
        page.wait_for_load_state("networkidle")

        browser.close()

    # Limit results
    return set(list(discovered)[:limit])
