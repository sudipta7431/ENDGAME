from playwright.sync_api import sync_playwright

def login_form(login_url, username, password, selectors):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        page.goto(login_url, timeout=30000)

        page.fill(selectors["username"], username)
        page.fill(selectors["password"], password)
        page.click(selectors["submit"])

        page.wait_for_load_state("networkidle")

        cookies = page.context.cookies()
        browser.close()

        return cookies
