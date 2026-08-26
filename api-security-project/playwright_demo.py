import time
from playwright.sync_api import sync_playwright

def run():
    print("Launching Chromium via Playwright for live browser presentation...")
    with sync_playwright() as p:
        # Launch browser in headed mode so it is visible to the user
        browser = p.chromium.launch(headless=False, slow_mo=800)
        context = browser.new_context(viewport={"width": 1280, "height": 800})
        
        # 1. Shop App UI
        page = context.new_page()
        print("Navigating to http://localhost:8000/ui ...")
        page.goto("http://localhost:8000/ui")
        time.sleep(2)
        
        # 2. Monitoring Dashboard
        page_dash = context.new_page()
        print("Navigating to http://localhost:9000/dashboard ...")
        page_dash.goto("http://localhost:9000/dashboard")
        time.sleep(2)
        
        # 3. Scanner UI
        page_scan = context.new_page()
        print("Navigating to http://localhost:9000/scan-ui ...")
        page_scan.goto("http://localhost:9000/scan-ui")
        time.sleep(2)

        # 4. Presenter Guide
        page_guide = context.new_page()
        print("Navigating to Presenter Guide ...")
        page_guide.goto("file:///c:/Users/Mazonia/Desktop/cyberlab%20work%20II/api-security-main/api-security-project/CY384_Presenter_Guide.html")
        time.sleep(2)
        
        print("\nAll presentation tabs loaded in Playwright Chromium window!")
        print("Press Ctrl+C in terminal when done to close browser.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            browser.close()

if __name__ == "__main__":
    run()
