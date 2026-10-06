"""crawl4ai through nokk: a page behind Cloudflare, as Markdown.

    pip install nokk crawl4ai
    python crawl4ai_nokk.py https://www.scrapingcourse.com/cloudflare-challenge

crawl4ai drives its browser over CDP, so nokk plugs in through `cdp_url`; the
crawler code stays as it is. With its own Chromium, crawl4ai stops at
"Blocked by anti-bot protection" on this page.
"""
import asyncio
import sys

import nokk
from crawl4ai import AsyncWebCrawler, BrowserConfig, CacheMode, CrawlerRunConfig

URL = sys.argv[1] if len(sys.argv) > 1 else "https://www.scrapingcourse.com/cloudflare-challenge"


async def main() -> None:
    # auto_solve: every navigation that lands on a challenge clears it first.
    with nokk.launch(auto_solve=True) as server:
        browser = BrowserConfig(browser_mode="custom", cdp_url=server.ws_endpoint)
        run = CrawlerRunConfig(cache_mode=CacheMode.BYPASS, page_timeout=60000)
        async with AsyncWebCrawler(config=browser) as crawler:
            result = await crawler.arun(URL, config=run)
    if not result.success:
        sys.exit(f"failed: {result.error_message}")
    print(result.markdown)


if __name__ == "__main__":
    asyncio.run(main())
