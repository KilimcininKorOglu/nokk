# Using nokk from other tools

Anything that drives Chrome over the DevTools Protocol can drive nokk: point it at
nokk's endpoint instead of launching a browser. The tool keeps working as it was,
and the pages it visits see Chrome 151 on Linux, Cloudflare's challenges included.

## crawl4ai

[crawl4ai](https://github.com/unclecode/crawl4ai) turns pages into Markdown for LLMs.
Its own Chromium is stopped by Cloudflare ("Blocked by anti-bot protection"); with
nokk the same crawl gets the page behind the challenge. Needs nokk 0.1.37 or newer.

```python
import asyncio, nokk
from crawl4ai import AsyncWebCrawler, BrowserConfig, CacheMode, CrawlerRunConfig

async def main():
    with nokk.launch(auto_solve=True) as server:
        browser = BrowserConfig(browser_mode="custom", cdp_url=server.ws_endpoint)
        async with AsyncWebCrawler(config=browser) as crawler:
            r = await crawler.arun("https://www.scrapingcourse.com/cloudflare-challenge",
                                   config=CrawlerRunConfig(cache_mode=CacheMode.BYPASS))
            print(r.markdown)

asyncio.run(main())
```

The full script is [examples/crawl4ai_nokk.py](../examples/crawl4ai_nokk.py). A nokk
server that is already running works the same way: `cdp_url="ws://127.0.0.1:9222/devtools/browser/nokk"`
(add `?token=…` if it was started with one).

What does not work: crawl4ai's screenshots and PDFs (nokk has no rendering engine).

## Playwright and Puppeteer

See the [README](../README.md#usage). Through Playwright: navigation, `evaluate`,
locators, cookies (`addCookies`, `cookies()`), new pages and CDP sessions.

## browser-use

Not yet. browser-use reads pages through CDP domains nokk does not serve today
(`DOMSnapshot`, `Accessibility`, screenshots); support is planned.
