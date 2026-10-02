#!/usr/bin/env bash
# Run nokk against the public Cloudflare test targets and print, per target: the
# verdict (exit code 0 = through, 3 = a gate is still up), the time, the final
# page title and, where a Turnstile widget sits on the page, its token length.
# Do not run it alongside `cargo test` or a Chrome: under load a challenge can
# run out of time.
NOKK=${NOKK:-./target/release/nokk}   # or: NOKK=$(command -v nokk) tools/cf-check.sh
PROBE='(() => { const t = document.querySelector("[name=cf-turnstile-response]");
  return document.title + "  |  " + (/Just a moment/i.test(document.title) ? "GATE" : "page")
    + (t && t.value ? "  |  token " + t.value.length + " chars" : ""); })()'
for url in \
  https://www.chess.com/login \
  https://www.scrapingcourse.com/cloudflare-challenge \
  https://peet.ws/turnstile-test/managed.html \
  https://peet.ws/turnstile-test/non-interactive.html \
  https://nopecha.com/demo/cloudflare \
  https://www.usvisascheduling.com/en-US/ ; do
  t0=$(date +%s)
  out=$(RUST_LOG=error timeout 90 "$NOKK" --load "$url" --solve-challenge 30 --fail-on-challenge --eval "$PROBE" 2>/dev/null)
  code=$?
  case $code in 0) st="OK  ";; 3) st="FAIL";; 124) st="TIME";; *) st="E$code";; esac
  printf '%s %3ss  %-52s %s\n' "$st" $(( $(date +%s)-t0 )) "$url" "$(echo "$out" | grep -v '^\s*$' | tail -1)"
done
