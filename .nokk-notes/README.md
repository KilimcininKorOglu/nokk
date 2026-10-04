# Captured traces

Traces that are expensive to capture again: every run against a challenge
spends the address's reputation, and some of these were taken from real Chrome.

| file | contents |
|---|---|
| `our_strings.json`, `chr_strings.json` | first-POST body fields in order, ours and Chrome's |
| `our_strings2.json` | the same after the on-the-wire size fix |
| `our_walks.json`, `our_walk.json`, `chr_walk.json` | what the graph walk asks interfaces and which numbers it gets back |
| `chr_protos.json`, `our_protos.json` | descriptors of every member of every prototype (950 interfaces) |
| `chr_worker.json`, `our_worker6.json` | worker scope own property names |
| `chr_win.json`, `our_win3.json` | window own property names, in creation order |
| `window_order.json` | tail of the window name order; `WINDOW_ORDER` in `crates/stealth` is built from it |

How to recapture them is in the project notes ("Where we stopped"). The
directory is deliberately not in `.gitignore`: the traces are small and useful
next to the code.
