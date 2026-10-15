# How this copy differs from html5ever 0.39.0 on crates.io

One change: **`<?` starts a processing instruction, as in Chrome 151**.

Chrome 151 tokenizes `<?target data?>` in HTML into a ProcessingInstruction
node (`third_party/blink/renderer/core/html/parser/html_tokenizer.cc`,
`kProcessingInstruction*States`); html5ever follows the older rule and makes a
bogus comment of it. Pages read the difference: `innerHTML` prints
`<?pi z?>` in Chrome and `<!--?pi z?-->` here, and `nodeType` is 7, not 8.

`src/tokenizer/states.rs` adds five states, `src/tokenizer/mod.rs` implements
them as Chrome does:

- the target is ASCII letters, digits, `-` and `_`, starting with a letter or
  `_`, lowercased; `xml` and `xml-stylesheet` (any case) are not targets, and
  any other character after the target makes the whole thing a bogus comment
  `?` + target as written, as before;
- whitespace after the target is skipped, the data runs to `>`, and a `?`
  right before that `>` is dropped;
- end of input inside one drops it.

The tree builder has no processing instruction token, and Chrome places one
exactly where it would place a comment, so the tokenizer emits it as a comment
`\0target\0data`. No parsed comment starts with NUL (the comment states turn
NUL into U+FFFD), and `nokk-dom` turns these back into processing
instructions (`comment_json`).

One-line check:

```
nokk --load about:blank --eval "(d => (d.innerHTML = '<?pi z?>', d.firstChild.nodeType + d.innerHTML))(document.createElement('div'))"
```

prints `7<?pi z?>`.
