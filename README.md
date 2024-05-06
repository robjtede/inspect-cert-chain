# `inspect-cert-chain`

> OpenSSL-like text output for debugging certificate chains.

[![asciicast](https://asciinema.org/a/657965.svg)](https://asciinema.org/a/657965)

# Install

With [`cargo-binstall`]:

```console
$ cargo binstall inspect-cert-chain
```

From source:

```console
$ cargo install inspect-cert-chain
```

# Usage

From remote host:

```console
inspect-cert-chain --host <hostname>
```

From chain file:

```console
inspect-cert-chain --file <path>
```

From stdin:

```console
cat <path> | inspect-cert-chain --file -
```

# Roadmap

- [x] OpenSSL-like text info.
- [x] Fetch certificate chain from remote host.
- [x] Read certificate chain from file and stdin.
- [x] Interpret standard X.509 extensions.
- [x] Option to read local chain files.
- [ ] Determine chain validity.

[`cargo-binstall`]: https://github.com/cargo-bins/cargo-binstall
