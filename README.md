# inspect-cert-chain

> OpenSSL-like text output for debugging certificate chains.

# Installation

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
