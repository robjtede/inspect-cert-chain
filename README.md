# inspect-cert-chain

> OpenSSL-like text output for debugging certificate chains.

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

- [x] OpenSSL-like text info
- [x] fetch certificate from URL
- [x] interpret more standard X.509 extensions
- [x] option to read local chain files
- [ ] determine chain validity
