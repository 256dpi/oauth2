# oauth2

[![Test](https://github.com/256dpi/oauth2/actions/workflows/test.yml/badge.svg)](https://github.com/256dpi/oauth2/actions/workflows/test.yml)
[![GoDoc](https://godoc.org/github.com/256dpi/oauth2?status.svg)](http://godoc.org/github.com/256dpi/oauth2)
[![Release](https://img.shields.io/github/release/256dpi/oauth2.svg)](https://github.com/256dpi/oauth2/releases)

**A fundamental and extendable OAuth2 library for Go.**

Package [`oauth2`](http://godoc.org/github.com/256dpi/oauth2) provides structures and functions to implement [OAuth2](https://oauth.net/2/) compatible authentication servers. The library can be used standalone or with any framework as it is built on top of the standard Go http library.

## Specifications

The library considers and implements the following specifications:
 
- [OAuth 2.0 Framework](https://tools.ietf.org/html/rfc6749) - RFC 6749
- [Bearer Token Usage](https://tools.ietf.org/html/rfc6750) - RFC 6750
- [Threat Model and Security Considerations](https://tools.ietf.org/html/rfc6819) - RFC 6819
- [Token Revocation](https://tools.ietf.org/html/rfc7009) - RFC 7009
- [Token Introspection](https://tools.ietf.org/html/rfc7662) - RFC 7662

## Example

The test [server](https://github.com/256dpi/oauth2/blob/master/server.go) implements a basic but feature-complete in-memory OAuth2 authentication server. The code can be used as a template to build a custom implementation of an OAuth2 compatible authentication server.

## Installation

Get the package using the go tool:

```bash
$ go get -u github.com/256dpi/oauth2/v2
```

## License

The MIT License (MIT)

Copyright (c) 2016 Joël Gähwiler
