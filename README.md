# oauth2

[![Build Status](https://travis-ci.org/gonfire/oauth2.svg?branch=master)](https://travis-ci.org/gonfire/oauth2)
[![Coverage Status](https://coveralls.io/repos/github/gonfire/oauth2/badge.svg?branch=master)](https://coveralls.io/github/gonfire/oauth2?branch=master)
[![GoDoc](https://godoc.org/github.com/gonfire/oauth2?status.svg)](http://godoc.org/github.com/gonfire/oauth2)
[![Release](https://img.shields.io/github/release/gonfire/oauth2.svg)](https://github.com/gonfire/oauth2/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/gonfire/oauth2)](http://goreportcard.com/report/gonfire/oauth2)

**A fundamental and extendable OAuth2 library for Go.**

Package [`oauth2`](http://godoc.org/github.com/gonfire/oauth2) provides structures and functions to implement [OAuth2](https://oauth.net/2/) compatible authentication servers. The library can be used with any framework and is built on top of the standard Go http library.

_Note: This package is still under development._

## Specifications

The library considers and implements the following specifications:
 
- [OAuth 2.0 Framework](https://tools.ietf.org/html/rfc6749) - RFC 6749
- [Bearer Token Usage](https://tools.ietf.org/html/rfc6750) - RFC 6750
- [Threat Model and Security Considerations](https://tools.ietf.org/html/rfc6819) - RFC 6819

## Example

The following examples show the usage of this package:

- The [server](https://github.com/gonfire/oauth2/blob/master/examples/server) example implements a complete authentication server using the standard HTTP package.

## Installation

Get the package using the go tool:

```bash
$ go get -u github.com/gonfire/oauth2
```

## License

The MIT License (MIT)

Copyright (c) 2016 Joël Gähwiler
