# nassh-relay

[![Build Status](https://badge.buildkite.com/8fad31fa601281619d3c24b5473abd741ea029a8f80dcf4292.svg)](https://buildkite.com/lstoll/nassh-relay)
[![godoc](https://godoc.org/github.com/lstoll/nassh-relay?status.svg)](https://godoc.org/github.com/lstoll/nassh-relay)

Basic implementation of the [nassh relay protocol](https://chromium.googlesource.com/apps/libapps/+/HEAD/nassh/doc/relay-protocol.md) in Go. This can be used for relaying SSH sessions in the ChromeOS SSH app, but worth noting is that it doesn't contain any SSH specific code - it could be used to relay any TCP connections.

This repository doesn't contain any usable client/server implementations, it's just a library. An example bastion that uses OpenID Connect for auth can be found in [https://github.com/lstoll/ssh-bastion](https://github.com/lstoll/ssh-bastion).
