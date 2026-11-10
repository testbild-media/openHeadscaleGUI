# Third-party notices

OpenHeadscaleGUI bundles or embeds the following components. Their licenses
require the copyright notices below to be reproduced with binary
distributions.

| Component | Use | License |
|---|---|---|
| [Headscale](https://github.com/juanfont/headscale) | control server, shipped as separate binary by the installer | BSD 3-Clause, Copyright (c) 2020, Juan Font |
| [Tailscale](https://github.com/tailscale/tailscale) (`tailscale.com`) | embedded tsnet nodes, DERP and STUN server | BSD 3-Clause, Copyright (c) 2020 Tailscale Inc & AUTHORS |
| [Go x/crypto, x/net, x/sys, x/term, x/time](https://cs.opensource.google/go/x) | Argon2id, ACME, terminal, rate limiting | BSD 3-Clause, Copyright 2009 The Go Authors |
| [modernc.org/sqlite](https://gitlab.com/cznic/sqlite) | database | BSD 3-Clause, Copyright (c) 2017 The Sqlite Authors |
| [gopkg.in/yaml.v3](https://github.com/go-yaml/yaml) | configuration files | MIT and Apache 2.0 |
| [rsc.io/qr](https://github.com/rsc/qr) | QR codes for 2FA | BSD 3-Clause, Copyright (c) 2011 The Go Authors |

The full dependency list including transitive modules is in `go.mod`/`go.sum`;
each module's license is distributed with its source.

## BSD 3-Clause License (applies to the BSD-licensed components above)

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
