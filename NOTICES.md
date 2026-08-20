# Third-party notices

ctxcop is statically linked against the following open-source libraries.
Each retains its original copyright and license. The full direct-and-
transitive dependency list lives in `go.mod`; per-module license summaries
can be regenerated with [`go-licenses`][go-licenses]:

    go install github.com/google/go-licenses@latest
    go-licenses report ./cmd/ctxcop

[go-licenses]: https://github.com/google/go-licenses

## betterleaks (MIT)

ctxcop's detection pipeline is built on [betterleaks][bl] — rule loading,
the betterleaks rule TOML schema, the Aho-Corasick keyword prefilter,
codec-aware decoding (base64 / hex / percent / unicode), and the CEL
filter primitives (`entropy()`, `failsTokenEfficiency()`, etc.) come
from upstream betterleaks.

[bl]: https://github.com/betterleaks/betterleaks

> MIT License
>
> Copyright (c) 2026 Zachary Rice
>
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.

## Other dependencies

ctxcop's transitive dependencies are predominantly MIT, Apache-2.0,
BSD-2-Clause, and BSD-3-Clause licensed. Each project's full license is
reproduced in its source distribution; running `go-licenses report` (above)
emits a per-module CSV with SPDX identifiers and source URLs.

Direct dependencies (see `go.mod` for versions):

- [`github.com/BurntSushi/toml`](https://github.com/BurntSushi/toml) — MIT
- [`github.com/betterleaks/betterleaks`](https://github.com/betterleaks/betterleaks) — MIT
- [`github.com/spf13/viper`](https://github.com/spf13/viper) — MIT

Indirect dependencies inherit licensing from their respective projects.
