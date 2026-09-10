# Per-variant RandomX constants

One header per RandomX variant. A tier-2 variant's header is injected into its
own compiled core with `-include` (see `Makefile.am`); a tier-1 variant's
values are applied at runtime instead, and its header uses distinct macro
names so they cannot collide with the core's compile-time defaults.

The vendored `configuration.h` and `aes_hash.cpp` wrap every constant in
`#ifndef`, so an injected header wins and anything it omits keeps the rx/0
value. `-include` rather than `-D` because several constants are
comma-separated four-word lists.

rx/0 injects nothing, so its objects compile exactly as they did before the
`#ifndef` wraps were added.

Every value here is consensus data. Derive it from the coin's own source and
record the URL and pinned commit in the header. Do not read a fork's default
branch: at least one of these forks leaves upstream's salt there. A wrong
constant does not mine nothing quietly, it submits shares that are all
rejected.
