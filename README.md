# eradius

This fork of eradius is a radical deviation from the original
Jungerl code. It contains a generic RADIUS client, support for 
several authentication mechanisms and dynamic configuration
(it implements the `config_change/3` application callback).

We should probably rename it to avoid confusion.

## Building eradius

```
git clone {{REPO_LINK}} ./eradius
cd eradius
./rebar get-deps
./rebar compile
```

## Starting eradius from cli

```
erl -pa $PWD/ebin -pa $PWD/deps/*/ebin -pa $PWD/priv
application:ensure_all_started(eradius).
```

Note: To use `ensure_all_started` you will need Erlang R16B02 or better.
