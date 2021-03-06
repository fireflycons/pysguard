# PYSGUARD

**WORK IN PROGRESS** This work is incomplete, but is under active development!

PYSGUARD (or Python SquidGuard) is a pure python rewrite of [squidGuard](http://www.squidguard.org/) based on the [Andi Hofmeister](https://github.com/andihofmeister/squidGuard) fork and updated for [Squid](http://www.squid-cache.org/) v4.

Rather than fully reverse engineer the original C code (my C is a bit rusty these days), I went for the approach of "What is it trying to do?" and then replicate that behaviour.

This implementation is compatible with the blacklist format of squidGuard and will process the blacklists created for it. Instead of using the venerable Berkeley DB, I use sqlite3 which is a core part of modern python distributions. Performance with this is very good - a few microseconds for a 3 million URL database. I also opted to scrap the original configuration file format in favour of YAML, this being much easier to parse than creating a custom parser for the original format.

## Configuration File

This is a YAML representation of the original squidGuard config file and is intended to be a semantically close to that as possible. There are a few minor differences

* Variable definitions (e.g. `dbhome`, `logdir`):  These are now grouped under `set`. This is an idea taken from Andi Hofmiester. Environment variables my be referenced by naming them within `$()` e.g. `$(tmp)`
* Time format: This is now true 24 hour clock (00:00-23:59). 24:00 as an expression of midnight is an error.
* "NOT" indicator: Now a `~` rather than `!` as `!` has meaning in YAML. You can still use `!` however the entire pass entry should be quoted if you do.
* Destination entries: Not required to specify `domainlist` or `urlist`. Locations of these are implied from the destination name and are expected to be subdirectories of the `dbhome` directory.
* Time constraint ACLs may have separate redirects for `within`/`outside` and `else` blocks
* External files for source configuration not yet supported.

See squidGuard configuration reference for explanation of what everything does

* http://www.squidguard.org/Doc/configure.html
* http://www.squidguard.org/Doc/extended.html

## Built-in directives

### Sources

* `all` means all requests. It is processed after any user defined sources thus will match if no other defined source matches.

### Destinations

* `all` means all destinations ALLOW. It is processed after any user defined destinations thus acts as a catch-all
* `none` means all destinations DENY. It is processed after any user defined destinations thus acts as a catch-all

### ACL Entries

* `default` provides an ACL entry if no other ACL entry matches the conditions. It is processed last thus acts as a catch-all. If a default is not explicitly present in the config file, then a built-in default is used that provides full access.

## Initialising Blacklist Database

1. Choose a SquidGuard compatible blacklist ([see here](http://www.squidguard.org/blacklists.html))
1. Download and extract the tarball
1. Adjust `pysguard.conf.yaml` and set `dbhome` to point to the extracted directory
1. Run the following to import the lists into the sqlite database

```
./pysguard.py --create-db --config /path/to/pysguard.conf.yaml
```

## Module Dependencies

The following required modules should be installed using pip

* indexedproperty
* ipcalc
* pyyaml

## Coming Soon

A full containerised Squid configuration using this application directed at keeping your kids safe on your home network.
