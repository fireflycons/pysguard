# PYSGUARD

**WORK IN PROGRESS** This work is incomplete, but is uder active development!

PYSGUARD (or Python SquidGuard) is a rewrite of [squidGuard](http://www.squidguard.org/) based on the [Andi Hofmeister](https://github.com/andihofmeister/squidGuard) fork in pure python and updated for [Squid](http://www.squid-cache.org/) v4.

Rather than fully reverse engineer the original C code (my C is a bit rusty these days), I went for the approach of "What is it trying to do?" and then replicate that behaviour.

This implementation is compatible with the blacklist format of squidGuard and will process the blacklists created for it. Instead of uisng the venerable Berkeley DB, I use sqlite3 which is a core part of modern python distributions. Performance with this is very good - a few microseconds for a 3 million URL database. I also opted to scrap the original configuration file format in favour of yaml, this being much easier to parse than creating a custom parser for the original format.