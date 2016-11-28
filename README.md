Return Link Encapsulation (RLE) Implementation as defined by the ETSI TS 103 179

# Build [![Build Status](https://api.travis-ci.org/yne/rle.svg)](https://travis-ci.org/yne/rle)

```
c99 rle.c
```
# Testing [![Coverage](https://codecov.io/github/yne/rle/coverage.svg?branch=master)](https://codecov.io/github/yne/rle?branch=master)

```
./a.out
```

# Benchmarking (AMD E-350 @ 1.6 Ghz)

- small SDU (4B) encapsulation (worst case)
	500.000 SDU/s 6.993 fpdu/s (~4MiB/s)

- smal SDU decapsulation
	TODO

# Documentation

See [ETSI TS 103 179](http://www.etsi.org/deliver/etsi_ts/103100_103199/103179/01.01.01_60/ts_103179v010101p.pdf) for the full RLE specification.

