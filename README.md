# RLE [![Build Status](https://api.travis-ci.org/yne/rle.svg)](https://travis-ci.org/yne/rle) [![Coverage](https://codecov.io/github/yne/rle/coverage.svg?branch=master)](https://codecov.io/github/yne/rle?branch=master)
Return Link Encapsulation protocol provide a flexible, bandwidth efficient transport protocol for DVB-RCS2 based satellite network.

# Principes
To abstract trasmited payload from the physical limitation, RLE use 4 layers:

- Service Data Unit (SDU) : contain the higher level payload (IP, Ethernet, Vlan).
- Addressed Link PDU (ALPDU) : contain the SDU and it meta data (protocol pype, label, protection).
- Payload-adapted PDU (PPDU) : use to adapt each variable-sized ALPDU into the fixed-sized physical layer frames.
- Frame PDU (FPDU) : The physical frame that transit throught the satelite link. 

```
                  ┌─SDU1──┐       ┌───SDU2────┐       ┌──SDU3───┐
      ↓           │       │       │           │       │         │      ↑
                  └───────┘       └───────────┘       └─────────┘ 
 Encapsulation                                                  Decapsulation
                ┌──ALPDU1─┐   ┌──────ALPDU2───────┐   ┌─ALPDU3──┐       
      ↓         │P│ SDU1  │   │P│L│   SDU2    │Pro│   │  SDU3   │      ↑
                └─────────┘   └───────────────────┘   └─────────┘       
 Fragmentation                                                     Reassembly
              ┌─────PPDU1─┐ ┌──PPDU2──┐ ┌──PPDU3──┐ ┌──PPDU4────┐
      ↓       │F│  ALPDU1 │ │S│    ALP│ │E│DU2    │ │C│ ALPDU3  │      ↑
              └───────────┘ └─────────┘ └─────────┘ └───────────┘    Frame
 Frame Packing                                                     Unpacking
           ...──┬───FPDU1───┬───FPDU2───┬───FPDU3───┬───FPDU4───┌──...
      ↓         │   PPDU1   │  PPDU2  │P│  PPDU3  │P│  PPDU4    │      ↑
           ...──┴───────────┴───────────┴───────────┴───────────┴──...
```

# Features

## Memory/`memcpy` efficient
The de/encapsulation process goes throught 4 differents layers.
A naiv approch would be to create a buffer for every layer, but it imply having to memcpy the old buffer into the new one at least 3 times.
A smarter approach would :
- let the user, directly fill the ALPU "data" field (without realizing it), then simply add the ALPDU header/footer around that.
- let the user provide the FPDU location because he know, more than us, how to handle it memory allocation. 
- write each fragment of our freshly generated ALPDU into this FPDU, using PPDU header signaling.

## Stream oriented API
The de/encapsulation function use an event based API :

```
int rle_encap(rle_profile*, rle_sdu_iterator, rle_fpdu_iterator);
int rle_decap(rle_profile*, rle_fpdu_iterator, rle_sdu_iterator);
```

Iterators callbacks must handle they own memory re-allocation but most of time none are needed since they are just send()/recv() datas.
This allocation abstraction remove bunch of unnecessary problematics.
The `rle_decap`/`rle_encap` functions will {de,en}capsulate {SDU/FPDU}s into {FPDU/SDU}s until one of them run out because of an end of stream or end of process reason.

# Benchmarks (AMD E-350 @ 1.6 Ghz)

- small SDU (4B) encapsulation (worst case)
  500.000 SDU/s 6.993 fpdu/s (~4MiB/s)

- small SDU decapsulation
  TODO

# Build

```
c99 rle.c -o rle
```
# Testing 

```
./rle
```

# Documentation

See [ETSI TS 103 179](http://www.etsi.org/deliver/etsi_ts/103100_103199/103179/01.01.01_60/ts_103179v010101p.pdf) for the full RLE specification.

