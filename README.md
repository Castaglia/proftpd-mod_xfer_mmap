proftpd-mod_xfer_mmap
=====================

Status
------
[![GitHub Actions CI Status](https://github.com/Castaglia/proftpd-mod_xfer_mmap/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/Castaglia/proftpd-mod_xfer_mmap/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-GPL-brightgreen.svg)](https://img.shields.io/badge/license-GPL-brightgreen.svg)

Synopsis
--------
The `mod_xfer_mmap` module for ProFTPD uses the `mmap(2)` system call to
_map_ files to be downloaded into memory, rather than using `read(2)`.  This
hopefully saves on kernel I/O and memory usage.

See the [mod_xfer_mmap.html](https://htmlpreview.github.io/?https://github.com/Castaglia/proftpd-mod_xfer_mmap/blob/master/mod_xfer_mmap.html) documentation for more details.
