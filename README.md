# ROSE: Robust Searchable Encryption with Forward and Backward Security

This repository open-sources the experimental code used in the paper *ROSE: Robust Searchable Encryption with Forward and Backward Security*. Containing the implementations of ROSE (proposed in this paper), [Fides](https://dl.acm.org/doi/abs/10.1145/3133956.3133980?casa_token=410_cucSorkAAAAA:Fwl7Hfwd5HW3ARk5NxJlEZQTGmyGpZtD54vZHWeVl0Fh2y4o8CbO-dNYgZj2txos0pR1y65_jRKVfA), [Horus](https://dl.acm.org/doi/abs/10.1145/3243734.3243833), and [IM-DSSE<sub>I+II</sub>](https://ieeexplore.ieee.org/document/8632753).

# Required Libraries

All implementations are compiled and run under Ubuntu Server 20.04 X86_64 with GCC 9.4.0, cmake 3.16.3, and OpenSSL 1.1.1f.

## ROSE

ROSE additionally requires the [Relic](https://github.com/relic-toolkit/relic) Ver. 0.5.0. Make sure configuring relic by passing the following argument to cmake before compiling it.

`-DMULTI=PTHREAD`

## Fides

Fides additionally requires [GMP Library](https://gmplib.org). In Ubuntu, this library can be installed by the following command.

`sudo apt-get install libgmp-dev`

## Horus

The code of Horus is revised from the corresponding [code of Chamani](https://github.com/jgharehchamani/SSE). The code of Horus requires no additional libraries.

## IM-DSSE<sub>I+II</sub>

The code of IM-DSSE<sub>I+II</sub> is revised from the corresponding [code of Hoang](https://github.com/thanghoang/IM-DSSE). To compile and run this code, one needs to install [LibTomCrypt](https://www.libtom.net/LibTomCrypt/) and [libaesni](https://github.com/amiralis/libaesni).

Specifically, to install this library. on needs to run the following commands.

```
sudo apt-get install yasm
git clone https://github.com/amiralis/libaesni.git
cd libaesni
make -j
sudo cp libaes_lin64.so /usr/local/lib
sudo cp iaes*h /usr/local/include
sudo ldconfig -v
```