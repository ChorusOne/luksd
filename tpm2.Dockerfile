FROM ubuntu:20.04

RUN apt-get update
RUN apt-get install -y libssl-dev build-essential git autoconf automake libtool m4 vim autoconf-archive pkgconf libjson-c-dev uuid-dev

RUN git clone https://github.com/tpm2-software/tpm2-tss.git
RUN git clone https://github.com/tpm2-software/tpm2-tools
RUN git clone https://github.com/curl/curl

# build and install tss lib

RUN cd curl && autoreconf -fi && ./configure "CFLAGS=--static" --disable-shared --with-openssl --prefix=/usr && make -j && make install

RUN cd tpm2-tss && ./bootstrap && \
    ./configure "CFLAGS=--static" --enable-shared=no --enable-fapi=no --enable-nodl --disable-tcti-mssim --disable-integration --disable-tcti-swtpm --disable-hardening --prefix=/usr --disable-doxygen-doc && make -j && make install && \
    echo "/usr/lib" > /etc/ld.so.conf.d/tss.conf && ldconfig

RUN cd tpm2-tools && ./bootstrap && ./configure "CFLAGS=--static" --enable-fapi=no --enable-shared=no --disable-hardening --disable-fapi --prefix=/usr

RUN cd tpm2-tools && make -j && make install

ENTRYPOINT ["/bin/cp", "/usr/bin/tpm2", "/output/tpm2"]
