ARG REGISTRY_PREFIX=''
ARG CODENAME=bionic

FROM ${REGISTRY_PREFIX}ubuntu:${CODENAME} as builder

RUN set -x \
	&& apt update \
	&& apt upgrade -y \
	&& apt install --yes --no-install-recommends \
		build-essential \
		autotools-dev \
		automake \
		pkg-config \
                libltdl-dev \
		ca-certificates \
		curl \
		libqt4-dev \
		libqt4-sql-sqlite \
		qt4-dev-tools \
		x11-apps \
		python3-pip

ARG INSTALL_SPHINX=
RUN test "$INSTALL_SPHINX" != "yes" || pip3 install sphinx

ARG PARALLELMFLAGS=-j2

ARG BUILD_DIR=/tmp/build

ARG DUMB_INIT_VERSION=1.2.2
RUN set -x \
	&& mkdir -p ${BUILD_DIR} \
	&& cd ${BUILD_DIR} \
	&& curl -fSL -s -o dumb-init-${DUMB_INIT_VERSION}.tar.gz https://github.com/Yelp/dumb-init/archive/v${DUMB_INIT_VERSION}.tar.gz \
	&& tar -xf dumb-init-${DUMB_INIT_VERSION}.tar.gz \
	&& cd dumb-init-${DUMB_INIT_VERSION} \
	&& make "$PARALLELMFLAGS" \
	&& chmod +x dumb-init \
	&& mv dumb-init /usr/local/bin/dumb-init \
	&& dumb-init --version \
	&& cd \
	&& rm -rf ${BUILD_DIR}

ARG OPENSSL_UPSTREAM=old/1.1.1/openssl-1.1.1d.tar.gz
ARG OPENSSL_SHA1=056057782325134b76d1931c48f2c7e6595d7ef4
ARG OPENSSL_BUILD_PARALLEL=YES
ARG OPENSSL_FLAGS=
RUN set -x \
	&& mkdir -p ${BUILD_DIR} \
	&& cd ${BUILD_DIR} \
	&& curl -fSL -s -o openssl.tar.gz https://www.openssl.org/source/${OPENSSL_UPSTREAM} \
	&& echo "${OPENSSL_SHA1} openssl.tar.gz" | sha1sum -c - \
	&& tar -xf openssl.tar.gz \
	&& cd openssl-* \
	&& ./config shared --prefix=/usr/local --openssldir=/usr/local ${OPENSSL_FLAGS} \
	&& if [ "${OPENSSL_BUILD_PARALLEL}" == "YES" ] ; then make "$PARALLELMFLAGS" ; else make ; fi \
	&& make install \
	&& cd \
	&& rm -rf ${BUILD_DIR}

ENV LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/usr/local/lib"

COPY . ${BUILD_DIR}
RUN set -x \
	&& cd ${BUILD_DIR} \
	&& ./bootstrap \
	&& ./configure \
	&& make "$PARALLELMFLAGS" \
	&& make install \
	&& cd \
	&& rm -rf ${BUILD_DIR}

ARG USER_ID=1000
RUN set -x \
	&& useradd -u "$USER_ID" -ms /bin/bash user

ENTRYPOINT ["dumb-init", "--", "xca"]

