ARG REGISTRY_PREFIX=''
ARG CODENAME=jammy

FROM ${REGISTRY_PREFIX}ubuntu:${CODENAME} as builder

ENV DEBIAN_FRONTEND noninteractive

RUN set -x \
	&& apt update \
	&& apt upgrade -y \
	&& apt install --yes --no-install-recommends \
		build-essential libssl-dev pkg-config qtbase5-dev \
		qttools5-dev-tools qttools5-dev libqt5sql5 libqt5help5 \
		python3-sphinxcontrib.qthelp git cmake

ARG PARALLELMFLAGS=-j6
ARG BUILD_DIR=/tmp/build

COPY . ${BUILD_DIR}
RUN set -x \
	&& cd ${BUILD_DIR} \
	&& cmake -B BUILD \
	&& cmake --build BUILD ${PARALLELMFLAGS} \
	&& cmake --install BUILD \
	&& cd \
	&& rm -rf ${BUILD_DIR}

ARG USER_ID=1000
RUN set -x \
	&& useradd -u "$USER_ID" -ms /bin/bash user

ENTRYPOINT ["xca"]

