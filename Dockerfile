ARG REGISTRY_PREFIX=''
ARG CODENAME=noble

FROM ${REGISTRY_PREFIX}ubuntu:${CODENAME} as builder

ENV DEBIAN_FRONTEND noninteractive

RUN set -x \
	&& apt update \
	&& apt upgrade -y \
	&& apt install --yes --no-install-recommends \
		build-essential libssl-dev pkg-config ninja-build \
		python3-sphinxcontrib.qthelp git cmake locales \
		qt6-base-dev qt6-tools-dev

ARG BUILD_DIR=/tmp/build

COPY . ${BUILD_DIR}
RUN set -x \
	&& cd ${BUILD_DIR} \
	&& cmake -B BUILD -G Ninja \
	&& cmake --build BUILD \
	&& cmake --install BUILD \
	&& cd \
	&& mv ${BUILD_DIR}/misc/docker_start.sh / \
	&& rm -rf ${BUILD_DIR}

RUN mkdir -p /home/user && chmod 0777 /home/user

ENTRYPOINT ["/docker_start.sh"]

