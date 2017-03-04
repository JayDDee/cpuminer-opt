#
# Dockerfile for cpuminer-opt
# usage: docker build -t cpuminer-opt:latest .
# run: docker run -it --rm cpuminer-opt:latest [ARGS]
# ex: docker run -it --rm cpuminer-opt:latest -a cryptonight -o cryptonight.eu.nicehash.com:3355 -u 1MiningDW2GKzf4VQfmp4q2XoUvR6iy6PD.worker1 -p x -t 3
#

FROM ubuntu:16.04
RUN BUILD_DEPS="build-essential \
    libssl-dev \
	  libgmp-dev \
	  libcurl4-openssl-dev \
	  libjansson-dev \
	  automake" && \

	  apt-get update && \
	  apt-get install -y ${BUILD_DEPS}

COPY . /app/
RUN	cd /app/ && ./build.sh

ENTRYPOINT ["/app/cpuminer"]
CMD ["-h"]
