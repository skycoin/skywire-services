ARG image_tag=e2e

ARG base=alpine
FROM golang:1.21-alpine as builder

ARG BUILDINFO_LDFLAGS
ARG CGO_ENABLED=0
ENV CGO_ENABLED=${CGO_ENABLED} \
    GOOS=linux  \
    GO111MODULE=on

WORKDIR /

RUN apk add --no-cache make git build-base && \
    git clone -b develop https://github.com/skycoin/skywire && \
    cd skywire && \
    sh -c /skywire/docker/images/visor/install-preq.sh && \
    make build-race

## Resulting image
FROM ${base} as visor-runner

COPY --from=builder /skywire/docker/images/visor/install-preq.sh /release/install-preq.sh
COPY --from=builder /release /release

RUN sh -c /release/install-preq.sh \
    && rm -rf /release/install-preq.sh \
    && mkdir -p /opt/skywire &&\
    apk add curl 

STOPSIGNAL SIGINT

ENTRYPOINT [ "/release/skywire" ]

# default target
FROM visor-runner as prod

FROM visor-runner as test

FROM visor-runner as e2e

FROM ${image_tag}
