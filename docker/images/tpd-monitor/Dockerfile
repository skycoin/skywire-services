ARG image_tag
ARG base_image

FROM ${base_image} as builder

ARG build_opts
ARG go111module
ARG goos
ARG goarch
ENV GO111MODULE=$go111module \
    GOOS=$goos \
    GOARCH=$goarch

COPY . /skywire-services
WORKDIR /skywire-services

RUN go build "${build_opts}" -o /release/tpd-monitor ./cmd/tpd-monitor && \
    mv /skywire-services/docker/config/tpd-monitor.json /release/tpd-monitor.json

FROM alpine as prod
COPY --from=builder /release/tpd-monitor /release/tpd-monitor
COPY --from=builder /release/tpd-monitor.json /release/tpd-monitor.json
ENTRYPOINT ["/release/tpd-monitor"]

FROM prod as test

# OS image
FROM alpine as e2e
WORKDIR /release

COPY ./docker/common/install-prequisites.sh /release/install-prequisites.sh
RUN sh -c /release/install-prequisites.sh cert-only \
    && rm -rf /release/install-prequisites.sh

COPY --from=builder /release/tpd-monitor /release/tpd-monitor
COPY --from=builder /release/tpd-monitor.json /release/tpd-monitor.json
ENTRYPOINT ["/release/tpd-monitor"]

FROM e2e as integration

FROM ${image_tag}
