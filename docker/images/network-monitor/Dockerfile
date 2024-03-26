ARG image_tag
ARG base_image

FROM ${base_image} as builder

ARG build_opts

COPY . /skywire-services
WORKDIR /skywire-services

RUN go build "${build_opts}" -o /release/network-monitor ./cmd/network-monitor

FROM alpine as prod

WORKDIR /release
COPY --from=builder /release/network-monitor /release/network-monitor
ENTRYPOINT ["/release/network-monitor"]

FROM prod as test

# OS image
FROM alpine as e2e
WORKDIR /release

COPY ./docker/common/install-prequisites.sh /release/install-prequisites.sh
RUN sh -c /release/install-prequisites.sh cert-only \
    && rm -rf /release/install-prequisites.sh

COPY --from=builder /release/network-monitor /release/network-monitor
ENTRYPOINT ["/release/network-monitor"]

FROM e2e as integration

FROM ${image_tag}
