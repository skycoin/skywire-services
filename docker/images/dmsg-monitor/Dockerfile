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

RUN go build "${build_opts}" -o /release/dmsg-monitor ./cmd/dmsg-monitor

FROM alpine as prod

WORKDIR /release
COPY --from=builder /release/dmsg-monitor /release/dmsg-monitor
ENTRYPOINT ["/release/dmsg-monitor"]

FROM prod as test

# OS image
FROM alpine as e2e
WORKDIR /release

COPY ./docker/common/install-prequisites.sh /release/install-prequisites.sh
RUN sh -c /release/install-prequisites.sh cert-only \
    && rm -rf /release/install-prequisites.sh

COPY --from=builder /release/dmsg-monitor /release/dmsg-monitor
ENTRYPOINT ["/release/dmsg-monitor"]

FROM e2e as integration

FROM ${image_tag}
