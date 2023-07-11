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

RUN go build "${build_opts}" -o /release/transport-setup ./cmd/transport-setup && \
    mv ./docker/config/transport-setup.json /release/transport-setup.json

FROM alpine as prod

WORKDIR /release
COPY --from=builder /release/transport-setup /release/transport-setup
COPY --from=builder /release/transport-setup.json /release/transport-setup.json
ENTRYPOINT ["/release/transport-setup"]

FROM prod as test

# OS image
FROM alpine as e2e
WORKDIR /release

COPY ./docker/common/install-prequisites.sh /release/install-prequisites.sh
RUN sh -c /release/install-prequisites.sh cert-only \
    && rm -rf /release/install-prequisites.sh

COPY --from=builder /release/transport-setup /release/transport-setup
COPY --from=builder /release/transport-setup.json /release/transport-setup.json
ENTRYPOINT ["/release/transport-setup"]

FROM e2e as integration

FROM ${image_tag}
