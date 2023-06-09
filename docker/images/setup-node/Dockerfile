ARG image_tag
ARG base_image

FROM ${base_image} as builder

ARG build_opts

COPY . /skywire-services
WORKDIR /skywire-services

RUN go build "${build_opts}" -o /release/setup-node ./cmd/setup-node && \
    mv ./docker/config/setup-node.json /release/setup-node.json

FROM alpine as prod

WORKDIR /release
COPY --from=builder /release/setup-node /release/setup-node
COPY --from=builder /release/setup-node.json /release/setup-node.json
ENTRYPOINT ["/release/setup-node"]

FROM prod as test

# OS image
FROM alpine as e2e
WORKDIR /release

COPY ./docker/common/install-prequisites.sh /release/install-prequisites.sh
RUN sh -c /release/install-prequisites.sh cert-only \
    && rm -rf /release/install-prequisites.sh

COPY --from=builder /release/setup-node /release/setup-node
COPY --from=builder /release/setup-node.json /release/setup-node.json
ENTRYPOINT ["/release/setup-node"]

FROM e2e as integration

FROM ${image_tag}
