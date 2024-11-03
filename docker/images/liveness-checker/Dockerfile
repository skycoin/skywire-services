ARG image_tag
ARG base_image

FROM ${base_image} AS builder

ARG build_opts

COPY . /skywire-services
WORKDIR /skywire-services

RUN go build "${build_opts}" -o /release/liveness-checker ./cmd/liveness-checker && \
    go build "${build_opts}" -o /release/vpn-client ./cmd/vpn-lite-client && \
    mv /skywire-services/docker/config/liveness-checker.json /release/liveness-checker.json

FROM alpine AS prod
COPY --from=builder /release/vpn-client /apps/vpn-client
COPY --from=builder /release/liveness-checker /release/liveness-checker
COPY --from=builder /release/liveness-checker.json /release/liveness-checker.json
ENTRYPOINT ["/release/liveness-checker"]

FROM prod AS test

# OS image
FROM alpine AS e2e
WORKDIR /release

COPY ./docker/common/install-prequisites.sh /release/install-prequisites.sh
RUN sh -c /release/install-prequisites.sh cert-only \
    && rm -rf /release/install-prequisites.sh

COPY --from=builder /release/vpn-client /release/vpn-client
COPY --from=builder /release/liveness-checker /release/liveness-checker
COPY --from=builder /release/liveness-checker.json /release/liveness-checker.json
ENTRYPOINT ["/release/liveness-checker"]

FROM e2e AS integration

FROM ${image_tag}
