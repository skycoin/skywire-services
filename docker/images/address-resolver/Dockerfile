ARG base_image
ARG image_tag

FROM ${base_image} as builder

ARG build_opts
ARG docker_opts

COPY . /skywire-services
WORKDIR /skywire-services

RUN "${docker_opts}" go build "${build_opts}" -o /release/address-resolver \
    ./cmd/address-resolver


FROM alpine as prod
COPY --from=builder /release/address-resolver /release/address-resolver
ENTRYPOINT ["/release/address-resolver"]

FROM prod as test

# OS image
FROM alpine as e2e

COPY ./docker/common/install-prequisites.sh /release/install-prequisites.sh
RUN sh -c /release/install-prequisites.sh cert-only \
    && rm -rf /release/install-prequisites.sh

COPY --from=builder /release/address-resolver /release/address-resolver
ENTRYPOINT ["/release/address-resolver"]

FROM e2e as integration

FROM ${image_tag}
