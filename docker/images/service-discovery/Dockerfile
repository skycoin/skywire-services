ARG image_tag
ARG base_image

FROM ${base_image} as service-discovery-build

ARG build_opts
RUN apk --no-cache add bash curl

ARG CGO_ENABLED=0
ENV CGO_ENABLED=${CGO_ENABLED} \
    GOOS=linux  \
    GOARCH=amd64 \
    GO111MODULE=on

COPY /docker/common/install-prequisites.sh /install-prequisites.sh
COPY /tmp/skycoin-service-discovery /skycoin-service-discovery

WORKDIR /skycoin-service-discovery

RUN go build "${build_opts}" -o /release/service-discovery ./cmd/service-discovery


FROM alpine as prod

COPY --from=service-discovery-build /install-prequisites.sh /release/install-prequisites.sh
RUN sh -c /release/install-prequisites.sh cert-only \
    && rm -rf /release/install-prequisites.sh

COPY --from=service-discovery-build /release/* /release/
WORKDIR /release
ENTRYPOINT [ "/release/service-discovery" ]

FROM prod as test

FROM alpine as e2e

COPY --from=service-discovery-build /install-prequisites.sh /release/install-prequisites.sh
RUN sh -c /release/install-prequisites.sh cert-only \
    && rm -rf /release/install-prequisites.sh

COPY --from=service-discovery-build /release /release
WORKDIR /release
ENTRYPOINT [ "/release/service-discovery" ]

FROM e2e as integration

FROM ${image_tag}
