ARG image_tag
ARG base_image

FROM ${base_image} as uptime-tracker-build

ARG build_opts
RUN apk --no-cache add bash curl

ARG CGO_ENABLED=0
ENV CGO_ENABLED=${CGO_ENABLED} \
    GOOS=linux  \
    GOARCH=amd64 \
    GO111MODULE=on

COPY /docker/common/install-prequisites.sh /install-prequisites.sh
COPY /tmp/skywire-ut /skywire-ut

WORKDIR /skywire-ut

RUN go build "${build_opts}" -o /release/uptime-tracker ./cmd/uptime-tracker


FROM alpine as prod

COPY --from=uptime-tracker-build /install-prequisites.sh /release/install-prequisites.sh
RUN sh -c /release/install-prequisites.sh cert-only \
    && rm -rf /release/install-prequisites.sh

COPY --from=uptime-tracker-build /release/* /release/
WORKDIR /release
ENTRYPOINT [ "/release/uptime-tracker" ]

FROM prod as test

FROM alpine as e2e

COPY --from=uptime-tracker-build /install-prequisites.sh /release/install-prequisites.sh
RUN sh -c /release/install-prequisites.sh cert-only \
    && rm -rf /release/install-prequisites.sh

COPY --from=uptime-tracker-build /release /release
WORKDIR /release
ENTRYPOINT [ "/release/uptime-tracker" ]

FROM e2e as integration

FROM ${image_tag}
