# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

ARG GO_VERSION="1.21" NODE_VERSION="20.9.0"
ARG TARGETOS TARGETARCH
ARG DISTROLESS_VERSION="base-debian12:latest-$TARGETARCH"

FROM --platform=$BUILDPLATFORM docker.io/library/node:$NODE_VERSION as node
WORKDIR /src
COPY web/package.json web/package-lock.json ./
RUN --mount=type=cache,target=node_modules \
  npm ci
COPY web .
RUN --mount=type=cache,target=node_modules \
  npm run build

FROM --platform=$BUILDPLATFORM docker.io/library/golang:$GO_VERSION as go
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod/ \
  go mod download -x
COPY . .
COPY --from=node /src/static/ /src/web/static/
RUN --mount=type=cache,target=/go/pkg/mod/ \
  mkdir -p bin \
  && env CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o bin ./...


FROM gcr.io/distroless/$DISTROLESS_VERSION as authz
COPY --from=go /src/bin/bouncer /
ENTRYPOINT [ "/bouncer" ]

FROM gcr.io/distroless/$DISTROLESS_VERSION as ca
# uses lambda-web-adapter to run our standard HTTP app in a lambda
# https://github.com/awslabs/aws-lambda-web-adapter
# for configuration see https://github.com/awslabs/aws-lambda-web-adapter#configurations
ARG AWS_LWA_VERSION=0.7.1
COPY --from=public.ecr.aws/awsguru/aws-lambda-adapter:$AWS_LWA_VERSION \
  /lambda-adapter /opt/extensions/lambda-adapter
COPY --from=go /src/bin/issuer /
ENV PORT=8888
ENV AWS_LWA_READINESS_CHECK_PATH="/namespace"
ENV AWS_LWA_ENABLE_COMPRESSION="true"
ENTRYPOINT [ "/issuer" ]

FROM gcr.io/distroless/$DISTROLESS_VERSION
COPY --from=go /src/bin/* /
ENTRYPOINT [ "/bf" ]
