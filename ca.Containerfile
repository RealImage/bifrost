# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# vim:set ft=Dockerfile:
ARG GO_VERSION="1.21"
ARG NODE_VERSION="20.7.0"

FROM docker.io/library/node:${NODE_VERSION} as node
WORKDIR /src
COPY web .
RUN npm ci \
  && env NODE_ENV=production npm run build

FROM docker.io/library/golang:${GO_VERSION} as go
WORKDIR /src
COPY . .
COPY --from=node /src/static/js/index.js /src/web/static/js/index.js
RUN mkdir /build \
  && env CGO_ENABLED=0 go build -o /build ./cmd/issuer

FROM gcr.io/distroless/base-debian11
# uses lambda-web-adapter to run our standard HTTP app in a lambda
# https://github.com/awslabs/aws-lambda-web-adapter
# for configuration see https://github.com/awslabs/aws-lambda-web-adapter#configurations
ARG AWS_LWA_VERSION=0.7.1
COPY --from=public.ecr.aws/awsguru/aws-lambda-adapter:$AWS_LWA_VERSION \
  /lambda-adapter /opt/extensions/lambda-adapter
COPY --from=go /build/issuer /
ENV PORT=8888
ENV AWS_LWA_READINESS_CHECK_PATH="/metrics"
ENTRYPOINT [ "/issuer" ]
