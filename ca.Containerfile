# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

ARG GO_VERSION="1.20"

FROM docker.io/library/golang:${GO_VERSION} as builder
WORKDIR /src
COPY . .
RUN mkdir /build
RUN env CGO_ENABLED=0 go build -o /build ./...

FROM gcr.io/distroless/base-debian11
# uses lambda-web-adapter to run our standard HTTP app in a lambda
# https://github.com/awslabs/aws-lambda-web-adapter
# for configuration see https://github.com/awslabs/aws-lambda-web-adapter#configurations
ARG AWS_LAMBDA_WEB_ADAPTER_VERSION=0.7.0
COPY --from=public.ecr.aws/awsguru/aws-lambda-adapter:$AWS_LAMBDA_WEB_ADAPTER_VERSION \
  /lambda-adapter /opt/extensions/lambda-adapter
COPY --from=builder /build/issuer /
ENV PORT=8080
ENV READINESS_CHECK_PATH="/metrics"
ENV REMOVE_BASE_PATH=""
ENTRYPOINT [ "/issuer" ]
