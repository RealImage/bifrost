# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

ARG GO_VERSION="1.20"

FROM docker.io/library/golang:${GO_VERSION} as builder
WORKDIR /src
COPY . .
ENV GOPRIVATE="github.com/RealImage/*"
RUN mkdir /build
RUN go build -o /build ./...

FROM gcr.io/distroless/base-debian11
COPY --from=builder /build/* /
ENTRYPOINT [ "/bf" ]
