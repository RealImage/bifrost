# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

ARG GO_VERSION="1.21"
ARG NODE_VERSION="20.7.0"

FROM docker.io/library/node:${NODE_VERSION} as node
WORKDIR /src
COPY web .
RUN npm ci \
  && env NODE_ENV=production npm run build

FROM docker.io/library/golang:${GO_VERSION} as builder
WORKDIR /src
COPY . .
COPY --from=node /src/static/js/index.js /src/web/static/js/index.js
RUN mkdir /build \
  && env CGO_ENABLED=0 go build -o /build ./...

FROM gcr.io/distroless/base-debian11
COPY --from=builder /build/* /
ENTRYPOINT [ "/bf" ]
