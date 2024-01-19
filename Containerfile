ARG GO_VERSION="1.21"
ARG NODE_VERSION="20.9.0"
ARG DISTROLESS_VERSION="base-debian12:latest"

FROM --platform=$BUILDPLATFORM docker.io/library/node:$NODE_VERSION as node
WORKDIR /src
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web .
RUN npm run build

FROM --platform=$BUILDPLATFORM docker.io/library/golang:$GO_VERSION as go
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download -x
COPY . .
COPY --from=node /src/static/ /src/web/static/
RUN mkdir -p bin \
  && env CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build ./cmd/bf

FROM gcr.io/distroless/$DISTROLESS_VERSION
# uses lambda-web-adapter to run our standard HTTP app in a lambda
# https://github.com/awslabs/aws-lambda-web-adapter
# for configuration see https://github.com/awslabs/aws-lambda-web-adapter#configurations
ARG AWS_LWA_VERSION=0.7.1
COPY --from=public.ecr.aws/awsguru/aws-lambda-adapter:$AWS_LWA_VERSION \
  /lambda-adapter /opt/extensions/lambda-adapter
COPY --from=go /src/bf /
ENV PORT=8080
ENV AWS_LWA_READINESS_CHECK_PATH="/namespace"
ENV AWS_LWA_ENABLE_COMPRESSION="true"
ENTRYPOINT ["/bf"]
CMD ["ca"]
