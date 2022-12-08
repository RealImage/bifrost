ARG GO_VERSION="1.19"

FROM docker.io/library/golang:${GO_VERSION}-alpine as builder
ARG ZIG_VERSION="0.10.0"
RUN apk add --quiet --no-cache --update \
  build-base git
RUN wget -qO- https://ziglang.org/download/${ZIG_VERSION}/zig-linux-x86_64-${ZIG_VERSION}.tar.xz \
  | unxz | tar x -C /usr/local/bin --strip-components 1 \
  zig-linux-x86_64-${ZIG_VERSION}/zig \
  zig-linux-x86_64-${ZIG_VERSION}/lib
WORKDIR /src
COPY . .
ENV GOPRIVATE="github.com/RealImage/*"
RUN mkdir /build
RUN env CGO_ENABLED=1 \
  CC="zig cc -target x86_64-linux-musl" \
  CXX="zig c++ -target x86_64-linux-musl" \
  go build -o /build ./...

FROM gcr.io/distroless/static as bouncer
COPY --from=builder /build/bouncer /
ENV PORT=8080
ENTRYPOINT ["/bouncer"]

FROM gcr.io/distroless/static as issuer
# uses lambda-web-adapter to run our standard HTTP app in a lambda
# https://github.com/awslabs/aws-lambda-web-adapter
# for configuration see https://github.com/awslabs/aws-lambda-web-adapter#configurations
COPY --from=public.ecr.aws/awsguru/aws-lambda-adapter:0.3.3 /lambda-adapter /opt/extensions/lambda-adapter
COPY --from=builder /build/issuer /
ENV PORT=8080
ENV READINESS_CHECK_PATH="/metrics"
ENV REMOVE_BASE_PATH=""
ENTRYPOINT ["/issuer"]
