ARG GO_VERSION="1.19"

FROM docker.io/library/golang:${GO_VERSION}-alpine as builder
RUN apk add --quiet --no-cache --update git
WORKDIR /src
COPY . .
ENV GOPRIVATE="github.com/RealImage/*"
RUN mkdir /build
RUN go build -o /build ./...

FROM gcr.io/distroless/static as bouncer
COPY --from=builder /build/bouncer /
ENV PORT=8080
ENTRYPOINT ["/bouncer"]

FROM gcr.io/distroless/static as issuer
# uses lambda-web-adapter to run our standard HTTP app in a lambda
# https://github.com/awslabs/aws-lambda-web-adapter
# for configuration see https://github.com/awslabs/aws-lambda-web-adapter#configurations
ARG AWS_LAMBDA_WEB_ADAPTER_VERSION=0.6.0
COPY --from=public.ecr.aws/awsguru/aws-lambda-adapter:$AWS_LAMBDA_WEB_ADAPTER_VERSION /lambda-adapter /opt/extensions/lambda-adapter
COPY --from=builder /build/issuer /
ENV PORT=8080
ENV READINESS_CHECK_PATH="/metrics"
ENV REMOVE_BASE_PATH=""
ENTRYPOINT ["/issuer"]
