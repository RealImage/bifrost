ARG go_version="1.19"

FROM docker.io/library/golang:${go_version}-alpine as builder
WORKDIR /src
COPY . .
RUN go test ./... -race -cover
RUN env CGO_ENABLED=0 go build ./cmd/issuer

FROM gcr.io/distroless/static as bifrost
# uses lambda-web-adapter to run our standard HTTP app in a lambda
# https://github.com/awslabs/aws-lambda-web-adapter
# for configuration see https://github.com/awslabs/aws-lambda-web-adapter#configurations
ENV PORT=8080
ENV READINESS_CHECK_PATH="/health"
ENV REMOVE_BASE_PATH=""
COPY --from=public.ecr.aws/awsguru/aws-lambda-adapter:0.3.3 /lambda-adapter /opt/extensions/lambda-adapter
COPY --from=builder /src/issuer /
ENTRYPOINT ["/issuer"]
