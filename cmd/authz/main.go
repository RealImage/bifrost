package main

import (
	"github.com/RealImage/bifrost/internal/handlers"
	"github.com/aws/aws-lambda-go/lambda"
)

func main() {
	lambda.Start(handlers.BifrostAuthorizer)
}
