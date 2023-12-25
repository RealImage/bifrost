package main

import (
	"log/slog"

	"github.com/RealImage/bifrost/internal/config"
	"github.com/RealImage/bifrost/internal/middleware"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/kelseyhightower/envconfig"
)

func main() {
	envconfig.MustProcess(config.EnvPrefix, &config.Bouncer)

	slog.Info("build info",
		slog.String("rev", config.BuildRevision),
		slog.Time("timestamp", config.BuildTime),
	)

	lambda.Start(middleware.CertAuthorizer(config.Bouncer.Namespace))
}
