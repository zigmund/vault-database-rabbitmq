package main

import (
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/database/dbplugin/v5"
	log "github.com/sirupsen/logrus"
	"github.com/zigmund/vault-database-rabbitmq/rabbitmq"
	"os"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	if err := flags.Parse(os.Args[1:]); err != nil {
		log.WithError(err).Fatal("failed to parse args")
	}

	dbplugin.ServeMultiplex(rabbitmq.New)
}
