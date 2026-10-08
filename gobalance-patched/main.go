package main

import (
	"crypto/ed25519"
	_ "crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v2"
	"gobalance/pkg/brand"
	"gobalance/pkg/onionbalance/config"
	"gobalance/pkg/onionbalance/manager"
	"gobalance/pkg/onionbalance/utils"
	"gobalance/pkg/stem/descriptor"
	_ "golang.org/x/crypto/sha3"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strings"
)

// https://onionbalance.readthedocs.io
// https://github.com/torproject/torspec/blob/main/control-spec.txt
// https://github.com/torproject/torspec/blob/main/rend-spec-v3.txt

var appVersion = "0.0.0"

func main() {
	logrus.SetLevel(logrus.DebugLevel)

	customFormatter := new(logrus.TextFormatter)
	customFormatter.TimestampFormat = "2006-01-02 15:04:05"
	logrus.SetFormatter(customFormatter)
	customFormatter.FullTimestamp = true

	app := &cli.App{
		Name:    "gobalance",
		Usage:   "Golang rewrite of onionbalance",
		Authors: []*cli.Author{{Name: "n0tr1v", Email: "n0tr1v@protonmail.com"}},
		Version: appVersion,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "ip",
				Aliases: []string{"i"},
				Usage:   "Tor control IP address",
				Value:   "127.0.0.1",
			},
			&cli.IntFlag{
				Name:    "port",
				Aliases: []string{"p"},
				Usage:   "Tor control port",
				Value:   9051,
			},
			&cli.StringFlag{
				Name:    "torPassword",
				Aliases: []string{"tor-password"},
				Usage:   "Tor control password",
			},
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Usage:   "Config file location",
				Value:   "config.yaml",
			},
			&cli.BoolFlag{
				Name:    "quick",
				Aliases: []string{"q"},
				Usage:   "Quickly deploy a new descriptor (no 5min wait)",
			},
			&cli.StringFlag{
				Name:    "verbosity",
				Aliases: []string{"vv"},
				Usage:   "Minimum verbosity level for logging. Available in ascending order: debug, info, warning, error, critical. The default is info.",
				Value:   "info",
			},
		},
		Action: mainAction,
		Commands: []*cli.Command{
			{
				Name:    "generate-config",
				Aliases: []string{"g"},
				Usage:   "generate a config.yaml file",
				Action:  generateConfigAction,
			},
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		logrus.Fatal(err)
	}
}

func mainAction(c *cli.Context) error {
	level, err := logrus.ParseLevel(c.String("verbosity"))
	if err != nil {
		level = logrus.InfoLevel
	}
	logrus.SetLevel(level)

	logrus.Warningf("Initializing onionbalance (version: %s)...", appVersion)
	manager.Main(c)
	select {}
}

func generateConfigAction(_ *cli.Context) error {
	/*
		Enter path to store generated config
		Number of services (frontends) to create (default: 1):
		Enter path to master service private key (i.e. path to 'hs_ed25519_secret_key') (Leave empty to generate a key)
		Number of instance services to create (default: 2) (min: 1, max: 8)
		Provide a tag name to group these instances [node]

		Wrote master service config file '/Users/n0tr1v/Documents/onionbalance/config/config.yaml'
		Done! Successfully generated Onionbalance config
		Now please edit 'config/config.yaml' with a text editor to add/remove/edit your backend instances
	*/
	configFilePath, err := filepath.Abs("./config.yaml")
	if err != nil {
		logrus.Fatal(err)
	}
	if utils.FileExists(configFilePath) {
		logrus.Fatalf("config file %s already exists", configFilePath)
	}

	masterPublicKey, masterPrivateKey, err := ed25519.GenerateKey(brand.Reader())
	if err != nil {
		logrus.Fatal(err)
	}
	masterPrivateKeyDer, err := x509.MarshalPKCS8PrivateKey(masterPrivateKey)
	if err != nil {
		logrus.Fatal(err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: masterPrivateKeyDer}
	onionAddress := descriptor.AddressFromIdentityKey(masterPublicKey)
	masterKeyFileName := strings.TrimSuffix(onionAddress, ".onion") + ".key"
	masterKeyFile, err := os.Create(masterKeyFileName)
	if err != nil {
		logrus.Fatal(err)
	}
	defer masterKeyFile.Close()
	if err = pem.Encode(masterKeyFile, block); err != nil {
		logrus.Fatal(err)
	}

	configFile, err := os.Create(configFilePath)
	if err != nil {
		logrus.Fatal(err)
	}
	defer configFile.Close()
	data := config.ConfigData{
		Services: []config.ServiceConfig{{
			Key:       masterKeyFileName,
			Instances: []config.InstanceConfig{{Address: "<Enter the instance onion address here>"}},
		}},
	}
	if err := yaml.NewEncoder(configFile).Encode(data); err != nil {
		logrus.Fatal(err)
	}
	return nil
}
