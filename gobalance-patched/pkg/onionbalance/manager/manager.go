package manager

import (
	"github.com/urfave/cli/v2"
	"gobalance/pkg/onionbalance/onionbalance"
	"gobalance/pkg/onionbalance/param"
	"time"
)

// Main This is the entry point of v3 functionality.
// Initialize onionbalance, schedule future jobs and let the scheduler do its thing.
func Main(c *cli.Context) {
	config := c.String("config")
	ip := c.String("ip")
	port := c.Int("port")
	quick := c.Bool("quick")
	torPassword := c.String("torPassword")
	myOnionbalance := onionbalance.NewOnionbalance()
	if err := myOnionbalance.InitSubsystems(onionbalance.InitSubsystemsParams{
		ConfigPath:  config,
		IP:          ip,
		Port:        port,
		TorPassword: torPassword,
	}); err != nil {
		panic(err)
	}
	initScheduler(quick, myOnionbalance)
}

func initScheduler(quick bool, myOnionbalance *onionbalance.Onionbalance) {
	if myOnionbalance.IsTestnet() {
	} else {
		go func() {
			for {
				time.Sleep(param.FetchDescriptorFrequency * time.Second)
				myOnionbalance.FetchInstanceDescriptors()
			}
		}()
		go func() {
			for {
				time.Sleep(param.PublishDescriptorCheckFrequency * time.Second)
				myOnionbalance.PublishAllDescriptors()
			}
		}()
		// Quick is a hack to quickly deploy a new descriptor without having to wait
		if quick {
			myOnionbalance.FetchInstanceDescriptors()
			myOnionbalance.PublishAllDescriptors()
			time.Sleep(5 * time.Second)
			myOnionbalance.PublishAllDescriptors()
		} else {
			time.Sleep(param.InitialCallbackDelay * time.Second)
			myOnionbalance.FetchInstanceDescriptors()
			myOnionbalance.PublishAllDescriptors()
		}
	}
}
