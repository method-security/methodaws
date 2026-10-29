package main

import (
	"os"

	"github.com/Method-Security/methodaws/cmd"
)

var Version = "none"

func main() {
	methodaws := cmd.NewMethodAws(Version)
	methodaws.InitRootCommand()

	methodaws.InitAPIGatewayCommand()
	methodaws.InitEc2Command()
	methodaws.InitEksCommand()
	methodaws.InitIamCommand()
	methodaws.InitLambdaCommand()
	methodaws.InitLoadBalancerCommand()
	methodaws.InitRdsCommand()
	methodaws.InitRoute53Command()
	methodaws.InitS3Command()
	methodaws.InitSecurityGroupCommand()
	methodaws.InitStsCommand()
	methodaws.InitVPCCommand()
	methodaws.InitWAFCommand()
	methodaws.InitCloudFrontCommand()

	os.Exit(methodaws.Execute())
}
