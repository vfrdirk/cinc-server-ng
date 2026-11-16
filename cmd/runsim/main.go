// Command runsim simulates a fleet of chef-client runs against a cinc-server-ng
// org, for load testing. Unlike fleetsim, which replays one admin's GET/PUT
// check-ins, every simulated node here is its own API client with its own key,
// so per-request signature verification and ACL checks run as they would for a
// real fleet, and each run makes the same calls a real chef-client run makes:
//
//	GET    /nodes/{name}                      (POST /nodes on the first run)
//	GET    /roles/{role}, /environments/{env}  (run-list expansion)
//	POST   /environments/{env}/cookbook_versions
//	GET    <file URLs>                        (all on the first run, then a few)
//	GET    /data/{bag}/{item}
//	POST   /search/node                       (partial search)
//	PUT    /nodes/{name}
//	POST   /data-collector                    (run_start and run_converge)
//
// Subcommands:
//
//	runsim setup    -base URL -admin pivotal -admin-key admin.pem -out validator.pem
//	runsim register -base URL -validator-key validator.pem -keys DIR -clients N
//	runsim run      -base URL -keys DIR -clients N -out results/
//	runsim sink     -listen :8099
//
// setup creates the validator client runsim registers with. register creates
// the clients (and is itself the registration-storm scenario). run drives the
// fleet and writes per-endpoint latency every -window to results/. sink is a
// throwaway data-collector endpoint that counts and discards run reports.
//
// This is a development tool; it is not built into the cinc-server-ng binary.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "setup":
		err = cmdSetup(os.Args[2:])
	case "register":
		err = cmdRegister(os.Args[2:])
	case "run":
		err = cmdRun(os.Args[2:])
	case "sink":
		err = cmdSink(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "runsim:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: runsim setup|register|run|sink [flags]  (runsim <cmd> -h for flags)")
}
