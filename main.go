package main

import (
	"fmt"
	"hackathon2/pkg/network"
	"hackathon2/pkg/robots"
)

func main() {
	fmt.Println("Hello World!")
	network.StartServer()  // SSE Server Starten
	robots.RobotsAnalyse() // Robots Analyse Starten
}
