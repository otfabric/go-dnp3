// The conformance run is a module of its own, so that neither the test
// outstation nor the GPL-3.0 dnp3c plugin next to it is part of go-dnp3's
// module.
module github.com/otfabric/go-dnp3/conformance

go 1.23

require github.com/otfabric/go-dnp3 v1.3.2

replace github.com/otfabric/go-dnp3 => ../
