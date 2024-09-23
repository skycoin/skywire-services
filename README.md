
# Skywire Services

`skywire-services` contains services that are required for `skywire-visor` to run. These services are

- Transport Discovery (TPD)
- Dmsg Discovery (MD)
- Dmsg Server (MS)
- Route Finder (RF)
- Setup Node (SN)
- Service Discovery (SD)
- Address Resolver (AR)
- Uptime Tracker (UT)

## Running the services locally

Run `make build` to build all the services and `make install` to install them into go binaries folder.

Refer to the [`cmd`](cmd) subdirectories for setting up each individual service locally.

### DB Setup
Some of our services needs database for running that we use postgresql here as default database. For setting it up, you just need run pg (by docker or install binary or etc.), make a database with UTF-8 character-set, and pass two credential as flag and save three of them as env variable before running services.

**List of services needs DB**:
- `route-finder`
- `transport-discovery`
- `service-discovery`

So for example if you want run a service, you should pass `--pg-host` and `--pg-port` as flag on running its binary, and also save `PG_USER`, `PG_PASSWORD` and `PG_DATABASE` as env variable.
```
export PG_USER=username
export PG_PASSWORD=pass
export PG_DATABASE=sampledb
```
and run service by

```
./route-finder --pg-host localhost --pg-port 5432
```

All tables created automatically.

## Deployments

We run two service deployments - production and test.

Upon a push to `master` new code is deployed to prod on skywire.skycoin.com subomains

Pushing to `develop` deploys changes to test on skywire.dev subdomains.

Logs can be retrieved through `kubectl` or grafana.skycoin.com.

Check the [docs](docs/Deployments.md) for more documentation on the deployments. Check [Skywire Devops](https://github.com/skycoin/skywire-devops) for more in depth info on our deployment setup.

## Documentation

- [Interactive Test Environment](docs/InteractiveEnvironments.md)
- [Docker Test Environment](docs/DockerEnvironment.md)
- [Load Testing](docs/LoadTesting.md)
- [Packages](docs/Packages.md)

## API Documentation

- [Address Resolver](cmd/address-resolver/README.md)
- [Config Bootstrapper](cmd/config-bootstrapper/README.md)
- [Liveness Checker](cmd/liveness-checker/README.md)
- [Network Monitor](cmd/network-monitor/README.md)
- [Public Visor Monitor](cmd/public-visor-monitor/README.md)
- [Route Finder](cmd/route-finder/README.md)
- [Transport Discovery](cmd/transport-discovery/README.md)
- [Vpn Monitor](cmd/vpn-monitor/README.md)
- [Dmsg Discovery](https://github.com/skycoin/dmsg/blob/develop/cmd/dmsg-discovery/README.md)
- [Dmsg Server](https://github.com/skycoin/dmsg/blob/develop/cmd/dmsg-server/README.md)
- [Service Discovery](https://github.com/skycoin/skycoin-service-discovery/blob/master/README.md#http-api)
- [Uptime Tracker](cmd/uptime-tracker/README.md)

## Dependency Graph

made with [goda](https://github.com/loov/goda)

```
goda graph github.com/skycoin/skywire-services/... | dot -Tsvg -o docs/skywire-services-goda-graph.svg
```

![Dependency Graph](docs/skywire-services-goda-graph.svg "github.com/skycoin/skywire-services Dependency Graph")
