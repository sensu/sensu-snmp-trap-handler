[![Sensu Bonsai Asset](https://img.shields.io/badge/Bonsai-Download%20Me-brightgreen.svg?colorB=89C967&logo=sensu)](https://bonsai.sensu.io/assets/sensu/sensu-snmp-trap-handler)
![Go Test](https://github.com/sensu/sensu-snmp-trap-handler/workflows/Go%20Test/badge.svg)
![goreleaser](https://github.com/sensu/sensu-snmp-trap-handler/workflows/goreleaser/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/sensu/sensu-snmp-trap-handler)](https://goreportcard.com/report/github.com/sensu/sensu-snmp-trap-handler)

# sensu-snmp-trap-handler

## Table of Contents
- [Overview](#overview)
- [Files](#files)
  - [MIBs](#mibs)
- [Usage examples](#usage-examples)
- [Configuration](#configuration)
  - [Asset registration](#asset-registration)
  - [Handler definition](#handler-definition)
  - [Annotations](#annotations)
- [Installation from source](#installation-from-source)
- [Additional notes](#additional-notes)
- [Contributing](#contributing)

## Overview

The sensu-snmp-trap-handler is a [Sensu Handler][2] that sends alerts to an SNMP manager via
SNMP traps.

## Files

### MIBs

The necessary MIB files are in the [mibs directory](https://github.com/sensu/sensu-snmp-trap-handler/tree/master/mibs) and in the release assets.

#### SNMPv1 MIBs

* [RFC-1212-MIB.txt](https://raw.githubusercontent.com/sensu/sensu-snmp-trap-handler/master/mibs/RFC-1212-MIB.txt)
* [RFC-1215-MIB.txt](https://raw.githubusercontent.com/sensu/sensu-snmp-trap-handler/master/mibs/RFC-1215-MIB.txt)
* [SENSU-ENTERPRISE-V1-MIB.txt](https://raw.githubusercontent.com/sensu/sensu-snmp-trap-handler/master/mibs/SENSU-ENTERPRISE-V1-MIB.txt)

#### SNMPv2 MIBs

* [SENSU-ENTERPRISE-ROOT-MIB.txt](https://raw.githubusercontent.com/sensu/sensu-snmp-trap-handler/master/mibs/SENSU-ENTERPRISE-ROOT-MIB.txt)
* [SENSU-ENTERPRISE-NOTIFY-MIB.txt](https://raw.githubusercontent.com/sensu/sensu-snmp-trap-handler/master/mibs/SENSU-ENTERPRISE-NOTIFY-MIB.txt)


## Usage examples

```
Sensu SNMP Trap Handler

Usage:
  sensu-snmp-trap-handler [flags]
  sensu-snmp-trap-handler [command]

Available Commands:
  help        Help about any command
  version     Print the version number of this plugin

Flags:
  -c, --community string          The SNMP Community string to use when sending traps (default "public")
  -h, --help                      help for sensu-snmp-trap-handler
  -H, --host string               The SNMP manager host address (default "127.0.0.1")
  -p, --port int                  The SNMP manager trap port (UDP) (default 162)
  -t, --varbind-trim int          The SNMP trap varbind value trim length in characters (default 100)
  -v, --version string            The SNMP version to use (1,2,2c) (default "2")
  -m, --message-template string   The template for the SNMP message (default "{{.Check.State}} - {{.Entity.Name}}/{{.Check.Name}} : {{.Check.Output}}")


Use "sensu-snmp-trap-handler [command] --help" for more information about a command.
```

## Configuration
### Sensu Go
#### Asset registration

[Sensu Assets][4] are the best way to make use of this plugin. If you're not using an asset, please
consider doing so! If you're using sensuctl 5.13 with Sensu Backend 5.13 or later, you can use the
following command to add the asset:

```
sensuctl asset add sensu/sensu-snmp-trap-handler
```

If you're using an earlier version of sensuctl, you can find the asset on the [Bonsai Asset Index][3].

#### Handler definition

```yml
---
type: Handler
api_version: core/v2
metadata:
  name: sensu-snmp-trap-handler
  namespace: default
spec:
  command: sensu-snmp-trap-handler --host snmp-manager.example.com
  type: pipe
  filters:
  - is_incident
  - not_silenced
  runtime_assets:
  - sensu/sensu-snmp-trap-handler
```

#### Annotations

All arguments for this handler are tunable on a per entity or check basis based on annotations.  The
annotations keyspace for this handler is `sensu.io/plugins/sensu-snmp-trap-handler/config`.

##### Examples

To change the host argument for a particular check, for that checks's metadata add the following:

```yml
type: CheckConfig
api_version: core/v2
metadata:
  annotations:
    sensu.io/plugins/sensu-snmp-trap-handler/config/host: "snmp-manager2.example.com"
[...]
```

## Installation from source

The preferred way of installing and deploying this plugin is to use it as an Asset. If you would
like to compile and install the plugin from source or contribute to it, download the latest version
or create an executable script from this source.

From the local path of the sensu-snmp-trap-handler repository:

```
go build
```

## Additional notes

N/A

## Contributing

For more information about contributing to this plugin, see [Contributing][1].

[1]: https://github.com/sensu/sensu-go/blob/master/CONTRIBUTING.md
[2]: https://docs.sensu.io/sensu-go/latest/reference/handlers/
[3]: https://bonsai.sensu.io/
[4]: https://docs.sensu.io/sensu-go/latest/reference/assets/
