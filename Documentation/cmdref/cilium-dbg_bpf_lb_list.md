<!-- This file was autogenerated via cilium-dbg cmdref, do not edit manually-->

## cilium-dbg bpf lb list

List load-balancing configuration

```
cilium-dbg bpf lb list [flags]
```

### Options

```
      --backends        List all service backend entries
      --frontends       List all service frontend entries
  -h, --help            help for list
  -o, --output string   json| yaml| jsonpath='{}'
      --revnat          List reverse NAT entries
      --source-ranges   List all source range entries
```

### Options inherited from parent commands

```
      --config string        Config file (default is $HOME/.cilium.yaml)
  -D, --debug                Enable debug messages
  -H, --host string          URI to server-side API
      --log-driver strings   Logging endpoints to use (example: syslog)
      --log-opt map          Log driver options (example: format=json)
```

### SEE ALSO

* [cilium-dbg bpf lb](cilium-dbg_bpf_lb.md)	 - Load-balancing configuration

