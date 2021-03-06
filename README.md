# libbpf

## KubeArmor bpf library

One will only be able to `go get` and to use this go module (library) setting the `CGO_LDFLAGS` environment variable, since this is based on the aqua security [libbpfgo](https://github.com/aquasecurity/libbpfgo) that is a `cgo` wrapper of the C [libbpf](https://github.com/libbpf/libbpf).

*So be aware that using this library in your go code turns it into cgo code.*

---

## General Dependencies

### Ubuntu

`linux-tools-generic`

`libelf-dev`

`zlib1g-dev`

`clang`

---

## Using this library

One way is to use the shared library `libbpf.so` if it is already installed.

`❯ CGO_LDFLAGS="/usr/lib/libbpf.so" go get github.com/kubearmor/libbpf`

However, currently, the most common is to use the `libbpf.a` (static version). To do so, follow the steps below.

- Clone this repository.

  `❯ git clone github.com/kubearmor/libbpf`

- Inside the repository folder, run make to download the C libbpf code and compile it.

  `❯ make`

  This will generate the static `libbpf.a` file and the `vmlinux.h` and `bpf/*.h` headers inside `./include`.

- Now one is able to make correct use of this library. Be sure to use absolute paths.

  `❯ CGO_LDFLAGS="/path_to_this_repo/include/libbpf.a" CGO_CFLAGS="-I /path_to_this_repo/include" go get github.com/kubearmor/libbpf`

The same environment variable need to be set when building the final application that uses this library.

`❯ CGO_LDFLAGS="/path_to_this_repo/include/libbpf.a" CGO_CFLAGS="-I /path_to_this_repo/include" go build`

### Testing it

The use cases inside [tests](tests/) can be tested using make.

`❯ make run-tests`

---

### KABPFMapElement interface

To satisfy `KABPFMapElement` interface, it's necessary to implement the following methods for an XXMapElem.

```go
func (pme *XXMapElem) KeyPointer() unsafe.Pointer {
	...
}

func (pme *XXMapElem) ValuePointer() unsafe.Pointer {
	...
}

func (pme *XXMapElem) SetFoundValue(value []byte) {
	...
}

func (pme *XXMapElem) MapName() string {
	return "map_name"
}
```

Examples can also be found in [tests](tests/).
