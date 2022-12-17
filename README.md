# nft

使用 [netfilter][1] 实现的进程级别代理服务，部分代码参考了 [netch][2]

> 后续有打算用 netfilter 的开源替代品 [Divert][3] 重新实现，但是两者的 api 完全不同，暂时没时间搞，所以先将就用这个了

# 用途

我是用来当网游加速器，理论上也可以用来代理其它程序，支持同时代理 tcp+udp

为什么不直接用 netch 呢
因为 netch 只有 socks5 协议支持 udp ，然后各种提供该协议的代理软件的 socks5 实现或多或少有点不稳定 ~~(说的就是你 v2ray)~~
就想到其实可以直接用 [gvisor][5] 来直接怼到 [wg-go][7] 里面 ~~，没有中间商赚差价~~

# 编译

在 [这里][4] netfilter 的 sdk 和驱动
然后将对应架构的头文件放到 `cgo/include` ，将对应的 `nftapi.dll` 放到 `cgo/include`
然后编译：

```bash
go build -o nft.exe
```

> 注意，该项目依赖 cgo ，因此需要 `CGO_ENABLE=1` ，该选项默认启用，但是如果你之前改成了禁用，就需要手动启用才能正常编译
> 因为启用 cgo 会链接 libc ，导致没法一处编译多处运行，所以我一般都禁用了的

# 使用

首次启动应该是需要管理员权限来自动安装驱动，后续就可以直接以普通用户权限启动
启动时需要保证 `netfilter2.sys` `nfapi.dll` 这两个文件与编译出来的程序在同一目录

参数如下：

- `f`: filter process name or directory
  - 如果是指定的目录，会自动找到该目录下所有 `.exe` 文件并加到过滤规则里
  - 如果是进程名，则会直接使用该名字。指定进程名的情况下可以指定多次
- `-c`: config file
  - 标准的 [wireguard][6] 的配置文件，需要以下字段：
    - Peer
      - PublicKey
      - Endpoint
      - MTU (optional)
    - Interface
      - PrivateKey
      - PersistentKeepalive (optional)

例如代理 apex 的主进程

```shell
# with log
.\nft.exe -f r5apex.exe -c .\nft.conf
# without log
.\nft.exe -f r5apex.exe -c .\nft.conf >nul 2>nul
```

# 链接

- [netfilter][1]
- [netch][2]
- [Divert][3]
- [netfilter sdk download][4]
- [gvisor][5]
- [wireguard][6]
- [wireguard-go][7]

[1]: https://netfiltersdk.com/
[2]: https://github.com/netchx/netch
[3]: https://github.com/basil00/Divert
[4]: https://netfiltersdk.com/download.html
[5]: https://github.com/google/gvisor
[6]: https://www.wireguard.com/
[7]: https://github.com/WireGuard/wireguard-go
