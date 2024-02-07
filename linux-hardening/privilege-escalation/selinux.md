<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS红队专家）</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在HackTricks中看到您的**公司广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或在**Twitter**上关注我 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


# 容器中的SELinux

[来自redhat文档的介绍和示例](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux) 是一个**标签系统**。每个**进程**和每个**文件**系统对象都有一个**标签**。SELinux策略定义了关于系统上的所有其他标签与**进程标签允许执行的操作**的规则。

容器引擎使用单个受限SELinux标签（通常为`container_t`）启动**容器进程**，然后将容器内的容器标记为`container_file_t`。SELinux策略规则基本上表示**`container_t`进程只能读取/写入/执行标记为`container_file_t`的文件**。如果容器进程逃逸容器并尝试写入主机上的内容，Linux内核将拒绝访问，并仅允许容器进程写入标记为`container_file_t`的内容。
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
# SELinux用户

除了常规的Linux用户外，还有SELinux用户。 SELinux用户是SELinux策略的一部分。 每个Linux用户都映射到策略的一部分作为SELinux用户。 这允许Linux用户继承放置在SELinux用户身上的限制、安全规则和机制。
