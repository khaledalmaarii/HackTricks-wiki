# macOS MIG - Mach接口生成器

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)或**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>

MIG被创建用于**简化Mach IPC代码生成的过程**。它基本上**根据给定的定义生成所需的代码**，以便服务器和客户端进行通信。即使生成的代码很丑陋，开发人员只需要导入它，他的代码将比以前简单得多。

### 示例

创建一个定义文件，这里是一个非常简单的函数：

{% code title="myipc.defs" %}
```cpp
subsystem myipc 500; // Arbitrary name and id

userprefix USERPREF;        // Prefix for created functions in the client
serverprefix SERVERPREF;    // Prefix for created functions in the server

#include <mach/mach_types.defs>
#include <mach/std_types.defs>

simpleroutine Subtract(
server_port :  mach_port_t;
n1          :  uint32_t;
n2          :  uint32_t);
```
{% endcode %}

现在使用mig生成服务器和客户端代码，它们将能够相互通信以调用Subtract函数：
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
当前目录将创建几个新文件。

在文件**`myipcServer.c`**和**`myipcServer.h`**中，您可以找到**`SERVERPREFmyipc_subsystem`**结构的声明和定义，该结构基本上定义了根据接收到的消息ID调用的函数（我们指定了起始编号为500）：

{% tabs %}
{% tab title="myipcServer.c" %}
```c
/* Description of this subsystem, for use in direct RPC */
const struct SERVERPREFmyipc_subsystem SERVERPREFmyipc_subsystem = {
myipc_server_routine,
500, // start ID
501, // end ID
(mach_msg_size_t)sizeof(union __ReplyUnion__SERVERPREFmyipc_subsystem),
(vm_address_t)0,
{
{ (mig_impl_routine_t) 0,
// Function to call
(mig_stub_routine_t) _XSubtract, 3, 0, (routine_arg_descriptor_t)0, (mach_msg_size_t)sizeof(__Reply__Subtract_t)},
}
};
```
{% tab title="myipcServer.h" %}

```c
#ifndef myipcServer_h
#define myipcServer_h

#include <stdio.h>
#include <stdlib.h>
#include <mach/mach.h>
#include <mach/mach_error.h>
#include <servers/bootstrap.h>
#include <mach/mach_traps.h>
#include <mach/mach_types.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/mach_interface.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher.h>
#include <mach/mach_time.h>
#include <mach/mach_host.h>
#include <mach/mach_host_priv.h>
#include <mach/mach_host_special_ports.h>
#include <mach/mach_vm.h>
#include <mach/mach_voucher_types.h>
#include <mach/mach_voucher
```c
/* Description of this subsystem, for use in direct RPC */
extern const struct SERVERPREFmyipc_subsystem {
mig_server_routine_t	server;	/* Server routine */
mach_msg_id_t	start;	/* Min routine number */
mach_msg_id_t	end;	/* Max routine number + 1 */
unsigned int	maxsize;	/* Max msg size */
vm_address_t	reserved;	/* Reserved */
struct routine_descriptor	/* Array of routine descriptors */
routine[1];
} SERVERPREFmyipc_subsystem;
```
{% endtab %}
{% endtabs %}

根据前面的结构，函数**`myipc_server_routine`**将获取**消息ID**并返回要调用的适当函数：
```c
mig_external mig_routine_t myipc_server_routine
(mach_msg_header_t *InHeadP)
{
int msgh_id;

msgh_id = InHeadP->msgh_id - 500;

if ((msgh_id > 0) || (msgh_id < 0))
return 0;

return SERVERPREFmyipc_subsystem.routine[msgh_id].stub_routine;
}
```
在这个例子中，我们只在定义中定义了一个函数，但如果我们定义了更多的函数，它们将会在**`SERVERPREFmyipc_subsystem`**的数组中，并且第一个函数将被分配给ID **500**，第二个函数将被分配给ID **501**...

实际上，我们可以在**`myipcServer.h`**的**`subsystem_to_name_map_myipc`**结构中识别出这种关系：
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
最后，使服务器工作的另一个重要函数将是**`myipc_server`**，它是实际上调用与接收到的id相关的函数的函数：

```c
mig_external boolean_t myipc_server
(mach_msg_header_t *InHeadP, mach_msg_header_t *OutHeadP)
{
/*
* typedef struct {
* 	mach_msg_header_t Head;
* 	NDR_record_t NDR;
* 	kern_return_t RetCode;
* } mig_reply_error_t;
*/

mig_routine_t routine;

OutHeadP->msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REPLY(InHeadP->msgh_bits), 0);
OutHeadP->msgh_remote_port = InHeadP->msgh_reply_port;
/* Minimal size: routine() will update it if different */
OutHeadP->msgh_size = (mach_msg_size_t)sizeof(mig_reply_error_t);
OutHeadP->msgh_local_port = MACH_PORT_NULL;
OutHeadP->msgh_id = InHeadP->msgh_id + 100;
OutHeadP->msgh_reserved = 0;

if ((InHeadP->msgh_id > 500) || (InHeadP->msgh_id < 500) ||
	    ((routine = SERVERPREFmyipc_subsystem.routine[InHeadP->msgh_id - 500].stub_routine) == 0)) {
		((mig_reply_error_t *)OutHeadP)->NDR = NDR_record;
((mig_reply_error_t *)OutHeadP)->RetCode = MIG_BAD_ID;
return FALSE;
}
	(*routine) (InHeadP, OutHeadP);
	return TRUE;
}
```

检查以下代码，使用生成的代码创建一个简单的服务器和客户端，其中客户端可以调用服务器的Subtract函数：

{% tabs %}
{% tab title="myipc_server.c" %}
```c
// gcc myipc_server.c myipcServer.c -o myipc_server

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include "myipcServer.h"

kern_return_t SERVERPREFSubtract(mach_port_t server_port, uint32_t n1, uint32_t n2)
{
printf("Received: %d - %d = %d\n", n1, n2, n1 - n2);
return KERN_SUCCESS;
}

int main() {

mach_port_t port;
kern_return_t kr;

// Register the mach service
kr = bootstrap_check_in(bootstrap_port, "xyz.hacktricks.mig", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_check_in() failed with code 0x%x\n", kr);
return 1;
}

// myipc_server is the function that handles incoming messages (check previous exlpanation)
mach_msg_server(myipc_server, sizeof(union __RequestUnion__SERVERPREFmyipc_subsystem), port, MACH_MSG_TIMEOUT_NONE);
}
```
{% tab title="myipc_client.c" %}

```c
#include <stdio.h>
#include <stdlib.h>
#include <servers/bootstrap.h>
#include "myipc.h"

int main(int argc, char *argv[]) {
    mach_port_t bootstrap_port;
    kern_return_t kr;
    myipc_msg_t msg;

    // Get the bootstrap port
    kr = task_get_bootstrap_port(mach_task_self(), &bootstrap_port);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to get bootstrap port: %s\n", mach_error_string(kr));
        exit(1);
    }

    // Look up the server port
    kr = bootstrap_look_up(bootstrap_port, MYIPC_SERVER_NAME, &msg.server_port);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to look up server port: %s\n", mach_error_string(kr));
        exit(1);
    }

    // Set the message type and data
    msg.type = MYIPC_MSG_TYPE;
    msg.data = 42;

    // Send the message
    kr = mach_msg(&msg.header, MACH_SEND_MSG, sizeof(msg), 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to send message: %s\n", mach_error_string(kr));
        exit(1);
    }

    printf("Message sent successfully\n");

    return 0;
}
```

{% endtab %}
```c
// gcc myipc_client.c myipcUser.c -o myipc_client

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <mach/mach.h>
#include <servers/bootstrap.h>
#include "myipcUser.h"

int main() {

// Lookup the receiver port using the bootstrap server.
mach_port_t port;
kern_return_t kr = bootstrap_look_up(bootstrap_port, "xyz.hacktricks.mig", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_look_up() failed with code 0x%x\n", kr);
return 1;
}
printf("Port right name %d\n", port);
USERPREFSubtract(port, 40, 2);
}
```
### 二进制分析

由于许多二进制文件现在使用MIG来公开mach端口，了解如何**识别使用了MIG**以及每个消息ID执行的**MIG函数**是很有趣的。

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/#jtool2)可以解析Mach-O二进制文件中的MIG信息，指示消息ID并标识要执行的函数：
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
先前提到，负责根据接收到的消息ID调用正确函数的函数是`myipc_server`。然而，通常你不会有二进制文件的符号（没有函数名），所以检查反编译后的代码是很有意思的，因为它们总是非常相似（这个函数的代码与暴露的函数无关）：

{% tabs %}
{% tab title="myipc_server反编译 1" %}
<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
var_10 = arg0;
var_18 = arg1;
// 初始指令以找到正确的函数指针
*(int32_t *)var_18 = *(int32_t *)var_10 &#x26; 0x1f;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
if (*(int32_t *)(var_10 + 0x14) &#x3C;= 0x1f4 &#x26;&#x26; *(int32_t *)(var_10 + 0x14) >= 0x1f4) {
rax = *(int32_t *)(var_10 + 0x14);
// 调用sign_extend_64函数，有助于识别该函数
// 这将在rax中存储需要调用的调用的指针
// 检查地址0x100004040的使用（函数地址数组）
// 0x1f4 = 500（起始ID）
<strong>            rax = *(sign_extend_64(rax - 0x1f4) * 0x28 + 0x100004040);
</strong>            var_20 = rax;
// 如果-否，则if返回false，而else调用正确的函数并返回true
<strong>            if (rax == 0x0) {
</strong>                    *(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
else {
// 计算的地址调用具有2个参数的正确函数
<strong>                    (var_20)(var_10, var_18);
</strong>                    var_4 = 0x1;
}
}
else {
*(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
rax = var_4;
return rax;
}
</code></pre>
{% endtab %}

{% tab title="myipc_server反编译 2" %}
这是在不同版本的Hopper free中反编译的相同函数：

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
r31 = r31 - 0x40;
saved_fp = r29;
stack[-8] = r30;
var_10 = arg0;
var_18 = arg1;
// 初始指令以找到正确的函数指针
*(int32_t *)var_18 = *(int32_t *)var_10 &#x26; 0x1f | 0x0;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
r8 = *(int32_t *)(var_10 + 0x14);
r8 = r8 - 0x1f4;
if (r8 > 0x0) {
if (CPU_FLAGS &#x26; G) {
r8 = 0x1;
}
}
if ((r8 &#x26; 0x1) == 0x0) {
r8 = *(int32_t *)(var_10 + 0x14);
r8 = r8 - 0x1f4;
if (r8 &#x3C; 0x0) {
if (CPU_FLAGS &#x26; L) {
r8 = 0x1;
}
}
if ((r8 &#x26; 0x1) == 0x0) {
r8 = *(int32_t *)(var_10 + 0x14);
// 0x1f4 = 500（起始ID）
<strong>                    r8 = r8 - 0x1f4;
</strong>                    asm { smaddl     x8, w8, w9, x10 };
r8 = *(r8 + 0x8);
var_20 = r8;
r8 = r8 - 0x0;
if (r8 != 0x0) {
if (CPU_FLAGS &#x26; NE) {
r8 = 0x1;
}
}
// 与前一个版本相同的if else
// 检查地址0x100004040的使用（函数地址数组）
<strong>                    if ((r8 &#x26; 0x1) == 0x0) {
</strong><strong>                            *(var_18 + 0x18) = **0x100004000;
</strong>                            *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
else {
// 调用计算的地址，其中应该包含函数
<strong>                            (var_20)(var_10, var_18);
</strong>                            var_4 = 0x1;
}
}
else {
*(var_18 + 0x18) = **0x100004000;
*(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
}
else {
*(var_18 + 0x18) = **0x100004000;
*(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
r0 = var_4;
return r0;
}

</code></pre>
{% endtab %}
{% endtabs %}

实际上，如果你转到函数**`0x100004000`**，你会找到**`routine_descriptor`**结构体的数组，结构体的第一个元素是函数实现的地址，**结构体占用0x28字节**，所以每0x28字节（从字节0开始）你可以得到8字节，那就是将要调用的**函数的地址**：

<figure><img src="../../../../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

可以使用[**这个Hopper脚本**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py)提取这些数据。
<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 YouTube 🎥</strong></a></summary>

* 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取最新版本的PEASS或下载HackTricks的PDF**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)
* 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)
* **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **通过向**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **和**[**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **提交PR来分享你的黑客技巧。**

</details>
