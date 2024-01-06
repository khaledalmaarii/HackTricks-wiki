<details>

<summary><strong>从零到英雄学习AWS黑客攻击，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS红队专家)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果您想在**HackTricks中看到您的公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs系列**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**telegram群组**](https://t.me/peass)或在**Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


# 基本信息

Logstash 用于收集、转换和输出日志。这是通过使用**管道**实现的，它包含输入、过滤和输出模块。当攻破运行Logstash服务的机器时，该服务变得很有趣。

## 管道

管道配置文件 **/etc/logstash/pipelines.yml** 指定了活动管道的位置：
```bash
# This file is where you define your pipelines. You can define multiple.
# For more information on multiple pipelines, see the documentation:
# https://www.elastic.co/guide/en/logstash/current/multiple-pipelines.html

- pipeline.id: main
path.config: "/etc/logstash/conf.d/*.conf"
- pipeline.id: example
path.config: "/usr/share/logstash/pipeline/1*.conf"
pipeline.workers: 6
```
在这里，你可以找到指向 **.conf** 文件的路径，这些文件包含配置好的管道。如果使用了 **Elasticsearch 输出模块**，**管道**很可能会**包含**对某个 Elasticsearch 实例的有效**凭证**。这些凭证通常拥有更多权限，因为 Logstash 需要向 Elasticsearch 写入数据。如果使用了通配符，Logstash 会尝试运行匹配该通配符的文件夹中的所有管道。

## 通过可写管道提升权限

在尝试提升自己的权限之前，你应该检查运行 logstash 服务的用户是谁，因为这将是你之后将要控制的用户。默认情况下，logstash 服务以 **logstash** 用户的权限运行。

检查你是否拥有以下所需的权限之一：

* 你对某个管道的 **.conf** 文件拥有**写权限**，**或者**
* **/etc/logstash/pipelines.yml** 包含一个通配符，并且你被允许写入指定的文件夹

此外，必须满足以下条件之一：

* 你能够重启 logstash 服务，**或者**
* **/etc/logstash/logstash.yml** 包含条目 **config.reload.automatic: true**

如果指定了通配符，尝试创建一个匹配该通配符的文件。可以将以下内容写入文件以执行命令：
```bash
input {
exec {
command => "whoami"
interval => 120
}
}

output {
file {
path => "/tmp/output.log"
codec => rubydebug
}
}
```
**间隔**指定时间（秒）。在此示例中，每120秒执行一次**whoami**命令。命令的输出保存在**/tmp/output.log**中。

如果**/etc/logstash/logstash.yml**包含条目**config.reload.automatic: true**，你只需等待命令执行，因为Logstash会自动识别新的管道配置文件或现有管道配置的任何更改。否则，触发重启logstash服务。

如果没有使用通配符，你可以将这些更改应用于现有的管道配置。**确保你不要弄坏东西！**

# 参考资料

* [https://insinuator.net/2021/01/pentesting-the-elk-stack/](https://insinuator.net/2021/01/pentesting-the-elk-stack/)


<details>

<summary><strong>从零开始学习AWS黑客攻击直到成为专家，通过</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

支持HackTricks的其他方式：

* 如果你想在**HackTricks**中看到你的**公司广告**或**下载HackTricks的PDF**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！
* 获取[**官方PEASS & HackTricks商品**](https://peass.creator-spring.com)
* 发现[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们独家的[**NFTs**](https://opensea.io/collection/the-peass-family)系列
* **加入** 💬 [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**telegram群组**](https://t.me/peass) 或在 **Twitter** 🐦 上**关注**我 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **通过向** [**HackTricks**](https://github.com/carlospolop/hacktricks) 和 [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享你的黑客技巧。

</details>
