<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


## Logstash

Logstash is used to **gather, transform, and dispatch logs** through a system known as **pipelines**. These pipelines are made up of **input**, **filter**, and **output** stages. An interesting aspect arises when Logstash operates on a compromised machine.

### Pipeline Configuration

Pipelines are configured in the file **/etc/logstash/pipelines.yml**, which lists the locations of the pipeline configurations:
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
**.conf** files, containing pipeline configurations, are located in this file. When using an **Elasticsearch output module**, it is common for **pipelines** to include **Elasticsearch credentials**, which often have extensive privileges because Logstash needs to write data to Elasticsearch. Wildcards in configuration paths allow Logstash to execute all matching pipelines in the specified directory.

### Privilege Escalation via Writable Pipelines

To attempt privilege escalation, first identify the user under which the Logstash service is running, typically the **logstash** user. Make sure you meet **one** of these criteria:

- Have **write access** to a pipeline **.conf** file **or**
- The **/etc/logstash/pipelines.yml** file uses a wildcard, and you can write to the target folder

In addition, **one** of these conditions must be met:

- Ability to restart the Logstash service **or**
- The **/etc/logstash/logstash.yml** file has **config.reload.automatic: true** set

If there is a wildcard in the configuration, creating a file that matches this wildcard allows for command execution. For example:
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
DaH, **interval** vItlhutlh vItlhutlh frequency seconds. vaj **whoami** command, **/tmp/output.log** vItlhutlh output, 120 seconds vItlhutlh run.

**/etc/logstash/logstash.yml** vIlo' automatic **config.reload.automatic: true** vItlhutlh Logstash, pipeline configurations new modified automatically detect apply without restart. wildcard, modifications existing configurations vItlhutlh, caution advised disruptions avoid.

## References

* [https://insinuator.net/2021/01/pentesting-the-elk-stack/](https://insinuator.net/2021/01/pentesting-the-elk-stack/)


<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
