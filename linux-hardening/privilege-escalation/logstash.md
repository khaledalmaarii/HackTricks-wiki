{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}


## Logstash

Logstash inatumika kwa **kusanya, kubadilisha, na kutuma logi** kupitia mfumo unaojulikana kama **pipelines**. Pipelines hizi zinajumuisha hatua za **input**, **filter**, na **output**. Kipengele cha kuvutia kinajitokeza wakati Logstash inafanya kazi kwenye mashine iliyoathiriwa.

### Pipeline Configuration

Pipelines zinapangiliwa katika faili **/etc/logstash/pipelines.yml**, ambayo inataja maeneo ya mipangilio ya pipeline:
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
This file reveals where the **.conf** files, containing pipeline configurations, are located. When employing an **Elasticsearch output module**, it's common for **pipelines** to include **Elasticsearch credentials**, which often possess extensive privileges due to Logstash's need to write data to Elasticsearch. Wildcards in configuration paths allow Logstash to execute all matching pipelines in the designated directory.

### Privilege Escalation via Writable Pipelines

Ili kujaribu kupandisha hadhi, kwanza tambua mtumiaji ambaye huduma ya Logstash inafanya kazi chini yake, kawaida ni mtumiaji **logstash**. Hakikisha unakidhi **moja** ya vigezo hivi:

- Kuwa na **ufikiaji wa kuandika** kwenye faili ya pipeline **.conf** **au**
- Faili ya **/etc/logstash/pipelines.yml** inatumia wildcard, na unaweza kuandika kwenye folda lengwa

Zaidi ya hayo, **moja** ya masharti haya lazima itimizwe:

- Uwezo wa kuanzisha upya huduma ya Logstash **au**
- Faili ya **/etc/logstash/logstash.yml** ina **config.reload.automatic: true** imewekwa

Ili kuwa na wildcard katika usanidi, kuunda faili inayolingana na wildcard hii inaruhusu utekelezaji wa amri. Kwa mfano:
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
Hapa, **interval** inatambulisha mzunguko wa utekelezaji kwa sekunde. Katika mfano uliopewa, amri ya **whoami** inatekelezwa kila sekunde 120, na matokeo yake yanaelekezwa kwenye **/tmp/output.log**.

Kwa **config.reload.automatic: true** katika **/etc/logstash/logstash.yml**, Logstash itagundua na kutekeleza kiotomatiki mipangilio mipya au iliyobadilishwa ya pipeline bila kuhitaji kuanzisha upya. Ikiwa hakuna wildcard, mabadiliko bado yanaweza kufanywa kwa mipangilio iliyopo, lakini tahadhari inashauriwa ili kuepuka usumbufu.
