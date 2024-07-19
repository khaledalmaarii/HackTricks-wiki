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

Logstash jest używany do **zbierania, przekształcania i wysyłania logów** przez system znany jako **pipelines**. Te pipelines składają się z etapów **input**, **filter** i **output**. Interesujący aspekt pojawia się, gdy Logstash działa na skompromitowanej maszynie.

### Konfiguracja Pipeline

Pipelines są konfigurowane w pliku **/etc/logstash/pipelines.yml**, który wymienia lokalizacje konfiguracji pipeline:
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
Ten plik ujawnia, gdzie znajdują się pliki **.conf**, zawierające konfiguracje potoków. Przy użyciu modułu wyjściowego **Elasticsearch**, powszechnie jest, że **potoki** zawierają **poświadczenia Elasticsearch**, które często mają szerokie uprawnienia z powodu potrzeby Logstasha do zapisywania danych w Elasticsearch. Znaki wieloznaczne w ścieżkach konfiguracji pozwalają Logstashowi na wykonanie wszystkich pasujących potoków w wyznaczonym katalogu.

### Eskalacja uprawnień za pomocą zapisywalnych potoków

Aby spróbować eskalacji uprawnień, najpierw zidentyfikuj użytkownika, pod którym działa usługa Logstash, zazwyczaj użytkownika **logstash**. Upewnij się, że spełniasz **jedno** z tych kryteriów:

- Posiadasz **dostęp do zapisu** do pliku **.conf** potoku **lub**
- Plik **/etc/logstash/pipelines.yml** używa znaku wieloznacznego, a ty możesz zapisywać w docelowym folderze

Dodatkowo, **jedno** z tych warunków musi być spełnione:

- Możliwość ponownego uruchomienia usługi Logstash **lub**
- Plik **/etc/logstash/logstash.yml** ma ustawione **config.reload.automatic: true**

Mając znak wieloznaczny w konfiguracji, stworzenie pliku, który pasuje do tego znaku, pozwala na wykonanie polecenia. Na przykład:
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
Tutaj **interwał** określa częstotliwość wykonywania w sekundach. W podanym przykładzie polecenie **whoami** jest uruchamiane co 120 sekund, a jego wyjście jest kierowane do **/tmp/output.log**.

Dzięki **config.reload.automatic: true** w **/etc/logstash/logstash.yml**, Logstash automatycznie wykryje i zastosuje nowe lub zmodyfikowane konfiguracje potoków bez potrzeby ponownego uruchamiania. Jeśli nie ma znaku wieloznacznego, nadal można wprowadzać zmiany w istniejących konfiguracjach, ale zaleca się ostrożność, aby uniknąć zakłóceń.
