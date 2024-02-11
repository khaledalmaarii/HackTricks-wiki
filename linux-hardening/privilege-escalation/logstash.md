<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>


## Logstash

Logstash służy do **zbierania, przekształcania i wysyłania logów** za pomocą systemu znakowanego jako **pipelines**. Te pipelines składają się z etapów **wejścia**, **filtrowania** i **wyjścia**. Interesujący aspekt pojawia się, gdy Logstash działa na skompromitowanej maszynie.

### Konfiguracja pipelines

Pipelines są konfigurowane w pliku **/etc/logstash/pipelines.yml**, który wymienia lokalizacje konfiguracji pipelines:
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
Ten plik ujawnia, gdzie znajdują się pliki **.conf** zawierające konfiguracje potoków. Podczas korzystania z modułu wyjściowego **Elasticsearch**, często w **potokach** znajdują się **dane uwierzytelniające Elasticsearch**, które często posiadają rozszerzone uprawnienia ze względu na potrzebę Logstash do zapisywania danych w Elasticsearch. Znaki wieloznaczne w ścieżkach konfiguracji pozwalają Logstashowi wykonywać wszystkie pasujące potoki w wyznaczonym katalogu.

### Eskalacja uprawnień za pomocą zapisywalnych potoków

Aby spróbować eskalacji uprawnień, najpierw zidentyfikuj użytkownika, na którym działa usługa Logstash, zwykle jest to użytkownik **logstash**. Upewnij się, że spełniasz **jeden** z tych kryteriów:

- Posiadanie **uprawnień do zapisu** pliku **.conf** potoku **lub**
- Plik **/etc/logstash/pipelines.yml** używa znaku wieloznacznego, a ty możesz zapisywać do docelowego folderu

Dodatkowo, musi być spełniony **jeden** z tych warunków:

- Możliwość ponownego uruchomienia usługi Logstash **lub**
- Plik **/etc/logstash/logstash.yml** ma ustawione **config.reload.automatic: true**

Podając znak wieloznaczny w konfiguracji, utworzenie pliku pasującego do tego znaku umożliwia wykonanie polecenia. Na przykład:
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
Tutaj **interval** określa częstotliwość wykonania w sekundach. W podanym przykładzie polecenie **whoami** uruchamia się co 120 sekund, a jego wynik jest kierowany do **/tmp/output.log**.

Dzięki **config.reload.automatic: true** w pliku **/etc/logstash/logstash.yml**, Logstash automatycznie wykrywa i stosuje nowe lub zmodyfikowane konfiguracje potoku bez konieczności ponownego uruchamiania. Jeśli nie ma symbolu wieloznaczności, nadal można dokonywać modyfikacji istniejących konfiguracji, ale zaleca się ostrożność, aby uniknąć zakłóceń.


## Referencje

* [https://insinuator.net/2021/01/pentesting-the-elk-stack/](https://insinuator.net/2021/01/pentesting-the-elk-stack/)


<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
