<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>


## Logstash

Logstash wird verwendet, um **Logs zu sammeln, zu transformieren und zu versenden** durch ein System, das als **Pipelines** bekannt ist. Diese Pipelines bestehen aus **Eingabe**, **Filter** und **Ausgabe** Stufen. Ein interessanter Aspekt ergibt sich, wenn Logstash auf einer kompromittierten Maschine arbeitet.

### Pipeline-Konfiguration

Die Pipelines werden in der Datei **/etc/logstash/pipelines.yml** konfiguriert, die die Speicherorte der Pipeline-Konfigurationen auflistet:
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
Diese Datei enthüllt, wo sich die **.conf**-Dateien mit den Pipeline-Konfigurationen befinden. Wenn das **Elasticsearch Output-Modul** verwendet wird, ist es üblich, dass **Pipelines** Elasticsearch-Anmeldeinformationen enthalten, die aufgrund der Notwendigkeit von Logstash, Daten in Elasticsearch zu schreiben, oft umfangreiche Berechtigungen besitzen. Platzhalter in den Konfigurationspfaden ermöglichen es Logstash, alle übereinstimmenden Pipelines im angegebenen Verzeichnis auszuführen.

### Privilege Escalation über beschreibbare Pipelines

Um eine Privilege Escalation zu versuchen, identifizieren Sie zunächst den Benutzer, unter dem der Logstash-Dienst läuft, normalerweise der **logstash**-Benutzer. Stellen Sie sicher, dass Sie **eine** der folgenden Kriterien erfüllen:

- Besitzen Sie **Schreibzugriff** auf eine Pipeline-**.conf**-Datei **oder**
- Die Datei **/etc/logstash/pipelines.yml** verwendet einen Platzhalter und Sie können in das Zielverzeichnis schreiben

Zusätzlich muss **eine** der folgenden Bedingungen erfüllt sein:

- Fähigkeit, den Logstash-Dienst neu zu starten **oder**
- Die Datei **/etc/logstash/logstash.yml** hat **config.reload.automatic: true** festgelegt

Bei einem Platzhalter in der Konfiguration ermöglicht das Erstellen einer Datei, die diesem Platzhalter entspricht, die Ausführung von Befehlen. Zum Beispiel:
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
Hier bestimmt **interval** die Ausführungshäufigkeit in Sekunden. Im gegebenen Beispiel wird der Befehl **whoami** alle 120 Sekunden ausgeführt und die Ausgabe wird in **/tmp/output.log** umgeleitet.

Mit **config.reload.automatic: true** in **/etc/logstash/logstash.yml** erkennt Logstash automatisch neue oder geänderte Pipeline-Konfigurationen und wendet sie an, ohne dass ein Neustart erforderlich ist. Wenn kein Platzhalter vorhanden ist, können Änderungen an bestehenden Konfigurationen vorgenommen werden, aber Vorsicht ist geboten, um Störungen zu vermeiden.


## Referenzen

* [https://insinuator.net/2021/01/pentesting-the-elk-stack/](https://insinuator.net/2021/01/pentesting-the-elk-stack/)


<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
