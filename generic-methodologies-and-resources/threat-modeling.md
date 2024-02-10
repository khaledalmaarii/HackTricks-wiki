# Threat Modeling

## Bedrohungsmodellierung

Willkommen zu HackTricks' umfassendem Leitfaden zur Bedrohungsmodellierung! Machen Sie sich auf eine Erkundung dieses wichtigen Aspekts der Cybersicherheit, bei dem potenzielle Schwachstellen in einem System identifiziert, verstanden und strategisch bekämpft werden. Dieser Thread dient als Schritt-für-Schritt-Anleitung, die mit realen Beispielen, hilfreicher Software und leicht verständlichen Erklärungen gefüllt ist. Ideal für Anfänger und erfahrene Praktiker, die ihre Cybersicherheitsverteidigung stärken möchten.

### Häufig verwendete Szenarien

1. **Softwareentwicklung**: Im Rahmen des Secure Software Development Life Cycle (SSDLC) hilft die Bedrohungsmodellierung dabei, **potenzielle Schwachstellen in den frühen Entwicklungsphasen zu identifizieren**.
2. **Penetrationstests**: Das Penetration Testing Execution Standard (PTES) Framework erfordert die **Bedrohungsmodellierung, um die Schwachstellen des Systems zu verstehen**, bevor der Test durchgeführt wird.

### Bedrohungsmodell in Kürze

Ein Bedrohungsmodell wird in der Regel als Diagramm, Bild oder in anderer visueller Form dargestellt, die die geplante Architektur oder den vorhandenen Aufbau einer Anwendung zeigt. Es ähnelt einem **Datenflussdiagramm**, aber der wesentliche Unterschied liegt in seinem sicherheitsorientierten Design.

Bedrohungsmodelle enthalten oft Elemente, die in Rot markiert sind und potenzielle Schwachstellen, Risiken oder Barrieren symbolisieren. Um den Prozess der Risikoerkennung zu optimieren, wird die CIA (Vertraulichkeit, Integrität, Verfügbarkeit) Triade verwendet, die die Grundlage vieler Bedrohungsmodellierungsmethoden bildet, wobei STRIDE eine der häufigsten ist. Die gewählte Methodik kann jedoch je nach spezifischem Kontext und Anforderungen variieren.

### Die CIA-Triade

Die CIA-Triade ist ein weit verbreitetes Modell im Bereich der Informationssicherheit und steht für Vertraulichkeit, Integrität und Verfügbarkeit. Diese drei Säulen bilden die Grundlage vieler Sicherheitsmaßnahmen und -richtlinien, einschließlich Bedrohungsmodellierungsmethoden.

1. **Vertraulichkeit**: Gewährleistung, dass die Daten oder das System nicht von unbefugten Personen abgerufen werden. Dies ist ein zentraler Aspekt der Sicherheit, der angemessene Zugangskontrollen, Verschlüsselung und andere Maßnahmen erfordert, um Datenlecks zu verhindern.
2. **Integrität**: Die Genauigkeit, Konsistenz und Vertrauenswürdigkeit der Daten über ihren Lebenszyklus hinweg. Dieses Prinzip stellt sicher, dass die Daten von unbefugten Parteien nicht verändert oder manipuliert werden. Es beinhaltet oft Prüfsummen, Hashing und andere Methoden zur Datenüberprüfung.
3. **Verfügbarkeit**: Dies stellt sicher, dass Daten und Dienste für autorisierte Benutzer zugänglich sind, wenn sie benötigt werden. Dies beinhaltet oft Redundanz, Ausfallsicherheit und Hochverfügbarkeitskonfigurationen, um Systeme auch bei Störungen am Laufen zu halten.

### Bedrohungsmodellierungsmethoden

1. **STRIDE**: Entwickelt von Microsoft, steht STRIDE für **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service und Elevation of Privilege**. Jede Kategorie repräsentiert eine Art von Bedrohung, und diese Methodik wird häufig in der Designphase eines Programms oder Systems verwendet, um potenzielle Bedrohungen zu identifizieren.
2. **DREAD**: Dies ist eine weitere Methodik von Microsoft, die zur Risikobewertung identifizierter Bedrohungen verwendet wird. DREAD steht für **Damage potential, Reproducibility, Exploitability, Affected users und Discoverability**. Jeder dieser Faktoren wird bewertet, und das Ergebnis wird zur Priorisierung identifizierter Bedrohungen verwendet.
3. **PASTA** (Process for Attack Simulation and Threat Analysis): Dies ist eine siebenstufige, **risikozentrierte** Methodik. Sie umfasst die Definition und Identifizierung von Sicherheitszielen, die Erstellung eines technischen Umfangs, die Anwendungszergliederung, die Bedrohungsanalyse, die Schwachstellenanalyse und die Risiko-/Triagebewertung.
4. **Trike**: Dies ist eine risikobasierte Methodik, die sich auf die Verteidigung von Vermögenswerten konzentriert. Sie beginnt aus einer **Risikomanagement**-Perspektive und betrachtet Bedrohungen und Schwachstellen in diesem Kontext.
5. **VAST** (Visual, Agile und Simple Threat Modeling): Dieser Ansatz zielt darauf ab, zugänglicher zu sein und sich in agile Entwicklungsumgebungen zu integrieren. Er kombiniert Elemente aus den anderen Methoden und konzentriert sich auf **visuelle Darstellungen von Bedrohungen**.
6. **OCTAVE** (Operationally Critical Threat, Asset und Vulnerability Evaluation): Entwickelt vom CERT Coordination Center, ist dieser Rahmen auf **organisatorische Risikobewertungen anstatt auf spezifische Systeme oder Software** ausgerichtet.

## Tools

Es gibt mehrere Tools und Softwarelösungen, die bei der Erstellung und Verwaltung von Bedrohungsmodellen **helfen** können. Hier sind einige, die Sie in Betracht ziehen könnten.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

Ein fortschrittlicher plattformübergreifender und multifunktionaler GUI-Web-Spider/Crawler für Cybersicherheitsfachleute. Spider Suite kann für die Kartierung und Analyse der Angriffsfläche verwendet werden.

**Verwendung**

1. Wählen Sie eine URL und crawlen Sie

<figure><img src="../.gitbook/assets/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Graph anzeigen

<figure><img src="../.gitbook/assets/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

Ein Open-Source-Projekt von OWASP, Threat Dragon ist sowohl eine Web- als auch eine Desktop-Anwendung, die Systemdiagramme sowie eine Regel-Engine zur automatischen Generierung von Bedrohungen/Minderungsmaßnahmen enthält.

**Verwendung**

1. Neues Projekt erstellen

<figure><img src="../.gitbook/assets/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

Manchmal könnte es so aussehen:

<figure><img src="../.gitbook/assets/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. Neues Projekt starten

<figure><img src="../.gitbook/assets/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. Das neue Projekt speichern

<figure><img src="../.gitbook/assets/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. Erstellen Sie Ihr Modell

Sie können Tools wie den SpiderSuite Crawler verwenden, um Inspiration zu erhalten. Ein grundlegendes Modell würde etwa so aussehen:

<figure><img src="../.gitbook/assets/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

Eine kleine Erklärung zu den Entitäten:

* Prozess (Die Entität selbst, wie z.B. Webserver oder Webfunktionalität)
* Akteur (Eine Person wie ein Website-Besucher, Benutzer oder Administrator)
* Datenflusslinie (Indikator für die Interaktion)
* Vertrauensgrenze (Unterschiedliche Netzwerksegmente oder Bereiche.)
* Speichern (Dinge, in denen Daten gespeichert werden, wie z.B. Datenbanken)

5. Bedrohung erstellen (Schritt 1)

Zunächst müssen Sie die Ebene auswählen, zu der Sie eine Bedrohung hinzufügen möchten

<figure><img src="../.gitbook/assets/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

Jetzt können Sie die Bedrohung erstellen

<figure><img src="../.gitbook/assets/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Beachten Sie, dass es einen Unterschied zwischen Akteursbedrohungen und Prozessbedrohungen gibt. Wenn Sie eine Bedrohung zu einem Akteur hinzufügen würden, könnten Sie nur "Spoofing" und "Repudiation" auswählen. In unserem Beispiel fügen wir jedoch eine Bedrohung zu einer Prozessentität hinzu, daher sehen wir Folgendes im Bedrohungs-Erstellungsfeld:

<figure><img src="../.gitbook/assets/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. Fertig

Jetzt sollte Ihr fertiges Modell etwa so aussehen. Und so erstellen Sie ein einfaches Bedrohungsmodell mit OWASP Threat Dragon.

<figure><img src="../.gitbook/assets/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Dies ist ein kostenloses Tool von Microsoft, das bei der Suche nach Bedrohungen in der Designphase von Softwareprojekten hilft. Es verwendet die STRIDE-Methodik und eignet sich besonders für diejenigen, die auf Microsofts Stack entwickeln.
