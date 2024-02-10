# FISSURE - Das RF-Framework

**Frequenzunabhängige SDR-basierte Signalverständnis und Reverse Engineering**

FISSURE ist ein Open-Source-RF- und Reverse-Engineering-Framework, das für alle Kenntnisstufen entwickelt wurde und über Hooks für die Signalerkennung und -klassifizierung, die Protokollentdeckung, die Angriffsausführung, die IQ-Manipulation, die Schwachstellenanalyse, die Automatisierung und KI/ML verfügt. Das Framework wurde entwickelt, um die schnelle Integration von Softwaremodulen, Radios, Protokollen, Signaldaten, Skripten, Flussdiagrammen, Referenzmaterial und Tools von Drittanbietern zu fördern. FISSURE ist ein Workflow-Enabler, der die Software an einem Ort hält und es Teams ermöglicht, sich mühelos einzuarbeiten, während sie die gleiche bewährte Basiskonfiguration für bestimmte Linux-Distributionen teilen.

Das Framework und die mit FISSURE gelieferten Tools sind darauf ausgelegt, das Vorhandensein von RF-Energie zu erkennen, die Eigenschaften eines Signals zu verstehen, Proben zu sammeln und zu analysieren, Übertragungs- und/oder Injektionstechniken zu entwickeln und benutzerdefinierte Payloads oder Nachrichten zu erstellen. FISSURE enthält eine wachsende Bibliothek von Protokoll- und Signalinformationen, um bei der Identifizierung, Paketerstellung und Fuzzing zu helfen. Es gibt Online-Archivfunktionen zum Herunterladen von Signaldateien und zum Erstellen von Wiedergabelisten zur Simulation von Verkehr und zum Testen von Systemen.

Der benutzerfreundliche Python-Code und die Benutzeroberfläche ermöglichen es Anfängern, schnell beliebte Tools und Techniken im Zusammenhang mit RF und Reverse Engineering zu erlernen. Cybersecurity- und Ingenieurpädagogen können das integrierte Material nutzen oder das Framework verwenden, um ihre eigenen realen Anwendungen zu demonstrieren. Entwickler und Forscher können FISSURE für ihre täglichen Aufgaben verwenden oder ihre modernsten Lösungen einem breiteren Publikum zugänglich machen. Mit dem Wachstum von Bewusstsein und Nutzung von FISSURE in der Community werden auch die Fähigkeiten und der Umfang der darin enthaltenen Technologie zunehmen.

**Zusätzliche Informationen**

* [AIS-Seite](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22-Folien](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22-Papier](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22-Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat-Transkript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Erste Schritte

**Unterstützt**

Es gibt drei Zweige innerhalb von FISSURE, um die Dateinavigation zu erleichtern und Code-Redundanz zu reduzieren. Der Zweig Python2\_maint-3.7 enthält eine Codebasis, die auf Python2, PyQt4 und GNU Radio 3.7 aufbaut. Der Zweig Python3\_maint-3.8 basiert auf Python3, PyQt5 und GNU Radio 3.8. Der Zweig Python3\_maint-3.10 basiert auf Python3, PyQt5 und GNU Radio 3.10.

|   Betriebssystem   |   FISSURE-Zweig   |
| :----------------: | :---------------: |
|  Ubuntu 18.04 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64) | Python3\_maint-3.8 |

**In Bearbeitung (Beta)**

Diese Betriebssysteme befinden sich noch im Beta-Status. Sie werden entwickelt und es fehlen mehrere Funktionen. Elemente im Installationsprogramm können mit vorhandenen Programmen in Konflikt stehen oder erst nach Entfernung des Status installiert werden.

|     Betriebssystem     |    FISSURE-Zweig   |
| :-------------------: | :----------------: |
| DragonOS Focal (x86\_64) |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)    | Python3\_maint-3.10 |

Hinweis: Bestimmte Software-Tools funktionieren nicht für jedes Betriebssystem. Siehe [Software And Conflicts](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)

**Installation**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
Dies installiert die PyQt-Softwareabhängigkeiten, die erforderlich sind, um die Installations-GUIs zu starten, falls sie nicht gefunden werden.

Wählen Sie anschließend die Option aus, die am besten zu Ihrem Betriebssystem passt (wird automatisch erkannt, wenn Ihr Betriebssystem mit einer Option übereinstimmt).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Es wird empfohlen, FISSURE auf einem sauberen Betriebssystem zu installieren, um vorhandene Konflikte zu vermeiden. Wählen Sie alle empfohlenen Kontrollkästchen (Standardtaste) aus, um Fehler beim Betrieb der verschiedenen Tools innerhalb von FISSURE zu vermeiden. Während der Installation werden mehrere Aufforderungen angezeigt, die hauptsächlich nach erhöhten Berechtigungen und Benutzernamen fragen. Wenn ein Element einen "Verify"-Abschnitt am Ende enthält, führt der Installer den folgenden Befehl aus und markiert das Kontrollkästchen grün oder rot, abhängig davon, ob Fehler durch den Befehl verursacht werden. Überprüfte Elemente ohne "Verify"-Abschnitt bleiben nach der Installation schwarz.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Verwendung**

Öffnen Sie ein Terminal und geben Sie ein:
```
fissure
```
Siehe das FISSURE-Hilfemenü für weitere Details zur Verwendung.

## Details

**Komponenten**

* Dashboard
* Zentrale Hub (HIPRFISR)
* Ziel-Signalidentifikation (TSI)
* Protokollerkennung (PD)
* Flussdiagramm & Skriptausführer (FGE)

![Komponenten](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Fähigkeiten**

| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Signal-Detektor**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**IQ-Manipulation**_      | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Signal-Suche**_          | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Mustererkennung**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Angriffe**_           | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Signal-Wiedergabelisten**_       | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Bildergalerie**_  |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Paket-Erstellung**_   | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy-Integration**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC-Rechner**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Protokollierung**_            |

**Hardware**

Die folgende Liste enthält "unterstützte" Hardware mit unterschiedlichen Integrationsstufen:

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* 802.11-Adapter
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## Lektionen

FISSURE wird mit mehreren hilfreichen Anleitungen geliefert, um sich mit verschiedenen Technologien und Techniken vertraut zu machen. Viele enthalten Schritte zur Verwendung verschiedener in FISSURE integrierter Tools.

* [Lektion1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Lektion2: Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Lektion3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Lektion4: ESP Boards](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Lektion5: Radiosonde Tracking](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Lektion6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Lektion7: Datentypen](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Lektion8: Benutzerdefinierte GNU Radio Blöcke](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Lektion9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Lektion10: Ham Radio Exams](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Lektion11: Wi-Fi Tools](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)

## Roadmap

* [ ] Weitere Hardwaretypen, RF-Protokolle, Signalparameter und Analysetools hinzufügen
* [ ] Unterstützung für weitere Betriebssysteme
* [ ] Entwicklung von Kursmaterial zu FISSURE (RF-Angriffe, Wi-Fi, GNU Radio, PyQt usw.)
* [ ] Erstellung eines Signalverstärkers, Merkmalsextraktors und Signalklassifikators mit auswählbaren KI/ML-Techniken
* [ ] Implementierung rekursiver Demodulationsmechanismen zur Erzeugung eines Bitstroms aus unbekannten Signalen
* [ ] Übergang der Hauptkomponenten von FISSURE zu einem generischen Sensor-Knoten-Bereitstellungsschema

## Mitarbeit

Vorschläge zur Verbesserung von FISSURE sind sehr willkommen. Hinterlassen Sie einen Kommentar auf der [Diskussionsseite](https://github.com/ainfosec/FISSURE/discussions) oder im Discord-Server, wenn Sie Gedanken zu folgenden Themen haben:

* Neue Funktionsvorschläge und Designänderungen
* Softwaretools mit Installationsanleitungen
* Neue Lektionen oder zusätzliches Material für bestehende Lektionen
* Interessante RF-Protokolle
* Mehr Hardware- und SDR-Typen zur Integration
* IQ-Analyse-Skripte in Python
* Korrekturen und Verbesserungen bei der Installation

Beiträge zur Verbesserung von FISSURE sind entscheidend, um seine Entwicklung zu beschleunigen. Alle Beiträge, die Sie leisten, werden sehr geschätzt. Wenn Sie zur Code-Entwicklung beitragen möchten, erstellen Sie bitte einen Fork des Repositories und erstellen Sie einen Pull-Request:

1. Forken Sie das Projekt
2. Erstellen Sie Ihren Feature-Branch (`git checkout -b feature/AmazingFeature`)
3. Committen Sie Ihre Änderungen (`git commit -m 'Add some AmazingFeature'`)
4. Pushen Sie den Branch (`git push origin feature/AmazingFeature`)
5. Eröffnen Sie einen Pull-Request

Das Erstellen von [Issues](https://github.com/ainfosec/FISSURE/issues), um auf Fehler aufmerksam zu machen, ist ebenfalls willkommen.

## Zusammenarbeit

Kontaktieren Sie die Geschäftsentwicklung von Assured Information Security, Inc. (AIS), um mögliche Zusammenarbeitsmöglichkeiten mit FISSURE vorzuschlagen und zu formalisieren - sei es durch die Bereitstellung von Zeit zur Integration Ihrer Software, die Entwicklung von Lösungen für Ihre technischen Herausforderungen durch die talentierten Mitarbeiter von AIS oder die Integration von FISSURE in andere Plattformen/Anwendungen.

## Lizenz

GPL-3.0

Details zur Lizenz finden Sie in der LICENSE-Datei.
## Kontakt

Trete dem Discord-Server bei: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Folge auf Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Geschäftsentwicklung - Assured Information Security, Inc. - bd@ainfosec.com

## Anerkennungen

Wir erkennen und sind dankbar für die Arbeit dieser Entwickler:

[Anerkennungen](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Danksagungen

Besonderer Dank geht an Dr. Samuel Mantravadi und Joseph Reith für ihre Beiträge zu diesem Projekt.
