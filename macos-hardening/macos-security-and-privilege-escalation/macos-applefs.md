# macOS AppleFS

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
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Apple Proprietäres Dateisystem (APFS)

**Apple File System (APFS)** ist ein modernes Dateisystem, das entwickelt wurde, um das Hierarchical File System Plus (HFS+) zu ersetzen. Seine Entwicklung wurde durch die Notwendigkeit nach **verbesserter Leistung, Sicherheit und Effizienz** vorangetrieben.

Einige bemerkenswerte Funktionen von APFS sind:

1. **Raumteilung**: APFS ermöglicht es mehreren Volumes, **den gleichen zugrunde liegenden freien Speicher** auf einem einzigen physischen Gerät zu **teilen**. Dies ermöglicht eine effizientere Raumnutzung, da die Volumes dynamisch wachsen und schrumpfen können, ohne dass eine manuelle Größenänderung oder Neupartitionierung erforderlich ist.
1. Das bedeutet im Vergleich zu traditionellen Partitionen auf Datenträgern, **dass in APFS verschiedene Partitionen (Volumes) den gesamten Speicherplatz der Festplatte teilen**, während eine reguläre Partition normalerweise eine feste Größe hatte.
2. **Snapshots**: APFS unterstützt **das Erstellen von Snapshots**, die **schreibgeschützt** und zeitpunktbezogene Instanzen des Dateisystems sind. Snapshots ermöglichen effiziente Backups und einfache System-Rollbacks, da sie minimalen zusätzlichen Speicherplatz verbrauchen und schnell erstellt oder zurückgesetzt werden können.
3. **Klone**: APFS kann **Datei- oder Verzeichnis-Klone erstellen, die den gleichen Speicher** wie das Original teilen, bis entweder der Klon oder die Originaldatei geändert wird. Diese Funktion bietet eine effiziente Möglichkeit, Kopien von Dateien oder Verzeichnissen zu erstellen, ohne den Speicherplatz zu duplizieren.
4. **Verschlüsselung**: APFS **unterstützt nativ die vollständige Festplattenverschlüsselung** sowie die Verschlüsselung pro Datei und pro Verzeichnis, was die Datensicherheit in verschiedenen Anwendungsfällen erhöht.
5. **Absturzschutz**: APFS verwendet ein **Copy-on-Write-Metadaten-Schema, das die Konsistenz des Dateisystems gewährleistet**, selbst bei plötzlichem Stromausfall oder Systemabstürzen, wodurch das Risiko von Datenkorruption verringert wird.

Insgesamt bietet APFS ein moderneres, flexibleres und effizienteres Dateisystem für Apple-Geräte, mit einem Fokus auf verbesserte Leistung, Zuverlässigkeit und Sicherheit.
```bash
diskutil list # Get overview of the APFS volumes
```
## Firmlinks

Das `Data`-Volume ist in **`/System/Volumes/Data`** eingebunden (dies können Sie mit `diskutil apfs list` überprüfen).

Die Liste der Firmlinks befindet sich in der **`/usr/share/firmlinks`**-Datei.
```bash
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
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

{% endhint %}
</details>
{% endhint %}
