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


**Der ursprüngliche Beitrag ist** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## Zusammenfassung

Zwei Registrierungsschlüssel wurden gefunden, die vom aktuellen Benutzer beschreibbar sind:

- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**

Es wurde empfohlen, die Berechtigungen des **RpcEptMapper**-Dienstes mit der **regedit GUI** zu überprüfen, insbesondere im **Erweiterten Sicherheitsoptionen**-Fenster auf der Registerkarte **Effektive Berechtigungen**. Dieser Ansatz ermöglicht die Bewertung der gewährten Berechtigungen für bestimmte Benutzer oder Gruppen, ohne jeden Access Control Entry (ACE) einzeln zu überprüfen.

Ein Screenshot zeigte die Berechtigungen, die einem Benutzer mit niedrigen Rechten zugewiesen waren, unter denen die Berechtigung **Subkey erstellen** auffiel. Diese Berechtigung, auch als **AppendData/AddSubdirectory** bezeichnet, entspricht den Ergebnissen des Skripts.

Es wurde festgestellt, dass bestimmte Werte nicht direkt geändert werden konnten, jedoch die Möglichkeit bestand, neue Subkeys zu erstellen. Ein Beispiel war der Versuch, den Wert **ImagePath** zu ändern, was zu einer Zugriffsverweigerung führte.

Trotz dieser Einschränkungen wurde ein Potenzial für Privilegieneskalation identifiziert, indem die Möglichkeit genutzt wurde, den **Performance**-Subkey innerhalb der Registrierungsstruktur des **RpcEptMapper**-Dienstes zu verwenden, ein Subkey, der standardmäßig nicht vorhanden ist. Dies könnte die Registrierung von DLLs und die Leistungsüberwachung ermöglichen.

Dokumentation zum **Performance**-Subkey und seiner Nutzung zur Leistungsüberwachung wurde konsultiert, was zur Entwicklung einer Proof-of-Concept-DLL führte. Diese DLL, die die Implementierung der Funktionen **OpenPerfData**, **CollectPerfData** und **ClosePerfData** demonstrierte, wurde über **rundll32** getestet, was ihren operationellen Erfolg bestätigte.

Das Ziel war es, den **RPC Endpoint Mapper-Dienst** dazu zu bringen, die erstellte Performance-DLL zu laden. Beobachtungen zeigten, dass das Ausführen von WMI-Klassenabfragen im Zusammenhang mit Leistungsdaten über PowerShell zur Erstellung einer Protokolldatei führte, die die Ausführung beliebigen Codes im **LOCAL SYSTEM**-Kontext ermöglichte, wodurch erhöhte Berechtigungen gewährt wurden.

Die Persistenz und die potenziellen Auswirkungen dieser Schwachstelle wurden hervorgehoben, was ihre Relevanz für Post-Exploitation-Strategien, laterale Bewegung und die Umgehung von Antivirus-/EDR-Systemen unterstrich.

Obwohl die Schwachstelle zunächst unbeabsichtigt durch das Skript offengelegt wurde, wurde betont, dass ihre Ausnutzung auf veraltete Windows-Versionen (z. B. **Windows 7 / Server 2008 R2**) beschränkt ist und lokalen Zugriff erfordert.

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
