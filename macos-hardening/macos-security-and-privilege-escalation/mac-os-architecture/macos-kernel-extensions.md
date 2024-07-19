# macOS Kernel Extensions

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}

## Grundinformationen

Kernel-Erweiterungen (Kexts) sind **Pakete** mit einer **`.kext`**-Erweiterung, die **direkt in den macOS-Kernelraum geladen werden**, um zusätzliche Funktionalität zum Hauptbetriebssystem bereitzustellen.

### Anforderungen

Offensichtlich ist es so mächtig, dass es **kompliziert ist, eine Kernel-Erweiterung zu laden**. Dies sind die **Anforderungen**, die eine Kernel-Erweiterung erfüllen muss, um geladen zu werden:

* Beim **Eintreten in den Wiederherstellungsmodus** müssen Kernel-**Erweiterungen erlaubt** sein, geladen zu werden:

<figure><img src="../../../.gitbook/assets/image (327).png" alt=""><figcaption></figcaption></figure>

* Die Kernel-Erweiterung muss **mit einem Kernel-Code-Signaturzertifikat signiert** sein, das nur von **Apple** **gewährt** werden kann. Wer wird das Unternehmen und die Gründe, warum es benötigt wird, im Detail überprüfen.
* Die Kernel-Erweiterung muss auch **notariell beglaubigt** sein, Apple wird in der Lage sein, sie auf Malware zu überprüfen.
* Dann ist der **Root**-Benutzer derjenige, der die **Kernel-Erweiterung laden** kann, und die Dateien im Paket müssen **dem Root gehören**.
* Während des Ladeprozesses muss das Paket an einem **geschützten Nicht-Root-Standort** vorbereitet werden: `/Library/StagedExtensions` (erfordert die Genehmigung `com.apple.rootless.storage.KernelExtensionManagement`).
* Schließlich erhält der Benutzer beim Versuch, sie zu laden, eine [**Bestätigungsanfrage**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) und, wenn akzeptiert, muss der Computer **neu gestartet** werden, um sie zu laden.

### Ladeprozess

In Catalina war es so: Es ist interessant zu beachten, dass der **Überprüfungs**prozess in **Userland** erfolgt. Allerdings können nur Anwendungen mit der **`com.apple.private.security.kext-management`** Genehmigung **die Kernel anfordern, eine Erweiterung zu laden**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** CLI **startet** den **Überprüfungs**prozess zum Laden einer Erweiterung
* Es wird mit **`kextd`** kommunizieren, indem es einen **Mach-Dienst** verwendet.
2. **`kextd`** wird mehrere Dinge überprüfen, wie die **Signatur**
* Es wird mit **`syspolicyd`** kommunizieren, um zu **überprüfen**, ob die Erweiterung **geladen** werden kann.
3. **`syspolicyd`** wird den **Benutzer** **auffordern**, wenn die Erweiterung nicht zuvor geladen wurde.
* **`syspolicyd`** wird das Ergebnis an **`kextd`** melden
4. **`kextd`** wird schließlich in der Lage sein, dem Kernel zu **sagen, die Erweiterung zu laden**

Wenn **`kextd`** nicht verfügbar ist, kann **`kextutil`** die gleichen Überprüfungen durchführen.

## Referenzen

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}
