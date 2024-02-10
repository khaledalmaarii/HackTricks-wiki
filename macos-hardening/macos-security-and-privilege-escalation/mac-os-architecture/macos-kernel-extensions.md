# macOS Kernelerweiterungen

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersecurity-Unternehmen**? Möchten Sie Ihr Unternehmen auf HackTricks bewerben? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks als PDF herunterladen**? Schauen Sie sich die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop) an!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere exklusive Sammlung von [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS und HackTricks Merch**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) **Discord-Gruppe** oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen Sie mir** auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Teilen Sie Ihre Hacking-Tricks, indem Sie einen PR an das** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **und das** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **senden**.

</details>

## Grundlegende Informationen

Kernelerweiterungen (Kexts) sind **Pakete** mit der Dateierweiterung **`.kext`**, die direkt in den macOS-Kernelraum geladen werden und dem Hauptbetriebssystem zusätzliche Funktionen bieten.

### Anforderungen

Offensichtlich ist dies so mächtig, dass es **kompliziert ist, eine Kernelerweiterung zu laden**. Dies sind die **Anforderungen**, die eine Kernelerweiterung erfüllen muss, um geladen zu werden:

* Beim **Starten des Wiederherstellungsmodus** müssen Kernelerweiterungen **zugelassen** werden:

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* Die Kernelerweiterung muss mit einem **Kernel-Code-Signaturzertifikat signiert** sein, das nur von Apple **erteilt** werden kann. Apple wird das Unternehmen und die Gründe, warum es benötigt wird, im Detail prüfen.
* Die Kernelerweiterung muss auch **notariell beglaubigt** sein, Apple kann sie auf Malware überprüfen.
* Dann ist der **Root-Benutzer** derjenige, der die Kernelerweiterung **laden** kann, und die Dateien im Paket müssen **root gehören**.
* Während des Upload-Vorgangs muss das Paket an einem **geschützten Nicht-Root-Speicherort** vorbereitet werden: `/Library/StagedExtensions` (erfordert die Berechtigung `com.apple.rootless.storage.KernelExtensionManagement`).
* Schließlich erhält der Benutzer beim Versuch, sie zu laden, eine [**Bestätigungsanfrage**](https://developer.apple.com/library/archive/technotes/tn2459/\_index.html) und wenn sie akzeptiert wird, muss der Computer **neu gestartet** werden, um sie zu laden.

### Ladevorgang

In Catalina war es so: Es ist interessant zu beachten, dass der **Überprüfungsprozess** in **Userland** stattfindet. Nur Anwendungen mit der Berechtigung **`com.apple.private.security.kext-management`** können den Kernel auffordern, eine Erweiterung zu laden: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** CLI **startet** den **Überprüfungsprozess** zum Laden einer Erweiterung
* Es wird über einen **Mach-Dienst** mit **`kextd`** kommunizieren.
2. **`kextd`** überprüft verschiedene Dinge wie die **Signatur**
* Es wird mit **`syspolicyd`** sprechen, um zu überprüfen, ob die Erweiterung geladen werden kann.
3. **`syspolicyd`** fordert den **Benutzer auf**, wenn die Erweiterung zuvor nicht geladen wurde.
* **`syspolicyd`** meldet das Ergebnis an **`kextd`**
4. **`kextd`** kann schließlich den Kernel **auffordern, die Erweiterung zu laden**

Wenn **`kextd`** nicht verfügbar ist, kann **`kextutil`** die gleichen Überprüfungen durchführen.

## Referenzen

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersecurity-Unternehmen**? Möchten Sie Ihr Unternehmen auf HackTricks bewerben? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks als PDF herunterladen**? Schauen Sie sich die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop) an!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere exklusive Sammlung von [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS und HackTricks Merch**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) **Discord-Gruppe** oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen Sie mir** auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Teilen Sie Ihre Hacking-Tricks, indem Sie einen PR an das** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **und das** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **senden**.

</details>
