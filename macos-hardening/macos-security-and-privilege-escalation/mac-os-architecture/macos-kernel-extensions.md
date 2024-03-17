# macOS Kernelerweiterungen

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen auf HackTricks beworben sehen**? Oder möchten Sie Zugang zur **neuesten Version von PEASS erhalten oder HackTricks als PDF herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere exklusive Sammlung von [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das offizielle [**PEASS und HackTricks Merch**](https://peass.creator-spring.com)
* **Treten Sie dem** [**💬**](https://emojipedia.org/speech-balloon/) **Discord-Gruppe bei** oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen Sie mir** auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PR an das** [**hacktricks-Repository**](https://github.com/carlospolop/hacktricks) **und das** [**hacktricks-cloud-Repository**](https://github.com/carlospolop/hacktricks-cloud) **senden**.

</details>

## Grundlegende Informationen

Kernelerweiterungen (Kexts) sind **Pakete** mit der Erweiterung **`.kext`**, die **direkt in den macOS-Kernelraum geladen** werden und dem Hauptbetriebssystem zusätzliche Funktionen bieten.

### Anforderungen

Offensichtlich ist dies so mächtig, dass es **kompliziert ist, eine Kernelerweiterung zu laden**. Dies sind die **Anforderungen**, die eine Kernelerweiterung erfüllen muss, um geladen zu werden:

* Beim **Betreten des Wiederherstellungsmodus** müssen Kernelerweiterungen **zugelassen sein**, um geladen zu werden:

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* Die Kernelerweiterung muss mit einem Kernelcodesignaturzertifikat **signiert** sein, das nur von **Apple** erteilt werden kann. Wer wird das Unternehmen und die Gründe, warum es benötigt wird, im Detail überprüfen.
* Die Kernelerweiterung muss auch **notariell beglaubigt** sein, damit Apple sie auf Malware überprüfen kann.
* Dann ist der **Root**-Benutzer derjenige, der die Kernelerweiterung **laden kann**, und die Dateien im Paket müssen **Root gehören**.
* Während des Upload-Vorgangs muss das Paket an einem **geschützten Nicht-Root-Standort** vorbereitet werden: `/Library/StagedExtensions` (erfordert die Berechtigung `com.apple.rootless.storage.KernelExtensionManagement`).
* Schließlich wird der Benutzer beim Versuch, sie zu laden, eine [**Bestätigungsanfrage erhalten**](https://developer.apple.com/library/archive/technotes/tn2459/\_index.html) und, wenn akzeptiert, muss der Computer neu gestartet werden, um sie zu laden.

### Ladevorgang

In Catalina war es so: Es ist interessant festzustellen, dass der **Überprüfungsprozess** in **Benutzerland** stattfindet. Nur Anwendungen mit der Berechtigung **`com.apple.private.security.kext-management`** können den Kernel auffordern, eine Erweiterung zu laden: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **startet** den **Überprüfungsprozess** zum Laden einer Erweiterung
* Es wird mit **`kextd`** sprechen, indem es einen **Mach-Dienst** verwendet.
2. **`kextd`** wird verschiedene Dinge überprüfen, wie die **Signatur**
* Es wird mit **`syspolicyd`** sprechen, um zu **überprüfen**, ob die Erweiterung geladen werden kann.
3. **`syspolicyd`** wird den **Benutzer auffordern**, wenn die Erweiterung nicht zuvor geladen wurde.
* **`syspolicyd`** wird das Ergebnis an **`kextd`** melden
4. **`kextd`** kann schließlich den Kernel auffordern, die Erweiterung zu laden

Wenn **`kextd`** nicht verfügbar ist, kann **`kextutil`** die gleichen Überprüfungen durchführen.

## Referenzen

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen auf HackTricks beworben sehen**? Oder möchten Sie Zugang zur **neuesten Version von PEASS erhalten oder HackTricks als PDF herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere exklusive Sammlung von [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das offizielle [**PEASS und HackTricks Merch**](https://peass.creator-spring.com)
* **Treten Sie dem** [**💬**](https://emojipedia.org/speech-balloon/) **Discord-Gruppe bei** oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen Sie mir** auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PR an das** [**hacktricks-Repository**](https://github.com/carlospolop/hacktricks) **und das** [**hacktricks-cloud-Repository**](https://github.com/carlospolop/hacktricks-cloud) **senden**.

</details>
