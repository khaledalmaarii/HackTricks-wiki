# Bewaffnung von Distroless

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## Was ist Distroless

Ein Distroless-Container ist ein Container-Typ, der nur die erforderlichen Abhängigkeiten zum Ausführen einer bestimmten Anwendung enthält, ohne zusätzliche Software oder Tools, die nicht erforderlich sind. Diese Container sind darauf ausgelegt, so leichtgewichtig und sicher wie möglich zu sein und die Angriffsfläche zu minimieren, indem sie unnötige Komponenten entfernen.

Distroless-Container werden häufig in Produktionsumgebungen eingesetzt, in denen Sicherheit und Zuverlässigkeit oberste Priorität haben.

Einige **Beispiele** für **Distroless-Container** sind:

* Bereitgestellt von **Google**: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
* Bereitgestellt von **Chainguard**: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Bewaffnung von Distroless

Das Ziel der Bewaffnung eines Distroless-Containers besteht darin, beliebige Binärdateien und Payloads auszuführen, auch unter Berücksichtigung der Einschränkungen von Distroless (Fehlen gängiger Binärdateien im System) und der in Containern häufig vorkommenden Schutzmechanismen wie **Read-Only** oder **No-Execute** in `/dev/shm`.

### Über den Speicher

Kommt irgendwann 2023...

### Über vorhandene Binärdateien

#### openssl

****[**In diesem Beitrag**](https://www.form3.tech/engineering/content/exploiting-distroless-images) wird erklärt, dass die Binärdatei **`openssl`** häufig in diesen Containern zu finden ist, möglicherweise weil sie von der Software benötigt wird, die innerhalb des Containers ausgeführt wird.

Durch Missbrauch der **`openssl`**-Binärdatei ist es möglich, beliebige Dinge auszuführen.

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
