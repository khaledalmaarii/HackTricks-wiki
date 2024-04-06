# Kryptografische/Kompressionsalgorithmen

## Kryptografische/Kompressionsalgorithmen

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## Identifizierung von Algorithmen

Wenn Sie auf einen Code stoßen, der **Verschiebungen nach rechts und links, XORs und mehrere arithmetische Operationen** verwendet, ist es sehr wahrscheinlich, dass es sich um die Implementierung eines **kryptografischen Algorithmus** handelt. Hier werden einige Möglichkeiten gezeigt, wie der verwendete Algorithmus **ohne Umkehrung jedes Schritts identifiziert werden kann**.

### API-Funktionen

**CryptDeriveKey**

Wenn diese Funktion verwendet wird, können Sie herausfinden, welcher **Algorithmus verwendet wird**, indem Sie den Wert des zweiten Parameters überprüfen:

![](<../../.gitbook/assets/image (375) (1) (1) (1) (1).png>)

Hier finden Sie die Tabelle der möglichen Algorithmen und ihrer zugeordneten Werte: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Komprimiert und dekomprimiert einen gegebenen Datenpuffer.

**CryptAcquireContext**

Aus [den Dokumenten](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): Die Funktion **CryptAcquireContext** wird verwendet, um einen Handle für einen bestimmten Schlüsselcontainer innerhalb eines bestimmten kryptografischen Dienstanbieters (CSP) zu erhalten. **Dieses zurückgegebene Handle wird in Aufrufen von CryptoAPI-Funktionen verwendet**, die den ausgewählten CSP verwenden.

**CryptCreateHash**

Initiiert das Hashing eines Datenstroms. Wenn diese Funktion verwendet wird, können Sie herausfinden, welcher **Algorithmus verwendet wird**, indem Sie den Wert des zweiten Parameters überprüfen:

![](<../../.gitbook/assets/image (376).png>)

\
Hier finden Sie die Tabelle der möglichen Algorithmen und ihrer zugeordneten Werte: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Code-Konstanten

Manchmal ist es sehr einfach, einen Algorithmus zu identifizieren, da er einen speziellen und eindeutigen Wert verwenden muss.

![](<../../.gitbook/assets/image (370).png>)

Wenn Sie nach der ersten Konstante in Google suchen, erhalten Sie Folgendes:

![](<../../.gitbook/assets/image (371).png>)

Daher können Sie annehmen, dass die dekompilierte Funktion ein **SHA256-Rechner** ist.\
Sie können eine beliebige der anderen Konstanten suchen, und Sie erhalten (wahrscheinlich) das gleiche Ergebnis.

### Dateninformationen

Wenn der Code keine signifikante Konstante enthält, lädt er möglicherweise **Informationen aus dem .data-Abschnitt**.\
Sie können auf diese Daten zugreifen, **die erste Dword gruppieren** und in Google danach suchen, wie wir es im vorherigen Abschnitt getan haben:

![](<../../.gitbook/assets/image (372).png>)

In diesem Fall können Sie feststellen, dass **0xA56363C6** mit den **Tabellen des AES-Algorithmus** zusammenhängt, wenn Sie danach suchen.

## RC4 **(Symmetrische Verschlüsselung)**

### Eigenschaften

Es besteht aus 3 Hauptteilen:

* **Initialisierungsphase:** Erstellt eine **Tabelle von Werten von 0x00 bis 0xFF** (insgesamt 256 Bytes, 0x100). Diese Tabelle wird häufig als **Substitutionsbox** (oder SBox) bezeichnet.
* **Verwürfelungsphase:** Durchläuft die zuvor erstellte Tabelle (Schleife von 0x100 Iterationen, erneut) und modifiziert jeden Wert mit **halbzufälligen** Bytes. Um diese halbzufälligen Bytes zu erstellen, wird der RC4-**Schlüssel verwendet**. RC4-Schlüssel können **zwischen 1 und 256 Bytes lang sein**, es wird jedoch in der Regel empfohlen, dass er über 5 Bytes liegt. Üblicherweise sind RC4-Schlüssel 16 Bytes lang.
* **XOR-Phase:** Schließlich wird der Klartext oder der Chiffretext mit den zuvor erstellten Werten **XOR-verknüpft**. Die Funktion zum Verschlüsseln und Entschlüsseln ist dieselbe. Dazu wird eine **Schleife durch die erstellten 256 Bytes** so oft wie nötig durchgeführt. Dies wird in einem dekompilierten Code normalerweise mit einem **%256 (mod 256)** erkannt.

{% hint style="info" %}
**Um RC4 in einem Disassembly/dekompilierten Code zu identifizieren, können Sie nach 2 Schleifen der Größe 0x100 (mit Verwendung eines Schlüssels) und dann einem XOR der Eingabedaten mit den 256 zuvor erstellten Werten suchen, wahrscheinlich unter Verwendung eines %256 (mod 256)**
{% endhint %}

### **Initialisierungsphase/Substitutionsbox:** (Beachten Sie die Zahl 256 als Zähler und wie eine 0 an jeder Stelle der 256 Zeichen geschrieben wird)

![](<../../.gitbook/assets/image (377).png>)

### **Verwürfelungsphase:**

![](<../../.gitbook/assets/image (378).png>)

### **XOR-Phase:**

![](<../../.gitbook/assets/image (379).png>)

## **AES (Symmetrische Verschlüsselung)**

### **Eigenschaften**

* Verwendung von **Substitutionsboxen und Lookup-Tabellen**
* Es ist möglich, AES anhand der Verwendung bestimmter Lookup-Tabellenwerte (Konstanten) zu **unterscheiden**. Beachten Sie, dass die **Konstante** entweder im Binärformat **gespeichert** oder **dynamisch erstellt** werden kann.
* Der **Verschlüsselungsschlüssel** muss durch **16** (normalerweise 32B) **teilbar** sein, und in der Regel wird ein IV von 16B verwendet.

### SBox-Konstanten

![](<../../.gitbook/assets/image (380).png>)

## Serpent **(Symmetrische Verschlüsselung)**

### Eigenschaften

* Es ist selten, Malware zu finden, die es verwendet, aber es gibt Beispiele (Ursnif)
* Es ist einfach zu bestimmen, ob ein Algorithmus Serpent ist oder nicht, basierend auf seiner Länge (extrem lange Funktion)

### Identifizierung

Beachten Sie in dem folgenden Bild, wie die Konstante **0x9E3779B9** verwendet wird (beachten Sie, dass diese Konstante auch von anderen Kryptografiealgorithmen wie **TEA** - Tiny Encryption Algorithm verwendet wird).\
Beachten Sie auch die **Größe der Schleife** (**132**) und die **Anzahl der XOR-Operationen** in den **Disassembly-Anweisungen** und im **Codebeispiel**:

![](<../../.gitbook/assets/image (381).png>)

Wie bereits erwähnt, kann dieser Code in einem Dekompiler als **sehr lange Funktion** visualisiert werden, da es **keine Sprünge** darin gibt. Der dekompilierte Code kann wie folgt aussehen:

![](<../../.gitbook/assets/image (382).png>)

Daher ist es möglich, diesen Algorithmus zu identifizieren, indem Sie die **magische Zahl** und die **anfänglichen
## RSA **(Asymmetrische Verschlüsselung)**

### Eigenschaften

* Komplexer als symmetrische Algorithmen
* Es gibt keine Konstanten! (Benutzerdefinierte Implementierungen sind schwer zu bestimmen)
* KANAL (ein Kryptoanalysator) kann keine Hinweise auf RSA geben, da er auf Konstanten angewiesen ist.

### Identifizierung durch Vergleiche

![](<../../.gitbook/assets/image (383).png>)

* In Zeile 11 (links) gibt es `+7) >> 3`, was dem in Zeile 35 (rechts) entspricht: `+7) / 8`
* Zeile 12 (links) überprüft, ob `modulus_len < 0x040` und in Zeile 36 (rechts) wird überprüft, ob `inputLen+11 > modulusLen`

## MD5 & SHA (Hash)

### Eigenschaften

* 3 Funktionen: Init, Update, Final
* Ähnliche Initialisierungsfunktionen

### Identifizierung

**Init**

Sie können beide anhand der Konstanten identifizieren. Beachten Sie, dass sha\_init eine Konstante hat, die MD5 nicht hat:

![](<../../.gitbook/assets/image (385).png>)

**MD5 Transform**

Beachten Sie die Verwendung weiterer Konstanten

![](<../../.gitbook/assets/image (253) (1) (1) (1).png>)

## CRC (Hash)

* Kleiner und effizienter, da seine Funktion darin besteht, zufällige Änderungen in Daten zu finden
* Verwendet Lookup-Tabellen (damit können Konstanten identifiziert werden)

### Identifizierung

Überprüfen Sie **Lookup-Tabellenkonstanten**:

![](<../../.gitbook/assets/image (387).png>)

Ein CRC-Hash-Algorithmus sieht so aus:

![](<../../.gitbook/assets/image (386).png>)

## APLib (Kompression)

### Eigenschaften

* Nicht erkennbare Konstanten
* Sie können versuchen, den Algorithmus in Python zu schreiben und nach ähnlichen Dingen online zu suchen

### Identifizierung

Der Graph ist ziemlich groß:

![](<../../.gitbook/assets/image (207) (2) (1).png>)

Überprüfen Sie **3 Vergleiche, um ihn zu erkennen**:

![](<../../.gitbook/assets/image (384).png>)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder folgen Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>
