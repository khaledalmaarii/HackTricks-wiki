# Kryptografische/Kompressionsalgorithmen

## Kryptografische/Kompressionsalgorithmen

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

## Identifizierung von Algorithmen

Wenn Sie auf einen Code stoßen, der **Verschiebungen nach rechts und links, XORs und mehrere arithmetische Operationen** verwendet, ist es sehr wahrscheinlich, dass es sich um die Implementierung eines **kryptografischen Algorithmus** handelt. Hier werden einige Möglichkeiten gezeigt, um **den verwendeten Algorithmus zu identifizieren, ohne jeden Schritt umkehren zu müssen**.

### API-Funktionen

**CryptDeriveKey**

Wenn diese Funktion verwendet wird, können Sie herausfinden, welcher **Algorithmus verwendet wird**, indem Sie den Wert des zweiten Parameters überprüfen:

![](<../../.gitbook/assets/image (156).png>)

Überprüfen Sie hier die Tabelle möglicher Algorithmen und ihrer zugewiesenen Werte: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Komprimiert und dekomprimiert einen gegebenen Datenpuffer.

**CryptAcquireContext**

Aus [den Dokumenten](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): Die Funktion **CryptAcquireContext** wird verwendet, um einen Handle auf einen bestimmten Schlüsselcontainer innerhalb eines bestimmten kryptografischen Dienstanbieters (CSP) zu erhalten. **Dieses zurückgegebene Handle wird in Aufrufen von CryptoAPI-Funktionen verwendet**, die den ausgewählten CSP verwenden.

**CryptCreateHash**

Initiiert das Hashing eines Datenstroms. Wenn diese Funktion verwendet wird, können Sie herausfinden, welcher **Algorithmus verwendet wird**, indem Sie den Wert des zweiten Parameters überprüfen:

![](<../../.gitbook/assets/image (549).png>)

Überprüfen Sie hier die Tabelle möglicher Algorithmen und ihrer zugewiesenen Werte: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Konstanten im Code

Manchmal ist es wirklich einfach, einen Algorithmus zu identifizieren, da er einen speziellen und eindeutigen Wert verwenden muss.

![](<../../.gitbook/assets/image (833).png>)

Wenn Sie nach der ersten Konstanten in Google suchen, erhalten Sie Folgendes:

![](<../../.gitbook/assets/image (529).png>)

Daher können Sie annehmen, dass die dekompilierte Funktion ein **sha256-Rechner** ist.\
Sie können eine beliebige der anderen Konstanten suchen und wahrscheinlich dasselbe Ergebnis erhalten.

### Dateninformationen

Wenn der Code keine signifikante Konstante enthält, lädt er möglicherweise **Informationen aus dem .data-Abschnitt**.\
Sie können auf diese Daten zugreifen, **das erste Dword gruppieren** und danach in Google suchen, wie wir es im vorherigen Abschnitt getan haben:

![](<../../.gitbook/assets/image (531).png>)

In diesem Fall, wenn Sie nach **0xA56363C6** suchen, können Sie feststellen, dass es mit den **Tabellen des AES-Algorithmus** zusammenhängt.

## RC4 **(Symmetrische Verschlüsselung)**

### Eigenschaften

Er besteht aus 3 Hauptteilen:

* **Initialisierungsphase/**: Erstellt eine **Tabelle von Werten von 0x00 bis 0xFF** (insgesamt 256 Bytes, 0x100). Diese Tabelle wird normalerweise als **Substitutionsbox** (oder SBox) bezeichnet.
* **Verwürfelungsphase**: Wird durch die zuvor erstellte Tabelle durchlaufen (Schleife von 0x100 Iterationen, erneut) und modifiziert jeden Wert mit **halbzufälligen** Bytes. Um diese halbzufälligen Bytes zu erstellen, wird der RC4-**Schlüssel verwendet**. RC4-**Schlüssel** können **zwischen 1 und 256 Bytes lang sein**, es wird jedoch in der Regel empfohlen, dass er über 5 Bytes liegt. Üblicherweise sind RC4-Schlüssel 16 Bytes lang.
* **XOR-Phase**: Schließlich wird der Klartext oder der Geheimtext mit den zuvor erstellten Werten **XOR-verknüpft**. Die Funktion zum Verschlüsseln und Entschlüsseln ist dieselbe. Dafür wird eine **Schleife durch die erstellten 256 Bytes** so oft wie nötig durchgeführt. Dies wird in einem dekompilierten Code normalerweise mit einem **%256 (mod 256)** erkannt.

{% hint style="info" %}
**Um einen RC4 in einem Disassemblierungs-/dekompilierten Code zu identifizieren, können Sie nach 2 Schleifen der Größe 0x100 (mit Verwendung eines Schlüssels) suchen und dann ein XOR der Eingabedaten mit den 256 zuvor erstellten Werten in den 2 Schleifen wahrscheinlich unter Verwendung eines %256 (mod 256)**
{% endhint %}

### **Initialisierungsphase/Substitutionsbox:** (Beachten Sie die Zahl 256 als Zähler und wie eine 0 an jeder Stelle der 256 Zeichen geschrieben wird)

![](<../../.gitbook/assets/image (584).png>)

### **Verwürfelungsphase:**

![](<../../.gitbook/assets/image (835).png>)

### **XOR-Phase:**

![](<../../.gitbook/assets/image (904).png>)

## **AES (Symmetrische Verschlüsselung)**

### **Eigenschaften**

* Verwendung von **Substitutionsboxen und Lookup-Tabellen**
* Es ist möglich, AES anhand der Verwendung spezifischer Lookup-Tabellenwerte (Konstanten) zu **unterscheiden**. _Beachten Sie, dass die **Konstante** im Binärformat **gespeichert** oder **dynamisch erstellt** werden kann._
* Der **Verschlüsselungsschlüssel** muss durch **16 teilbar** sein (normalerweise 32 Byte) und normalerweise wird ein **IV** von 16 Byte verwendet.

### SBox-Konstanten

![](<../../.gitbook/assets/image (208).png>)

## Serpent **(Symmetrische Verschlüsselung)**

### Eigenschaften

* Es ist selten, Malware zu finden, die es verwendet, aber es gibt Beispiele (Ursnif)
* Es ist einfach zu bestimmen, ob ein Algorithmus Serpent ist oder nicht, basierend auf seiner Länge (extrem lange Funktion)

### Identifizierung

Beachten Sie in folgendem Bild, wie die Konstante **0x9E3779B9** verwendet wird (beachten Sie, dass diese Konstante auch von anderen Kryptoalgorithmen wie **TEA** -Tiny Encryption Algorithm verwendet wird).\
Beachten Sie auch die **Größe der Schleife** (**132**) und die **Anzahl der XOR-Operationen** in den **Disassemblierungsanweisungen** und im **Code**-Beispiel:

![](<../../.gitbook/assets/image (547).png>)

Wie bereits erwähnt, kann dieser Code in einem Dekompiler als **sehr lange Funktion** dargestellt werden, da es darin **keine Sprünge** gibt. Der dekompilierte Code kann wie folgt aussehen:

![](<../../.gitbook/assets/image (513).png>)

Daher ist es möglich, diesen Algorithmus zu identifizieren, indem Sie die **Magische Zahl** und die **anfänglichen XORs** überprüfen, eine **sehr lange Funktion** sehen und einige **Anweisungen** der langen Funktion **mit einer Implementierung vergleichen** (wie dem Linksschieben um 7 und dem Linksrotieren um 22).
## RSA **(Asymmetrische Verschlüsselung)**

### Eigenschaften

* Komplexer als symmetrische Algorithmen
* Es gibt keine Konstanten! (Benutzerdefinierte Implementierungen sind schwer zu bestimmen)
* KANAL (ein Kryptoanalysator) zeigt keine Hinweise auf RSA, da es auf Konstanten angewiesen ist.

### Identifizierung durch Vergleiche

![](<../../.gitbook/assets/image (1113).png>)

* In Zeile 11 (links) gibt es ein `+7) >> 3`, das dem in Zeile 35 (rechts) entspricht: `+7) / 8`
* Zeile 12 (links) überprüft, ob `modulus_len < 0x040` ist, und in Zeile 36 (rechts) wird überprüft, ob `inputLen+11 > modulusLen`

## MD5 & SHA (Hash)

### Eigenschaften

* 3 Funktionen: Init, Update, Final
* Ähnliche Initialisierungsfunktionen

### Identifizieren

**Init**

Sie können beide identifizieren, indem Sie die Konstanten überprüfen. Beachten Sie, dass sha\_init eine Konstante hat, die MD5 nicht hat:

![](<../../.gitbook/assets/image (406).png>)

**MD5 Transformieren**

Beachten Sie die Verwendung von mehr Konstanten

![](<../../.gitbook/assets/image (253) (1) (1).png>)

## CRC (Hash)

* Kleiner und effizienter, da seine Funktion darin besteht, zufällige Änderungen in Daten zu finden
* Verwendet Suchtabellen (damit Sie Konstanten identifizieren können)

### Identifizieren

Überprüfen Sie **Suchtabellenkonstanten**:

![](<../../.gitbook/assets/image (508).png>)

Ein CRC-Hash-Algorithmus sieht so aus:

![](<../../.gitbook/assets/image (391).png>)

## APLib (Kompression)

### Eigenschaften

* Nicht erkennbare Konstanten
* Sie können versuchen, den Algorithmus in Python zu schreiben und nach ähnlichen Dingen online zu suchen

### Identifizieren

Der Graph ist ziemlich groß:

![](<../../.gitbook/assets/image (207) (2) (1).png>)

Überprüfen Sie **3 Vergleiche, um es zu erkennen**:

![](<../../.gitbook/assets/image (430).png>)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
