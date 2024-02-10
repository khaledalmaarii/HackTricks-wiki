# macOS Seriennummer

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>


## Grundlegende Informationen

Apple-Geräte ab 2010 haben Seriennummern, die aus **12 alphanumerischen Zeichen** bestehen, wobei jeder Abschnitt spezifische Informationen übermittelt:

- **Erste 3 Zeichen**: Zeigen den **Herstellungsort** an.
- **Zeichen 4 & 5**: Kennzeichnen das **Jahr und die Woche der Herstellung**.
- **Zeichen 6 bis 8**: Dienen als **eindeutiger Identifikator** für jedes Gerät.
- **Letzte 4 Zeichen**: Spezifizieren die **Modellnummer**.

Beispielsweise folgt die Seriennummer **C02L13ECF8J2** dieser Struktur.

### **Herstellungsorte (Erste 3 Zeichen)**
Bestimmte Codes repräsentieren bestimmte Fabriken:
- **FC, F, XA/XB/QP/G8**: Verschiedene Standorte in den USA.
- **RN**: Mexiko.
- **CK**: Cork, Irland.
- **VM**: Foxconn, Tschechische Republik.
- **SG/E**: Singapur.
- **MB**: Malaysia.
- **PT/CY**: Korea.
- **EE/QT/UV**: Taiwan.
- **FK/F1/F2, W8, DL/DM, DN, YM/7J, 1C/4H/WQ/F7**: Unterschiedliche Standorte in China.
- **C0, C3, C7**: Bestimmte Städte in China.
- **RM**: Generalüberholte Geräte.

### **Herstellungsjahr (4. Zeichen)**
Dieses Zeichen variiert von 'C' (repräsentiert die erste Hälfte von 2010) bis 'Z' (zweite Hälfte von 2019), wobei verschiedene Buchstaben verschiedene Halbjahresperioden anzeigen.

### **Herstellungswoche (5. Zeichen)**
Die Ziffern 1-9 entsprechen den Wochen 1-9. Die Buchstaben C-Y (ohne Vokale und 'S') repräsentieren die Wochen 10-27. Für die zweite Hälfte des Jahres wird zu dieser Zahl 26 addiert.

### **Eindeutiger Identifikator (Zeichen 6 bis 8)**
Diese drei Ziffern stellen sicher, dass jedes Gerät, auch vom gleichen Modell und der gleichen Charge, eine eindeutige Seriennummer hat.

### **Modellnummer (Letzte 4 Zeichen)**
Diese Ziffern identifizieren das spezifische Modell des Geräts.

### Referenz

* [https://beetstech.com/blog/decode-meaning-behind-apple-serial-number](https://beetstech.com/blog/decode-meaning-behind-apple-serial-number)

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
