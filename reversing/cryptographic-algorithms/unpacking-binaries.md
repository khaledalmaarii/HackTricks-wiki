{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}


# Identifizierung gepackter Binaries

* **Mangel an Strings**: Es ist üblich, dass gepackte Binaries fast keine Strings haben.
* Viele **ungenutzte Strings**: Wenn Malware einen kommerziellen Packer verwendet, findet man oft viele Strings ohne Querverweise. Selbst wenn diese Strings existieren, bedeutet das nicht, dass die Binary nicht gepackt ist.
* Du kannst auch einige Tools verwenden, um herauszufinden, welcher Packer verwendet wurde, um eine Binary zu packen:
* [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
* [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
* [Language 2000](http://farrokhi.net/language/)

# Grundlegende Empfehlungen

* **Beginne** mit der Analyse der gepackten Binary **von unten in IDA und arbeite nach oben**. Unpacker beenden, sobald der entpackte Code endet, daher ist es unwahrscheinlich, dass der Unpacker die Ausführung an den entpackten Code zu Beginn übergibt.
* Suche nach **JMPs** oder **CALLs** zu **Registern** oder **Speicherbereichen**. Suche auch nach **Funktionen, die Argumente und eine Adressrichtung pushen und dann `retn` aufrufen**, da die Rückkehr der Funktion in diesem Fall die Adresse aufrufen kann, die zuvor auf den Stack gepusht wurde.
* Setze einen **Breakpoint** auf `VirtualAlloc`, da dies Speicher im RAM allokiert, wo das Programm entpackten Code schreiben kann. "Lauf zu Benutzercode" oder benutze F8, um **den Wert in EAX zu erhalten**, nachdem die Funktion ausgeführt wurde und "**folge dieser Adresse im Dump**". Du weißt nie, ob das der Bereich ist, in dem der entpackte Code gespeichert wird.
* **`VirtualAlloc`** mit dem Wert "**40**" als Argument bedeutet Lesen+Schreiben+Ausführen (einige Code, der ausgeführt werden muss, wird hier kopiert).
* **Während des Entpackens** von Code ist es normal, **mehrere Aufrufe** zu **arithmetischen Operationen** und Funktionen wie **`memcopy`** oder **`Virtual`**`Alloc` zu finden. Wenn du dich in einer Funktion befindest, die anscheinend nur arithmetische Operationen und vielleicht einige `memcopy` durchführt, ist die Empfehlung, zu versuchen, **das Ende der Funktion zu finden** (vielleicht ein JMP oder ein Aufruf zu einem Register) **oder** zumindest den **Aufruf zur letzten Funktion** und dann dorthin zu laufen, da der Code nicht interessant ist.
* Während des Entpackens von Code **beachte**, wann du **den Speicherbereich änderst**, da eine Änderung des Speicherbereichs den **Beginn des Entpackungscodes** anzeigen kann. Du kannst einen Speicherbereich einfach mit Process Hacker dumpen (Prozess --> Eigenschaften --> Speicher).
* Während du versuchst, Code zu entpacken, ist eine gute Möglichkeit zu **wissen, ob du bereits mit dem entpackten Code arbeitest** (damit du ihn einfach dumpen kannst), die **Strings der Binary zu überprüfen**. Wenn du zu einem bestimmten Zeitpunkt einen Sprung machst (vielleicht den Speicherbereich änderst) und bemerkst, dass **viele mehr Strings hinzugefügt wurden**, dann kannst du wissen, **dass du mit dem entpackten Code arbeitest**.\
Wenn der Packer jedoch bereits viele Strings enthält, kannst du sehen, wie viele Strings das Wort "http" enthalten und überprüfen, ob diese Zahl steigt.
* Wenn du eine ausführbare Datei aus einem Speicherbereich dumpst, kannst du einige Header mit [PE-bear](https://github.com/hasherezade/pe-bear-releases/releases) reparieren.
