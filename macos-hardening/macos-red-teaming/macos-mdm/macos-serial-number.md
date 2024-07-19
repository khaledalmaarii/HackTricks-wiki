# macOS Seriennummer

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


## Grundinformationen

Apple-Geräte nach 2010 haben Seriennummern, die aus **12 alphanumerischen Zeichen** bestehen, wobei jedes Segment spezifische Informationen vermittelt:

- **Erste 3 Zeichen**: Geben den **Herstellungsort** an.
- **Zeichen 4 & 5**: Bezeichnen das **Jahr und die Woche der Herstellung**.
- **Zeichen 6 bis 8**: Dienen als **eindeutiger Identifikator** für jedes Gerät.
- **Letzte 4 Zeichen**: Geben die **Modellnummer** an.

Zum Beispiel folgt die Seriennummer **C02L13ECF8J2** dieser Struktur.

### **Herstellungsorte (Erste 3 Zeichen)**
Bestimmte Codes repräsentieren spezifische Fabriken:
- **FC, F, XA/XB/QP/G8**: Verschiedene Standorte in den USA.
- **RN**: Mexiko.
- **CK**: Cork, Irland.
- **VM**: Foxconn, Tschechische Republik.
- **SG/E**: Singapur.
- **MB**: Malaysia.
- **PT/CY**: Korea.
- **EE/QT/UV**: Taiwan.
- **FK/F1/F2, W8, DL/DM, DN, YM/7J, 1C/4H/WQ/F7**: Verschiedene Standorte in China.
- **C0, C3, C7**: Bestimmte Städte in China.
- **RM**: Überholte Geräte.

### **Jahr der Herstellung (4. Zeichen)**
Dieses Zeichen variiert von 'C' (repräsentiert die erste Hälfte von 2010) bis 'Z' (zweite Hälfte von 2019), wobei verschiedene Buchstaben unterschiedliche Halbjahresperioden anzeigen.

### **Woche der Herstellung (5. Zeichen)**
Ziffern 1-9 entsprechen den Wochen 1-9. Buchstaben C-Y (ohne Vokale und 'S') repräsentieren die Wochen 10-27. Für die zweite Hälfte des Jahres wird 26 zu dieser Zahl addiert.

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
