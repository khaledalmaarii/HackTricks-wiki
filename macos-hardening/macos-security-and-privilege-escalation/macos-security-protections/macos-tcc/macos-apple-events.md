# macOS Apple Events

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Basiese Inligting

**Apple Events** is 'n kenmerk in Apple se macOS wat toelaat dat toepassings met mekaar kommunikeer. Dit is deel van die **Apple Event Manager**, wat 'n komponent van die macOS bedryfstelsel is wat verantwoordelik is vir die hantering van interproseskommunikasie. Hierdie stelsel stel een toepassing in staat om 'n boodskap aan 'n ander toepassing te stuur om te vra dat dit 'n spesifieke operasie uitvoer, soos om 'n lêer te open, data te verkry, of 'n opdrag uit te voer.

Die mina daemon is `/System/Library/CoreServices/appleeventsd` wat die diens `com.apple.coreservices.appleevents` registreer.

Elke toepassing wat gebeurtenisse kan ontvang, sal met hierdie daemon nagaan deur sy Apple Event Mach Port te verskaf. En wanneer 'n app 'n gebeurtenis na dit wil stuur, sal die app hierdie poort van die daemon aan vra.

Sandboxed toepassings vereis voorregte soos `allow appleevent-send` en `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` om in staat te wees om gebeurtenisse te stuur. Let daarop dat regte soos `com.apple.security.temporary-exception.apple-events` kan beperk wie toegang het om gebeurtenisse te stuur wat regte soos `com.apple.private.appleevents` sal benodig.

{% hint style="success" %}
Dit is moontlik om die omgevariable **`AEDebugSends`** te gebruik om inligting oor die gestuurde boodskap te log:
```bash
AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
```
{% endhint %}

{% hint style="success" %}
Leer en oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer en oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
