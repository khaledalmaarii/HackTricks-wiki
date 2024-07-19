# macOS Kernel Extensions

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PR's in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Basiese Inligting

Kernel uitbreidings (Kexts) is **pakkette** met 'n **`.kext`** uitbreiding wat **direk in die macOS kernel ruimte gelaai word**, wat addisionele funksionaliteit aan die hoofbedryfstelsel bied.

### Vereistes

Dit is duidelik dat dit so kragtig is dat dit **gekompliseerd is om 'n kernel uitbreiding te laai**. Dit is die **vereistes** waaraan 'n kernel uitbreiding moet voldoen om gelaai te kan word:

* Wanneer **jy herstelmodus binnegaan**, moet kernel **uitbreidings toegelaat word** om gelaai te word:

<figure><img src="../../../.gitbook/assets/image (327).png" alt=""><figcaption></figcaption></figure>

* Die kernel uitbreiding moet **onderteken wees met 'n kernel kode ondertekeningssertifikaat**, wat slegs **deur Apple** toegestaan kan word. Wie die maatskappy en die redes waarom dit nodig is, in detail sal hersien.
* Die kernel uitbreiding moet ook **genotarieer** wees, Apple sal dit vir malware kan nagaan.
* Dan is die **root** gebruiker die een wat die **kernel uitbreiding kan laai** en die lêers binne die pakkie moet **aan root behoort**.
* Tydens die oplaadproses moet die pakkie in 'n **beskermde nie-root ligging** voorberei word: `/Library/StagedExtensions` (vereis die `com.apple.rootless.storage.KernelExtensionManagement` toestemming).
* Laastens, wanneer daar probeer word om dit te laai, sal die gebruiker [**'n bevestigingsversoek ontvang**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) en, indien aanvaar, moet die rekenaar **herbegin** word om dit te laai.

### Laai proses

In Catalina was dit soos volg: Dit is interessant om op te let dat die **verifikasie** proses in **gebruikersland** plaasvind. Dit is egter slegs toepassings met die **`com.apple.private.security.kext-management`** toestemming wat **die kernel kan vra om 'n uitbreiding te laai**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **begin** die **verifikasie** proses om 'n uitbreiding te laai
* Dit sal met **`kextd`** praat deur 'n **Mach diens** te gebruik.
2. **`kextd`** sal verskeie dinge nagaan, soos die **handtekening**
* Dit sal met **`syspolicyd`** praat om te **kontroleer** of die uitbreiding gelaai kan word.
3. **`syspolicyd`** sal die **gebruiker** **vra** of die uitbreiding nie voorheen gelaai is nie.
* **`syspolicyd`** sal die resultaat aan **`kextd`** rapporteer
4. **`kextd`** sal uiteindelik in staat wees om die kernel te **vertel om** die uitbreiding te laai

As **`kextd`** nie beskikbaar is nie, kan **`kextutil`** dieselfde kontroles uitvoer.

## Verwysings

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PR's in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
