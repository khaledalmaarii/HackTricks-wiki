# macOS Kerneluitbreidings

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy vir 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer op HackTricks**? Of wil jy toegang hê tot die **laaste weergawe van PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**SUBSKRIPSIEPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons eksklusiewe versameling van [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS- en HackTricks-uitrusting**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) **Discord-groep** of die [**telegram-groep**](https://t.me/peass) of **volg my** op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Deel jou hacking-truuks deur 'n PR te stuur na** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Basiese Inligting

Kerneluitbreidings (Kexts) is **pakette** met 'n **`.kext`**-uitbreiding wat **direk in die macOS-kernelruimte gelaai** word en addisionele funksionaliteit aan die hoof-bedryfstelsel bied.

### Vereistes

Dit is vanselfsprekend dat dit so kragtig is dat dit **moeilik is om 'n kerneluitbreiding te laai**. Hier is die **vereistes** wat 'n kerneluitbreiding moet nakom om gelaai te word:

* Wanneer jy **herstelmodus betree**, moet kernel-uitbreidings toegelaat word om gelaai te word:

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* Die kerneluitbreiding moet **onderteken wees met 'n kernel-kodesertifikaat**, wat slegs deur Apple **toegeken** kan word. Apple sal in detail die maatskappy en die redes waarom dit nodig is, ondersoek.
* Die kerneluitbreiding moet ook **genotariseer** word, sodat Apple dit vir malware kan ondersoek.
* Die **root**-gebruiker is die een wat die kerneluitbreiding kan laai en die lêers binne die pakkie moet aan **root** behoort.
* Tydens die oplaai-proses moet die pakkie voorberei word in 'n **beskermde nie-root-plek**: `/Library/StagedExtensions` (vereis die `com.apple.rootless.storage.KernelExtensionManagement` toekenning).
* Laastens, wanneer jy probeer om dit te laai, sal die gebruiker 'n [**bevestigingsversoek ontvang**](https://developer.apple.com/library/archive/technotes/tn2459/\_index.html) en, indien aanvaar, moet die rekenaar **herlaai** word om dit te laai.

### Laaiproses

In Catalina was dit so: Dit is interessant om op te merk dat die **verifikasieproses** in **userland** plaasvind. Slegs programme met die **`com.apple.private.security.kext-management`**-toekenning kan egter die kernel versoek om 'n uitbreiding te laai: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`**-opdraglyn **begin** die **verifikasieproses** vir die laai van 'n uitbreiding
* Dit sal met **`kextd`** praat deur gebruik te maak van 'n **Mach-diens**.
2. **`kextd`** sal verskeie dinge nagaan, soos die **handtekening**
* Dit sal met **`syspolicyd`** praat om te **kontroleer** of die uitbreiding gelaai kan word.
3. **`syspolicyd`** sal die **gebruiker versoek** as die uitbreiding nie voorheen gelaai is nie.
* **`syspolicyd`** sal die resultaat aan **`kextd`** rapporteer
4. **`kextd`** sal uiteindelik die kernel kan **instrueer om die uitbreiding te laai**

As **`kextd`** nie beskikbaar is nie, kan **`kextutil`** dieselfde kontroles uitvoer.

## Verwysings

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy vir 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer op HackTricks**? Of wil jy toegang hê tot die **laaste weergawe van PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**SUBSKRIPSIEPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons eksklusiewe versameling van [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS- en HackTricks-uitrusting**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) **Discord-groep** of die [**telegram-groep**](https://t.me/peass) of **volg my** op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Deel jou hacking-truuks deur 'n PR te stuur na** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
