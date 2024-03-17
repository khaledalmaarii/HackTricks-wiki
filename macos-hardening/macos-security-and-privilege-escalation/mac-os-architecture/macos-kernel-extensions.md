# macOS Kernel-uitbreidings

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy vir 'n **sakeman in siber-sekuriteit**? Wil jy jou **sakeman geadverteer sien op HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons eksklusiewe versameling van [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS en HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) **Discord-groep** of die [**telegram-groep**](https://t.me/peass) of **volg my** op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Deel jou hacking-truuks deur 'n PR te stuur na** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Basiese Inligting

Kernel-uitbreidings (Kexts) is **pakkette** met 'n **`.kext`**-uitbreiding wat **direk in die macOS-kernelruimte gelaai word**, wat addisionele funksionaliteit aan die hoofbedryfstelsel bied.

### Vereistes

Dit is vanselfsprekend so kragtig dat dit **ingewikkeld is om 'n kernel-uitbreiding te laai**. Dit is die **vereistes** wat 'n kernel-uitbreiding moet nakom om gelaai te word:

* Wanneer jy **herstelmodus betree**, moet kernel-**uitbreidings toegelaat word** om gelaai te word:

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* Die kernel-uitbreiding moet **onderteken wees met 'n kernel-kodesertifikaat**, wat slegs deur Apple **toegeken kan word**. Hulle sal in detail die maatskappy en die redes waarom dit benodig word, ondersoek.
* Die kernel-uitbreiding moet ook **genoteer wees**, sodat Apple dit vir malware kan ondersoek.
* Dan is die **root**-gebruiker die een wat die kernel-uitbreiding kan **laai** en die lêers binne die pakkie moet aan **root** toebehoort.
* Tydens die oplaai-proses moet die pakkie voorberei word in 'n **beskermde nie-root-plek**: `/Library/StagedExtensions` (vereis die `com.apple.rootless.storage.KernelExtensionManagement` toekenning).
* Laastens, wanneer 'n poging gedoen word om dit te laai, sal die gebruiker 'n [**bevestigingsversoek ontvang**](https://developer.apple.com/library/archive/technotes/tn2459/\_index.html) en, indien aanvaar, moet die rekenaar **herlaai** word om dit te laai.

### Laaiproses

In Catalina was dit so: Dit is interessant om op te let dat die **verifikasieproses** in **gebruikersruimte** plaasvind. Tog kan slegs programme met die **`com.apple.private.security.kext-management`** toekenning die kernel nader om 'n uitbreiding te laai: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** kliek **begin** die **verifikasieproses** vir die laai van 'n uitbreiding
* Dit sal met **`kextd`** praat deur 'n **Mach-diens** te stuur.
2. **`kextd`** sal verskeie dinge nagaan, soos die **handtekening**
* Dit sal met **`syspolicyd`** praat om te **kontroleer** of die uitbreiding gelaai kan word.
3. **`syspolicyd`** sal die **gebruiker versoek** as die uitbreiding nie voorheen gelaai is nie.
* **`syspolicyd`** sal die resultaat aan **`kextd`** rapporteer
4. **`kextd`** sal uiteindelik die kernel kan sê om die uitbreiding te laai

As **`kextd`** nie beskikbaar is nie, kan **`kextutil`** dieselfde kontroles uitvoer.

## Verwysings

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy vir 'n **sakeman in siber-sekuriteit**? Wil jy jou **sakeman geadverteer sien op HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons eksklusiewe versameling van [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS en HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) **Discord-groep** of die [**telegram-groep**](https://t.me/peass) of **volg my** op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Deel jou hacking-truuks deur 'n PR te stuur na** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
