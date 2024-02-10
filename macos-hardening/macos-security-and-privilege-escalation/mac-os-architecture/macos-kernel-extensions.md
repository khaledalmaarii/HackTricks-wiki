# macOS Kernelni ekstenzije

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised on HackTricks**? Or do you want to have access to the **latest version of PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our exclusive collection of [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS and HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) **Discord group** or the [**telegram group**](https://t.me/peass) or **follow me** on **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Share your hacking tricks by sending PR to** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Osnovne informacije

Kernelne ekstenzije (Kexts) su **paketi** sa **`.kext`** ekstenzijom koji se **direktno učitavaju u macOS kernel prostor**, pružajući dodatne funkcionalnosti glavnom operativnom sistemu.

### Zahtevi

Očigledno, ovo je tako moćno da je **komplikovano učitati kernelnu ekstenziju**. Ovo su **zahtevi** koje kernelna ekstenzija mora ispuniti da bi se učitala:

* Kada se **ulazi u režim oporavka**, kernelne **ekstenzije moraju biti dozvoljene** za učitavanje:

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* Kernelna ekstenzija mora biti **potpisana kernelnim sertifikatom za potpisivanje koda**, koji može **dodeliti samo Apple**. Koja će detaljno pregledati kompaniju i razloge zašto je potrebna.
* Kernelna ekstenzija takođe mora biti **notarizovana**, Apple će je moći proveriti na prisustvo malvera.
* Zatim, **root** korisnik je taj koji može **učitati kernelnu ekstenziju** i fajlovi unutar paketa moraju **pripadati root-u**.
* Tokom procesa učitavanja, paket mora biti pripremljen na **zaštićenoj lokaciji bez root pristupa**: `/Library/StagedExtensions` (zahteva `com.apple.rootless.storage.KernelExtensionManagement` dozvolu).
* Na kraju, prilikom pokušaja učitavanja, korisnik će [**primiti zahtev za potvrdu**](https://developer.apple.com/library/archive/technotes/tn2459/\_index.html) i, ako ga prihvati, računar se mora **ponovo pokrenuti** da bi ga učitao.

### Proces učitavanja

U Catalini je bilo ovako: Zanimljivo je primetiti da se **proces verifikacije** dešava u **userland-u**. Međutim, samo aplikacije sa **`com.apple.private.security.kext-management`** dozvolom mogu **zatražiti od kernela da učita ekstenziju**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** komandna linija **pokreće** proces **verifikacije** za učitavanje ekstenzije
* Komuniciraće sa **`kextd`** slanjem poruke putem **Mach servisa**.
2. **`kextd`** će proveriti nekoliko stvari, kao što je **potpis**
* Komuniciraće sa **`syspolicyd`** da **proveri** da li se ekstenzija može **učitati**.
3. **`syspolicyd`** će **zatražiti** od **korisnika** potvrdu ako ekstenzija prethodno nije učitana.
* **`syspolicyd`** će prijaviti rezultat **`kextd`**-u
4. **`kextd`** će konačno moći da **kaže kernelu da učita** ekstenziju

Ako **`kextd`** nije dostupan, **`kextutil`** može izvršiti iste provere.

## References

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised on HackTricks**? Or do you want to have access to the **latest version of PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our exclusive collection of [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS and HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) **Discord group** or the [**telegram group**](https://t.me/peass) or **follow me** on **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live).
* **Share your hacking tricks by sending PR to** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
