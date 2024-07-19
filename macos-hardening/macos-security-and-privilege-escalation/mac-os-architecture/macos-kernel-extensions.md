# macOS Kernel Extensions

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Osnovne informacije

Kernel ekstenzije (Kexts) su **paketi** sa **`.kext`** ekstenzijom koji se **učitavaju direktno u macOS kernel prostor**, pružajući dodatnu funkcionalnost glavnom operativnom sistemu.

### Zahtevi

Očigledno, ovo je toliko moćno da je **komplikovano učitati kernel ekstenziju**. Ovo su **zahtevi** koje kernel ekstenzija mora ispuniti da bi bila učitana:

* Kada se **ulazi u režim oporavka**, kernel **ekstenzije moraju biti dozvoljene** za učitavanje:

<figure><img src="../../../.gitbook/assets/image (327).png" alt=""><figcaption></figcaption></figure>

* Kernel ekstenzija mora biti **potpisana sa sertifikatom za potpisivanje kernel koda**, koji može biti **dodeljen samo od strane Apple-a**. Ko će detaljno pregledati kompaniju i razloge zašto je to potrebno.
* Kernel ekstenzija takođe mora biti **notarizovana**, Apple će moći da je proveri na malver.
* Zatim, **root** korisnik je taj koji može **učitati kernel ekstenziju** i datoteke unutar paketa moraju **pripadati root-u**.
* Tokom procesa učitavanja, paket mora biti pripremljen na **zaštićenoj lokaciji koja nije root**: `/Library/StagedExtensions` (zahteva `com.apple.rootless.storage.KernelExtensionManagement` dozvolu).
* Na kraju, kada se pokuša učitati, korisnik će [**dobiti zahtev za potvrdu**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) i, ako bude prihvaćen, računar mora biti **ponovo pokrenut** da bi se učitao.

### Proces učitavanja

U Catalina je to bilo ovako: Zanimljivo je napomenuti da se **proceso verifikacije** dešava u **userland-u**. Međutim, samo aplikacije sa **`com.apple.private.security.kext-management`** dozvolom mogu **zatražiti od kernela da učita ekstenziju**: `kextcache`, `kextload`, `kextutil`, `kextd`, `syspolicyd`

1. **`kextutil`** cli **pokreće** **proces verifikacije** za učitavanje ekstenzije
* Razgovaraće sa **`kextd`** slanjem putem **Mach servisa**.
2. **`kextd`** će proveriti nekoliko stvari, kao što su **potpis**
* Razgovaraće sa **`syspolicyd`** da bi **proverio** da li se ekstenzija može **učitati**.
3. **`syspolicyd`** će **pitati** **korisnika** ako ekstenzija nije prethodno učitana.
* **`syspolicyd`** će izvestiti rezultat **`kextd`**
4. **`kextd`** će konačno moći da **kaže kernelu da učita** ekstenziju

Ako **`kextd`** nije dostupan, **`kextutil`** može izvršiti iste provere.

## Reference

* [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
* [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
