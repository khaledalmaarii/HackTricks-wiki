# macOS Memory Dumping

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


## Memory Artifacts

### Swap Files

Swap datoteke, kao što je `/private/var/vm/swapfile0`, služe kao **keš kada je fizička memorija puna**. Kada više nema prostora u fizičkoj memoriji, njeni podaci se prebacuju u swap datoteku i zatim vraćaju u fizičku memoriju po potrebi. Mogu biti prisutne više swap datoteka, sa imenima kao što su swapfile0, swapfile1, i tako dalje.

### Hibernate Image

Datoteka koja se nalazi na `/private/var/vm/sleepimage` je ključna tokom **hibernacije**. **Podaci iz memorije se čuvaju u ovoj datoteci kada OS X hibernira**. Kada se računar probudi, sistem preuzima podatke iz memorije iz ove datoteke, omogućavajući korisniku da nastavi gde je stao.

Vredno je napomenuti da je na modernim MacOS sistemima ova datoteka obično enkriptovana iz bezbednosnih razloga, što otežava oporavak.

* Da biste proverili da li je enkripcija omogućena za sleepimage, može se pokrenuti komanda `sysctl vm.swapusage`. Ovo će pokazati da li je datoteka enkriptovana.

### Memory Pressure Logs

Još jedna važna datoteka vezana za memoriju u MacOS sistemima je **log memorijskog pritiska**. Ovi logovi se nalaze u `/var/log` i sadrže detaljne informacije o korišćenju memorije sistema i događajima pritiska. Mogu biti posebno korisni za dijagnostikovanje problema vezanih za memoriju ili razumevanje kako sistem upravlja memorijom tokom vremena.

## Dumping memory with osxpmem

Da biste dumpovali memoriju na MacOS mašini, možete koristiti [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Napomena**: Sledeće instrukcije će raditi samo za Mac računare sa Intel arhitekturom. Ovaj alat je sada arhiviran i poslednje izdanje je bilo 2017. Preuzeta binarna datoteka koristeći sledeće instrukcije cilja Intel čipove, jer Apple Silicon nije postojao 2017. Možda će biti moguće kompajlirati binarnu datoteku za arm64 arhitekturu, ali to ćete morati da probate sami.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Ako pronađete ovu grešku: `osxpmem.app/MacPmem.kext nije uspeo da se učita - (libkern/kext) neuspeh autentifikacije (vlasništvo/dozvole datoteke); proverite sistemske/kernel logove za greške ili pokušajte sa kextutil(8)` Možete to popraviti na sledeći način:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Druge greške** mogu biti ispravljene **dozvoljavanjem učitavanja kext-a** u "Bezbednost i privatnost --> Opšte", samo **dozvolite** to.

Možete takođe koristiti ovu **jednolinijsku komandu** da preuzmete aplikaciju, učitate kext i ispraznite memoriju:

{% code overflow="wrap" %}
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{% endcode %}


{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
