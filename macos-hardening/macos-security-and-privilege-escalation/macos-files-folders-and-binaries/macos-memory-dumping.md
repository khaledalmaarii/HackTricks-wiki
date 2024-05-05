# Dumpovanje memorije macOS-a

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) je **dark-web** pretraživač koji nudi **besplatne** funkcionalnosti za proveru da li je kompanija ili njeni korisnici **kompromitovani** od strane **stealer malvera**.

Primarni cilj WhiteIntel-a je borba protiv preuzimanja naloga i napada ransomware-a koji proizilaze iz malvera za krađu informacija.

Možete posetiti njihovu veb lokaciju i isprobati njihovu mašinu za **besplatno** na:

{% embed url="https://whiteintel.io" %}

***

## Memorijalni artefakti

### Fajlovi zamene

Fajlovi zamene, poput `/private/var/vm/swapfile0`, služe kao **keš kada je fizička memorija puna**. Kada više nema mesta u fizičkoj memoriji, njeni podaci se prenose u fajl zamene, a zatim se po potrebi vraćaju u fizičku memoriju. Mogu biti prisutni više fajlova zamene, sa imenima poput swapfile0, swapfile1, i tako dalje.

### Hibernate slika

Fajl koji se nalazi na lokaciji `/private/var/vm/sleepimage` je ključan tokom **režima hibernacije**. **Podaci iz memorije se čuvaju u ovom fajlu kada OS X hibernira**. Po buđenju računara, sistem povlači podatke iz memorije iz ovog fajla, omogućavajući korisniku da nastavi gde je stao.

Važno je napomenuti da je na modernim MacOS sistemima ovaj fajl obično enkriptovan iz sigurnosnih razloga, što otežava oporavak.

* Da biste proverili da li je enkripcija omogućena za sleepimage, može se pokrenuti komanda `sysctl vm.swapusage`. Ovo će pokazati da li je fajl enkriptovan.

### Logovi pritiska na memoriju

Još jedan važan fajl povezan sa memorijom u MacOS sistemima su **logovi pritiska na memoriju**. Ovi logovi se nalaze u `/var/log` i sadrže detaljne informacije o korišćenju memorije sistema i događajima pritiska na memoriju. Mogu biti posebno korisni za dijagnostikovanje problema povezanih sa memorijom ili razumevanje kako sistem upravlja memorijom tokom vremena.

## Dumpovanje memorije pomoću osxpmem

Da biste dumpovali memoriju na MacOS računaru možete koristiti [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Napomena**: Sledeće instrukcije će raditi samo za Mac računare sa Intel arhitekturom. Ovaj alat je sada arhiviran, a poslednje izdanje je bilo 2017. Binarni fajl preuzet korišćenjem instrukcija ispod cilja Intel čipove jer Apple Silicon nije postojao 2017. Moguće je da je moguće kompajlirati binarni fajl za arm64 arhitekturu, ali ćete morati sami da probate.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Ako pronađete ovu grešku: `osxpmem.app/MacPmem.kext nije uspeo da se učita - (libkern/kext) autentikacija nije uspela (vlasništvo/datoteke/dozvole); proverite sistemske/kernel dnevnike za greške ili pokušajte kextutil(8)` Možete je popraviti tako što ćete:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Drugi problemi** mogu biti rešeni **omogućavanjem učitavanja kext-a** u "Sigurnost i privatnost --> Opšte", jednostavno ga **omogućite**.

Takođe možete koristiti ovaj **oneliner** da preuzmete aplikaciju, učitate kext i izvršite dump memorije:

{% code overflow="wrap" %}
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{% endcode %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) je pretraživač pokrenut na **dark webu** koji nudi **besplatne** funkcionalnosti za proveru da li je kompanija ili njeni korisnici **ugroženi** od **malvera koji krade informacije**.

Njihov primarni cilj WhiteIntela je borba protiv preuzimanja naloga i napada ransomvera koji proizilaze iz malvera koji krade informacije.

Možete posetiti njihovu veb lokaciju i isprobati njihovu mašinu za **besplatno** na:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJATELJSTVO**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
