# Dumpovanje memorije macOS-a

{% hint style="success" %}
Naučite i vežbajte hakovanje AWS-a:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Obuka AWS Crveni Tim Stručnjak (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Obuka GCP Crveni Tim Stručnjak (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Pomozite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) je pretraživač pokretan **dark web-om** koji nudi **besplatne** funkcionalnosti za proveru da li je kompanija ili njeni korisnici **kompromitovani** od strane **kradljivih malvera**.

Primarni cilj WhiteIntela je borba protiv preuzimanja naloga i napada ransomware-a koji proizilaze iz malvera za krađu informacija.

Možete posetiti njihovu veb lokaciju i isprobati njihovu mašinu za **besplatno** na:

{% embed url="https://whiteintel.io" %}

***

## Memorijalni artefakti

### Fajlovi zamene

Fajlovi zamene, poput `/private/var/vm/swapfile0`, služe kao **keš kada je fizička memorija puna**. Kada više nema mesta u fizičkoj memoriji, njeni podaci se prenose u fajl zamene, a zatim se po potrebi vraćaju u fizičku memoriju. Mogu biti prisutni više fajlova zamene, sa imenima poput swapfile0, swapfile1, i tako dalje.

### Hibernate slika

Fajl koji se nalazi na lokaciji `/private/var/vm/sleepimage` je ključan tokom **režima hibernacije**. **Podaci iz memorije se čuvaju u ovom fajlu kada OS X hibernira**. Po buđenju računara, sistem preuzima podatke iz memorije iz ovog fajla, omogućavajući korisniku da nastavi gde je stao.

Važno je napomenuti da je na modernim MacOS sistemima ovaj fajl obično enkriptovan iz sigurnosnih razloga, što otežava oporavak.

* Da biste proverili da li je enkripcija omogućena za sleepimage, može se pokrenuti komanda `sysctl vm.swapusage`. To će pokazati da li je fajl enkriptovan.

### Logovi pritiska na memoriju

Još jedan važan fajl povezan sa memorijom u MacOS sistemima su **logovi pritiska na memoriju**. Ovi logovi se nalaze u `/var/log` i sadrže detaljne informacije o korišćenju memorije sistema i događajima pritiska. Mogu biti posebno korisni za dijagnostikovanje problema povezanih sa memorijom ili razumevanje kako sistem upravlja memorijom tokom vremena.

## Dumpovanje memorije pomoću osxpmem

Da biste dumpovali memoriju na MacOS računaru, možete koristiti [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Napomena**: Sledeće instrukcije će raditi samo za Mac računare sa Intel arhitekturom. Ovaj alat je sada arhiviran, a poslednje izdanje je bilo 2017. Binarni fajl preuzet korišćenjem instrukcija ispod cilja Intel čipove jer Apple Silicon nije postojao 2017. Možda je moguće kompajlirati binarni fajl za arm64 arhitekturu, ali ćete morati sami da probate.
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
**Drugi problemi** mogu biti rešeni **omogućavanjem učitavanja kexta** u "Sigurnost i privatnost --> Opšte", jednostavno ga **omogućite**.

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

Možete posetiti njihovu veb lokaciju i isprobati njihov pretraživač **besplatno** na:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
Naučite i vežbajte hakovanje AWS-a:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
