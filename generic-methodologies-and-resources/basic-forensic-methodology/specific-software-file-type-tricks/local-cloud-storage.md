# Lokalna Cloud Skladišta

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podrška HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=local-cloud-storage) za lako kreiranje i **automatizaciju radnih tokova** pokretanih najnaprednijim alatima zajednice na svetu.\
Dobijte pristup danas:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=local-cloud-storage" %}

## OneDrive

U Windows-u, možete pronaći OneDrive folder u `\Users\<username>\AppData\Local\Microsoft\OneDrive`. I unutar `logs\Personal` moguće je pronaći datoteku `SyncDiagnostics.log` koja sadrži neke zanimljive podatke o sinhronizovanim datotekama:

* Veličina u bajtovima
* Datum kreiranja
* Datum modifikacije
* Broj datoteka u cloud-u
* Broj datoteka u folderu
* **CID**: Jedinstveni ID OneDrive korisnika
* Vreme generisanja izveštaja
* Veličina HD operativnog sistema

Kada pronađete CID, preporučuje se da **pretražujete datoteke koje sadrže ovaj ID**. Možda ćete moći da pronađete datoteke sa imenom: _**\<CID>.ini**_ i _**\<CID>.dat**_ koje mogu sadržati zanimljive informacije kao što su imena datoteka sinhronizovanih sa OneDrive-om.

## Google Drive

U Windows-u, možete pronaći glavni Google Drive folder u `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Ovaj folder sadrži datoteku pod nazivom Sync\_log.log sa informacijama kao što su email adresa naloga, imena datoteka, vremenski oznake, MD5 heševi datoteka, itd. Čak i obrisane datoteke se pojavljuju u toj log datoteci sa svojim odgovarajućim MD5.

Datoteka **`Cloud_graph\Cloud_graph.db`** je sqlite baza podataka koja sadrži tabelu **`cloud_graph_entry`**. U ovoj tabeli možete pronaći **ime** **sinhronizovanih** **datoteka**, vreme modifikacije, veličinu i MD5 kontrolni zbir datoteka.

Podaci tabele baze podataka **`Sync_config.db`** sadrže email adresu naloga, putanju deljenih foldera i verziju Google Drive-a.

## Dropbox

Dropbox koristi **SQLite baze podataka** za upravljanje datotekama. U ovom\
Možete pronaći baze podataka u folderima:

* `\Users\<username>\AppData\Local\Dropbox`
* `\Users\<username>\AppData\Local\Dropbox\Instance1`
* `\Users\<username>\AppData\Roaming\Dropbox`

A glavne baze podataka su:

* Sigstore.dbx
* Filecache.dbx
* Deleted.dbx
* Config.dbx

Ekstenzija ".dbx" znači da su **baze podataka** **enkriptovane**. Dropbox koristi **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/ms995355\(v=msdn.10\)?redirectedfrom=MSDN))

Da biste bolje razumeli enkripciju koju Dropbox koristi, možete pročitati [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).

Međutim, glavne informacije su:

* **Entropija**: d114a55212655f74bd772e37e64aee9b
* **So**: 0D638C092E8B82FC452883F95F355B8E
* **Algoritam**: PBKDF2
* **Iteracije**: 1066

Pored tih informacija, da biste dekriptovali baze podataka, još uvek vam je potrebno:

* **enkriptovani DPAPI ključ**: Možete ga pronaći u registru unutar `NTUSER.DAT\Software\Dropbox\ks\client` (izvezite ove podatke kao binarne)
* **`SYSTEM`** i **`SECURITY`** hives
* **DPAPI master ključevi**: Koji se mogu pronaći u `\Users\<username>\AppData\Roaming\Microsoft\Protect`
* **korisničko ime** i **lozinka** Windows korisnika

Zatim možete koristiti alat [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi\_data\_decryptor.html)**:**

![](<../../../.gitbook/assets/image (443).png>)

Ako sve prođe kako se očekuje, alat će označiti **primarni ključ** koji treba da **koristite za oporavak originalnog**. Da biste povratili originalni, jednostavno koristite ovaj [cyber\_chef recept](https://gchq.github.io/CyberChef/#recipe=Derive\_PBKDF2\_key\(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D\)) stavljajući primarni ključ kao "lozinku" unutar recepta.

Rezultantni heksadecimalni broj je konačni ključ koji se koristi za enkripciju baza podataka koje se mogu dekriptovati sa:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
The **`config.dbx`** baza podataka sadrži:

* **Email**: Email korisnika
* **usernamedisplayname**: Ime korisnika
* **dropbox\_path**: Putanja gde se nalazi dropbox folder
* **Host\_id: Hash** korišćen za autentifikaciju u cloud. Ovo se može opozvati samo sa veba.
* **Root\_ns**: Identifikator korisnika

The **`filecache.db`** baza podataka sadrži informacije o svim datotekama i folderima sinhronizovanim sa Dropbox-om. Tabela `File_journal` je ona sa više korisnih informacija:

* **Server\_path**: Putanja gde se datoteka nalazi unutar servera (ova putanja je prethodna `host_id` klijenta).
* **local\_sjid**: Verzija datoteke
* **local\_mtime**: Datum modifikacije
* **local\_ctime**: Datum kreiranja

Ostale tabele unutar ove baze sadrže zanimljivije informacije:

* **block\_cache**: hash svih datoteka i foldera Dropbox-a
* **block\_ref**: Povezuje hash ID tabele `block_cache` sa ID datoteke u tabeli `file_journal`
* **mount\_table**: Deljeni folderi Dropbox-a
* **deleted\_fields**: Obrišene datoteke Dropbox-a
* **date\_added**

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=local-cloud-storage) za lako kreiranje i **automatizaciju radnih tokova** pokretanih najnaprednijim alatima zajednice na svetu.\
Pribavite pristup danas:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=local-cloud-storage" %}

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitter-u** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
