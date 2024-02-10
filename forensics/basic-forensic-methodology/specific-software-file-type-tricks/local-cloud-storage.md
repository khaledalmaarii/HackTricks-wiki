# Lokalno skladištenje u oblaku

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) da biste lako izgradili i **automatizovali radne tokove** uz pomoć najnaprednijih alata zajednice na svetu.\
Danas dobijte pristup:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## OneDrive

Na Windows-u, OneDrive folder se može pronaći u `\Users\<korisničko_ime>\AppData\Local\Microsoft\OneDrive`. A unutar `logs\Personal` foldera moguće je pronaći datoteku `SyncDiagnostics.log` koja sadrži neke zanimljive podatke u vezi sa sinhronizovanim datotekama:

* Veličina u bajtovima
* Datum kreiranja
* Datum modifikacije
* Broj datoteka u oblaku
* Broj datoteka u folderu
* **CID**: Jedinstveni ID OneDrive korisnika
* Vreme generisanja izveštaja
* Veličina HD-a operativnog sistema

Kada pronađete CID, preporučuje se **pretraga datoteka koje sadrže ovaj ID**. Moguće je pronaći datoteke sa imenom: _**\<CID>.ini**_ i _**\<CID>.dat**_ koje mogu sadržati zanimljive informacije poput imena datoteka sinhronizovanih sa OneDrive-om.

## Google Drive

Na Windows-u, glavni Google Drive folder se može pronaći u `\Users\<korisničko_ime>\AppData\Local\Google\Drive\user_default`\
Ovaj folder sadrži datoteku nazvanu Sync\_log.log sa informacijama poput adrese e-pošte naloga, imena datoteka, vremenskih oznaka, MD5 heševa datoteka, itd. Čak i obrisane datoteke se pojavljuju u toj log datoteci sa odgovarajućim MD5 vrednostima.

Datoteka **`Cloud_graph\Cloud_graph.db`** je sqlite baza podataka koja sadrži tabelu **`cloud_graph_entry`**. U ovoj tabeli možete pronaći **ime** **sinhronizovanih** **datoteka**, vreme izmene, veličinu i MD5 kontrolnu sumu datoteka.

Podaci tabele baze podataka **`Sync_config.db`** sadrže adresu e-pošte naloga, putanje deljenih foldera i verziju Google Drive-a.

## Dropbox

Dropbox koristi **SQLite baze podataka** za upravljanje datotekama. U ovim\
Baze podataka se mogu pronaći u folderima:

* `\Users\<korisničko_ime>\AppData\Local\Dropbox`
* `\Users\<korisničko_ime>\AppData\Local\Dropbox\Instance1`
* `\Users\<korisničko_ime>\AppData\Roaming\Dropbox`

A glavne baze podataka su:

* Sigstore.dbx
* Filecache.dbx
* Deleted.dbx
* Config.dbx

Ekstenzija ".dbx" znači da su **baze podataka** **šifrovane**. Dropbox koristi **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/ms995355\(v=msdn.10\)?redirectedfrom=MSDN))

Da biste bolje razumeli šifrovanje koje Dropbox koristi, možete pročitati [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).

Međutim, glavne informacije su:

* **Entropija**: d114a55212655f74bd772e37e64aee9b
* **So**: 0D638C092E8B82FC452883F95F355B8E
* **Algoritam**: PBKDF2
* **Iteracije**: 1066

Osim tih informacija, za dešifrovanje baza podataka vam je još uvek potrebno:

* **Šifrovani DPAPI ključ**: Možete ga pronaći u registru unutar `NTUSER.DAT\Software\Dropbox\ks\client` (izvezite ove podatke kao binarne)
* **`SYSTEM`** i **`SECURITY`** registarske ključeve
* **DPAPI master ključeve**: Koje možete pronaći u `\Users\<korisničko_ime>\AppData\Roaming\Microsoft\Protect`
* **Korisničko ime** i **lozinku** Windows korisnika

Zatim možete koristiti alatku [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi\_data\_decryptor.html)**:**

![](<../../../.gitbook/assets/image (448).png>)

Ako sve ide kako se očekuje, alatka će pokazati **primarni ključ** koji vam je potreban da biste **obnovili originalni ključ**. Da biste obnovili originalni ključ, jednostavno koristite ovaj [cyber\_chef recept](https://gchq.github.io/CyberChef/#recipe=Derive\_PBKDF2\_key\(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D\)) stavljajući primarni ključ kao "passphrase" unutar recepta.

Dobijeni heksadecimalni kod je konačni ključ koji se koristi za šifrovanje baza podataka koje se mogu dešifrovati sa:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
Baza podataka **`config.dbx`** sadrži:

* **Email**: Email korisnika
* **usernamedisplayname**: Ime korisnika
* **dropbox\_path**: Putanja gde se nalazi Dropbox folder
* **Host\_id: Hash**: Koristi se za autentifikaciju na oblaku. Može se povući samo sa veba.
* **Root\_ns**: Identifikator korisnika

Baza podataka **`filecache.db`** sadrži informacije o svim datotekama i fasciklama sinhronizovanim sa Dropbox-om. Tabela `File_journal` sadrži najkorisnije informacije:

* **Server\_path**: Putanja gde se datoteka nalazi na serveru (ova putanja je prethodena `host_id`-om klijenta).
* **local\_sjid**: Verzija datoteke
* **local\_mtime**: Datum izmene
* **local\_ctime**: Datum kreiranja

Druge tabele u ovoj bazi podataka sadrže još interesantnih informacija:

* **block\_cache**: heš svih datoteka i fascikli Dropbox-a
* **block\_ref**: Povezuje heš ID tabele `block_cache` sa ID-em datoteke u tabeli `file_journal`
* **mount\_table**: Deljeni folderi Dropbox-a
* **deleted\_fields**: Obrisane datoteke sa Dropbox-a
* **date\_added**

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) da biste lako izgradili i **automatizovali radne tokove** uz pomoć najnaprednijih alata zajednice.\
Dobijte pristup danas:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **oglašavanje vaše kompanije u HackTricks-u** ili **preuzmete HackTricks u PDF formatu**, proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
