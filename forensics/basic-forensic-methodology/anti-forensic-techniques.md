{% hint style="success" %}
Učite i vežbajte hakovanje AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte hakovanje GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


# Vremenske oznake

Napadač može biti zainteresovan za **menjanje vremenskih oznaka datoteka** kako bi izbegao otkrivanje.\
Moguće je pronaći vremenske oznake unutar MFT u atributima `$STANDARD_INFORMATION` __ i __ `$FILE_NAME`.

Oba atributa imaju 4 vremenske oznake: **Modifikacija**, **pristup**, **kreacija** i **modifikacija registra MFT** (MACE ili MACB).

**Windows explorer** i drugi alati prikazuju informacije iz **`$STANDARD_INFORMATION`**.

## TimeStomp - Anti-forenzički alat

Ovaj alat **menja** informacije o vremenskim oznakama unutar **`$STANDARD_INFORMATION`** **ali** **ne** informacije unutar **`$FILE_NAME`**. Stoga je moguće **identifikovati** **sumnjivu** **aktivnost**.

## Usnjrnl

**USN Journal** (Update Sequence Number Journal) je funkcija NTFS (Windows NT fajl sistem) koja prati promene na volumenu. Alat [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) omogućava pregled ovih promena.

![](<../../.gitbook/assets/image (449).png>)

Prethodna slika je **izlaz** prikazan od strane **alata** gde se može primetiti da su neke **promene izvršene** na datoteci.

## $LogFile

**Sve promene metapodataka na fajl sistemu se beleže** u procesu poznatom kao [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Beleženi metapodaci se čuvaju u fajlu nazvanom `**$LogFile**`, smeštenom u korenom direktorijumu NTFS fajl sistema. Alati poput [LogFileParser](https://github.com/jschicht/LogFileParser) mogu se koristiti za parsiranje ovog fajla i identifikaciju promena.

![](<../../.gitbook/assets/image (450).png>)

Ponovo, u izlazu alata moguće je videti da su **izvršene neke promene**.

Korišćenjem istog alata moguće je identifikovati **u koje vreme su vremenske oznake modifikovane**:

![](<../../.gitbook/assets/image (451).png>)

* CTIME: Vreme kreiranja fajla
* ATIME: Vreme modifikacije fajla
* MTIME: Modifikacija registra MFT fajla
* RTIME: Vreme pristupa fajlu

## Poređenje `$STANDARD_INFORMATION` i `$FILE_NAME`

Još jedan način identifikovanja sumnjivih modifikovanih datoteka bio bi upoređivanje vremena na oba atributa u potrazi za **neslaganjima**.

## Nanosekunde

Vremenske oznake **NTFS** imaju **preciznost** od **100 nanosekundi**. Zato je veoma sumnjivo pronaći datoteke sa vremenskim oznakama poput 2010-10-10 10:10:**00.000:0000**.

## SetMace - Anti-forenzički alat

Ovaj alat može modifikovati oba atributa `$STARNDAR_INFORMATION` i `$FILE_NAME`. Međutim, od Windows Vista, potrebno je da operativni sistem uživo modifikuje ove informacije.

# Skrivanje podataka

NTFS koristi klaster i minimalnu veličinu informacija. To znači da ako datoteka zauzima klaster i pola, **preostala polovina nikada neće biti korišćena** dok datoteka ne bude obrisana. Zato je moguće **sakriti podatke u ovom praznom prostoru**.

Postoje alati poput slacker koji omogućavaju skrivanje podataka u ovom "skrivenom" prostoru. Međutim, analiza `$logfile` i `$usnjrnl` može pokazati da su dodati neki podaci:

![](<../../.gitbook/assets/image (452).png>)

Zato je moguće povratiti prazan prostor korišćenjem alata poput FTK Imager. Imajte na umu da ovaj tip alata može sačuvati sadržaj zamućen ili čak šifrovan.

# UsbKill

Ovo je alat koji će **isključiti računar ako se detektuje bilo kakva promena u USB** portovima.\
Način da se ovo otkrije je inspekcija pokrenutih procesa i **pregled svakog pokrenutog python skripta**.

# Linux distribucije uživo

Ove distribucije se **izvršavaju unutar RAM** memorije. Jedini način da ih otkrijete je **ukoliko je NTFS fajl-sistem montiran sa dozvolama za pisanje**. Ako je montiran samo sa dozvolama za čitanje, neće biti moguće otkriti upad.

# Bezbedno brisanje

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

# Windows konfiguracija

Moguće je onemogućiti nekoliko metoda beleženja Windows-a kako bi forenzička istraga bila mnogo teža.

## Onemogući vremenske oznake - UserAssist

Ovo je registarski ključ koji čuva datume i sate kada je svaki izvršni fajl pokrenut od strane korisnika.

Onemogućavanje UserAssist zahteva dva koraka:

1. Postavite dva registarska ključa, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` i `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, oba na nulu kako biste signalizirali da želite onemogućiti UserAssist.
2. Obrišite podstabla registra koja izgledaju kao `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

## Onemogući vremenske oznake - Prefetch

Ovo će sačuvati informacije o aplikacijama koje su pokrenute sa ciljem poboljšanja performansi Windows sistema. Međutim, ovo može biti korisno i za forenzičke prakse.

* Izvršite `regedit`
* Izaberite putanju fajla `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
* Desni klik na `EnablePrefetcher` i `EnableSuperfetch`
* Izaberite Izmeni na svakom od njih da promenite vrednost sa 1 (ili 3) na 0
* Ponovo pokrenite računar

## Onemogući vremenske oznake - Vreme poslednjeg pristupa

Kada se otvori folder sa NTFS volumena na Windows NT serveru, sistem uzima vreme da **ažurira polje vremenske oznake na svakom navedenom folderu**, nazvano vreme poslednjeg pristupa. Na veoma korišćenom NTFS volumenu, ovo može uticati na performanse.

1. Otvorite Registry Editor (Regedit.exe).
2. Pretražite `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Potražite `NtfsDisableLastAccessUpdate`. Ako ne postoji, dodajte ovaj DWORD i postavite vrednost na 1, što će onemogućiti proces.
4. Zatvorite Registry Editor i ponovo pokrenite server.
## Brisanje USB istorije

Svi **unosi USB uređaja** se čuvaju u Windows registru pod ključem **USBSTOR** koji sadrži podključeve koji se kreiraju svaki put kada priključite USB uređaj na računar ili laptop. Možete pronaći ovaj ključ ovde `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Brisanjem ovoga** ćete obrisati USB istoriju.\
Takođe možete koristiti alatku [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) da biste bili sigurni da ste ih obrisali (i da ih obrišete).

Još jedan fajl koji čuva informacije o USB uređajima je fajl `setupapi.dev.log` unutar `C:\Windows\INF`. I ovaj fajl treba obrisati.

## Onemogući Shadow kopije

**Prikaži** shadow kopije sa `vssadmin list shadowstorage`\
**Obriši** ih pokretanjem `vssadmin delete shadow`

Takođe ih možete obrisati putem GUI prateći korake predložene na [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Za onemogućavanje shadow kopija [koraci odavde](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Otvorite program Services kucanjem "services" u polje za pretragu teksta nakon što kliknete na Windows start dugme.
2. Iz liste pronađite "Volume Shadow Copy", izaberite ga, a zatim pristupite Properties opciji desnim klikom.
3. Izaberite Disabled iz padajućeg menija "Startup type", a zatim potvrdite promenu klikom na Apply i OK.

Takođe je moguće modifikovati konfiguraciju koje datoteke će biti kopirane u shadow kopiji u registru `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

## Prepisi obrisane fajlove

* Možete koristiti **Windows alatku**: `cipher /w:C` Ovo će narediti cifri da ukloni sve podatke sa dostupnog neiskorišćenog prostora na disku C.
* Takođe možete koristiti alatke poput [**Eraser**](https://eraser.heidi.ie)

## Obriši Windows događajne zapise

* Windows + R --> eventvwr.msc --> Proširi "Windows Logs" --> Desni klik na svaku kategoriju i izaberi "Clear Log"
* `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
* `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

## Onemogući Windows događajne zapise

* `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
* Unutar sekcije servisa onemogući servis "Windows Event Log"
* `WEvtUtil.exec clear-log` ili `WEvtUtil.exe cl`

## Onemogući $UsnJrnl

* `fsutil usn deletejournal /d c:`

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}
