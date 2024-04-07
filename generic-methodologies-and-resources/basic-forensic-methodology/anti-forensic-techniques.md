# Anti-Forenske Tehnike

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Vremenske Oznake

Napadač može biti zainteresovan za **menjanje vremenskih oznaka fajlova** kako bi izbegao otkrivanje.\
Moguće je pronaći vremenske oznake unutar MFT-a u atributima `$STANDARD_INFORMATION` i `$FILE_NAME`.

Oba atributa imaju 4 vremenske oznake: **Modifikacija**, **pristup**, **kreacija** i **modifikacija MFT registra** (MACE ili MACB).

**Windows explorer** i drugi alati prikazuju informacije iz **`$STANDARD_INFORMATION`**.

### TimeStomp - Anti-forenzički Alat

Ovaj alat **menja** informacije o vremenskim oznakama unutar **`$STANDARD_INFORMATION`** **ali ne** informacije unutar **`$FILE_NAME`**. Stoga je moguće **identifikovati sumnjive aktivnosti**.

### Usnjrnl

**USN Journal** (Update Sequence Number Journal) je funkcija NTFS-a (Windows NT fajl sistem) koja prati promene na volumenu. Alat [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) omogućava pregled ovih promena.

![](<../../.gitbook/assets/image (798).png>)

Prethodna slika je **izlaz** prikazan od strane **alata** gde se može primetiti da su neke **promene izvršene** na fajlu.

### $LogFile

**Sve promene metapodataka na fajl sistemu se beleže** u procesu poznatom kao [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead\_logging). Beleženi metapodaci se čuvaju u fajlu nazvanom `**$LogFile**`, smeštenom u korenom direktorijumu NTFS fajl sistema. Alati poput [LogFileParser](https://github.com/jschicht/LogFileParser) se mogu koristiti za parsiranje ovog fajla i identifikaciju promena.

![](<../../.gitbook/assets/image (134).png>)

Ponovo, u izlazu alata je moguće videti da su **neke promene izvršene**.

Korišćenjem istog alata moguće je identifikovati **kada su vremenske oznake modifikovane**:

![](<../../.gitbook/assets/image (1086).png>)

* CTIME: Vreme kreiranja fajla
* ATIME: Vreme modifikacije fajla
* MTIME: Modifikacija MFT registra fajla
* RTIME: Vreme pristupa fajlu

### Poređenje `$STANDARD_INFORMATION` i `$FILE_NAME`

Još jedan način identifikovanja sumnjivih modifikovanih fajlova bi bilo upoređivanje vremena na oba atributa u potrazi za **neslaganjima**.

### Nanosekunde

**NTFS** vremenske oznake imaju **preciznost** od **100 nanosekundi**. Zato je veoma sumnjivo pronaći fajlove sa vremenskim oznakama poput 2010-10-10 10:10:**00.000:0000**.

### SetMace - Anti-forenzički Alat

Ovaj alat može modifikovati oba atributa `$STARNDAR_INFORMATION` i `$FILE_NAME`. Međutim, od Windows Vista, potrebno je da operativni sistem uživo modifikuje ove informacije.

## Skrivanje Podataka

NTFS koristi klaster i minimalnu veličinu informacija. To znači da ako fajl zauzima klaster i pola, **preostala polovina nikada neće biti korišćena** dok fajl ne bude obrisan. Zato je moguće **sakriti podatke u ovom praznom prostoru**.

Postoje alati poput slacker koji omogućavaju skrivanje podataka u ovom "skrivenom" prostoru. Međutim, analiza `$logfile` i `$usnjrnl` može pokazati da su dodati neki podaci:

![](<../../.gitbook/assets/image (1057).png>)

Zatim je moguće povratiti prazan prostor korišćenjem alata poput FTK Imager. Imajte na umu da ovaj tip alata može sačuvati sadržaj obfuskovan ili čak šifrovan.

## UsbKill

Ovo je alat koji će **isključiti računar ako se detektuje bilo kakva promena u USB** portovima.\
Način da se ovo otkrije je inspekcijom pokrenutih procesa i **pregledom svakog Python skripta koji se izvršava**.

## Linux Distribucije Uživo

Ove distribucije se **izvršavaju unutar RAM** memorije. Jedini način da se otkriju je **ukoliko je NTFS fajl-sistem montiran sa dozvolama za pisanje**. Ako je montiran samo sa dozvolama za čitanje, neće biti moguće otkriti upad.

## Sigurno Brisanje

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows Konfiguracija

Moguće je onemogućiti nekoliko metoda logovanja u Windows-u kako bi forenzička istraga bila mnogo teža.

### Onemogućavanje Vremenskih Oznaka - UserAssist

Ovo je registarski ključ koji čuva datume i sate kada je svaki izvršni fajl pokrenut od strane korisnika.

Onemogućavanje UserAssist zahteva dva koraka:

1. Postavite dva registarska ključa, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` i `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, oba na nulu kako biste signalizirali da želite onemogućiti UserAssist.
2. Obrišite podstabla registra koja izgledaju kao `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Onemogućavanje Vremenskih Oznaka - Prefetch

Ovo će sačuvati informacije o aplikacijama koje su izvršene sa ciljem poboljšanja performansi Windows sistema. Međutim, ovo može biti korisno i za forenzičke prakse.

* Izvršite `regedit`
* Izaberite putanju fajla `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
* Desni klik na `EnablePrefetch` i `EnableSuperfetch`
* Izaberite Izmeni na svakom od njih da promenite vrednost sa 1 (ili 3) na 0
* Ponovo pokrenite računar

### Onemogućavanje Vremenskih Oznaka - Vreme Poslednjeg Pristupa

Kada se folder otvori sa NTFS volumena na Windows NT serveru, sistem uzima vreme da **ažurira polje vremenske oznake na svakom navedenom folderu**, nazvano vreme poslednjeg pristupa. Na veoma korišćenom NTFS volumenu, ovo može uticati na performanse.

1. Otvorite Registry Editor (Regedit.exe).
2. Pretražite `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Potražite `NtfsDisableLastAccessUpdate`. Ako ne postoji, dodajte ovaj DWORD i postavite vrednost na 1, što će onemogućiti proces.
4. Zatvorite Registry Editor i ponovo pokrenite server.
### Brisanje USB istorije

Svi **unos uređaja USB** se čuvaju u Windows registru pod ključem **USBSTOR** koji sadrži podključeve koji se kreiraju svaki put kada priključite USB uređaj na računar. Možete pronaći ovaj ključ ovde `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Brisanjem ovoga** ćete obrisati USB istoriju.\
Takođe možete koristiti alat [**USBDeview**](https://www.nirsoft.net/utils/usb\_devices\_view.html) da biste bili sigurni da ste ih obrisali (i da ih obrišete).

Drugi fajl koji čuva informacije o USB uređajima je fajl `setupapi.dev.log` unutar `C:\Windows\INF`. I ovaj fajl treba obrisati.

### Onemogućavanje senki kopija

**Prikažite** senke kopija sa `vssadmin list shadowstorage`\
**Obrišite** ih pokretanjem `vssadmin delete shadow`

Takođe ih možete obrisati putem GUI prateći korake predložene na [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Za onemogućavanje senki kopija [koraci odavde](https://support.waters.com/KB\_Inf/Other/WKB15560\_How\_to\_disable\_Volume\_Shadow\_Copy\_Service\_VSS\_in\_Windows):

1. Otvorite program Servisi kucanjem "services" u polje za pretragu teksta nakon klika na Windows start dugme.
2. Iz liste pronađite "Volume Shadow Copy", izaberite ga, a zatim pristupite Properties desnim klikom.
3. Izaberite Disabled iz padajućeg menija "Startup type", a zatim potvrdite promenu klikom na Apply i OK.

Takođe je moguće izmeniti konfiguraciju koje datoteke će biti kopirane u senki kopiji u registru `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Prepisivanje obrisanih fajlova

* Možete koristiti **Windows alat**: `cipher /w:C` Ovo će narediti cifri da ukloni sve podatke sa dostupnog neiskorišćenog prostora diska unutar C drajva.
* Takođe možete koristiti alate poput [**Eraser**](https://eraser.heidi.ie)

### Brisanje Windows događajnih logova

* Windows + R --> eventvwr.msc --> Proširite "Windows Logs" --> Desni klik na svaku kategoriju i izaberite "Clear Log"
* `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
* `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Onemogućavanje Windows događajnih logova

* `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
* Unutar sekcije servisa onemogućite servis "Windows Event Log"
* `WEvtUtil.exec clear-log` ili `WEvtUtil.exe cl`

### Onemogućavanje $UsnJrnl

* `fsutil usn deletejournal /d c:`
