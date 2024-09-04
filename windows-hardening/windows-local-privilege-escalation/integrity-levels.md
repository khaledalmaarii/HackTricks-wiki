# Integrity Levels

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

## Integrity Levels

U Windows Vista i novijim verzijama, svi zaštićeni predmeti dolaze sa oznakom **nivoa integriteta**. Ova postavka uglavnom dodeljuje "srednji" nivo integriteta datotekama i registracionim ključevima, osim za određene foldere i datoteke kojima Internet Explorer 7 može pristupiti na niskom nivou integriteta. Podrazumevano ponašanje je da procesi koje pokreću standardni korisnici imaju srednji nivo integriteta, dok servisi obično rade na sistemskom nivou integriteta. Oznaka visokog integriteta štiti korenski direktorijum.

Ključna pravila su da objekti ne mogu biti modifikovani od strane procesa sa nižim nivoom integriteta od nivoa objekta. Nivoi integriteta su:

* **Nepouzdano**: Ovaj nivo je za procese sa anonimnim prijavama. %%%Primer: Chrome%%%
* **Nisko**: Uglavnom za internet interakcije, posebno u Zaštićenom režimu Internet Explorera, utičući na povezane datoteke i procese, kao i određene foldere poput **Privremenog internet foldera**. Procesi sa niskim integritetom suočavaju se sa značajnim ograničenjima, uključujući nedostatak pristupa za pisanje u registru i ograničen pristup pisanju korisničkog profila.
* **Srednje**: Podrazumevani nivo za većinu aktivnosti, dodeljen standardnim korisnicima i objektima bez specifičnih nivoa integriteta. Čak i članovi Administratorske grupe rade na ovom nivou podrazumevano.
* **Visoko**: Rezervisano za administratore, omogućavajući im da modifikuju objekte na nižim nivoima integriteta, uključujući one na visokom nivou.
* **Sistem**: Najviši operativni nivo za Windows kernel i osnovne servise, van domašaja čak i za administratore, osiguravajući zaštitu vitalnih sistemskih funkcija.
* **Instalater**: Jedinstveni nivo koji stoji iznad svih drugih, omogućavajući objektima na ovom nivou da deinstaliraju bilo koji drugi objekat.

Možete dobiti nivo integriteta procesa koristeći **Process Explorer** iz **Sysinternals**, pristupajući **svojstvima** procesa i gledajući karticu "**Bezbednost**":

![](<../../.gitbook/assets/image (824).png>)

Takođe možete dobiti **trenutni nivo integriteta** koristeći `whoami /groups`

![](<../../.gitbook/assets/image (325).png>)

### Integrity Levels in File-system

Objekat unutar fajl sistema može imati **minimalne zahteve za nivo integriteta** i ako proces nema ovaj nivo integriteta, neće moći da interaguje sa njim.\
Na primer, hajde da **napravimo regularnu datoteku iz konzole regularnog korisnika i proverimo dozvole**:
```
echo asd >asd.txt
icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
```
Sada, dodelimo minimalni nivo integriteta **High** datoteci. Ovo **mora biti urađeno iz konzole** koja se pokreće kao **administrator**, jer će **obična konzola** raditi na Medium Integrity nivou i **neće biti dozvoljeno** dodeliti High Integrity nivo objektu:
```
icacls asd.txt /setintegritylevel(oi)(ci) High
processed file: asd.txt
Successfully processed 1 files; Failed processing 0 files

C:\Users\Public>icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
Mandatory Label\High Mandatory Level:(NW)
```
Ovdje stvari postaju zanimljive. Možete vidjeti da korisnik `DESKTOP-IDJHTKP\user` ima **PUNE privilegije** nad datotekom (zaista, to je bio korisnik koji je kreirao datoteku), međutim, zbog minimalnog nivoa integriteta koji je implementiran, neće moći da modifikuje datoteku više osim ako ne radi unutar Visokog Nivoa Integriteta (napomena: moći će da je pročita):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
{% hint style="info" %}
**Dakle, kada datoteka ima minimalni nivo integriteta, da biste je izmenili, morate raditi barem na tom nivou integriteta.**
{% endhint %}

### Nivoi integriteta u binarnim datotekama

Napravio sam kopiju `cmd.exe` u `C:\Windows\System32\cmd-low.exe` i postavio joj **nivo integriteta nizak iz administratorske konzole:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Sada, kada pokrenem `cmd-low.exe`, on će **raditi pod niskim nivoom integriteta** umesto pod srednjim:

![](<../../.gitbook/assets/image (313).png>)

Za radoznale, ako dodelite visoki nivo integriteta binarnom fajlu (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`), on se neće automatski pokrenuti sa visokim nivoom integriteta (ako ga pozovete iz srednjeg nivoa integriteta --po defaultu-- pokrenuće se pod srednjim nivoom integriteta).

### Nivoi Integriteta u Procesima

Nisu svi fajlovi i fascikle imaju minimalni nivo integriteta, **ali svi procesi rade pod nivoom integriteta**. I slično onome što se desilo sa fajlskim sistemom, **ako proces želi da piše unutar drugog procesa, mora imati barem isti nivo integriteta**. To znači da proces sa niskim nivoom integriteta ne može otvoriti handle sa punim pristupom procesu sa srednjim nivoom integriteta.

Zbog ograničenja komentisanih u ovoj i prethodnoj sekciji, sa bezbednosnog stanovišta, uvek je **preporučljivo pokrenuti proces na najnižem mogućem nivou integriteta**.
