# ACLs - DACLs/SACLs/ACEs

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Użyj [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks), aby łatwo tworzyć i **automatyzować zadania** przy użyciu najbardziej zaawansowanych narzędzi społecznościowych na świecie.\
Otrzymaj dostęp już dziś:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**The PEASS Family**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## **Lista kontroli dostępu (ACL)**

Lista kontroli dostępu (ACL) składa się z uporządkowanego zestawu wpisów kontroli dostępu (ACE), które określają zabezpieczenia obiektu i jego właściwości. W skrócie, ACL definiuje, jakie działania przez jakie podmioty bezpieczeństwa (użytkownicy lub grupy) są dozwolone lub zabronione dla danego obiektu.

Istnieją dwa rodzaje ACL:

- **Dyskrecjonalna lista kontroli dostępu (DACL):** Określa, które użytkownicy i grupy mają lub nie mają dostępu do obiektu.
- **Systemowa lista kontroli dostępu (SACL):** Zarządza audytem prób dostępu do obiektu.

Proces dostępu do pliku polega na sprawdzeniu deskryptora zabezpieczeń obiektu przez system w stosunku do tokenu dostępu użytkownika, aby określić, czy dostęp powinien zostać udzielony i zakres tego dostępu, na podstawie ACE.

### **Kluczowe składniki**

- **DACL:** Zawiera ACE, które przyznają lub odmawiają uprawnienia dostępu użytkownikom i grupom dla obiektu. Jest to główny ACL, który określa prawa dostępu.

- **SACL:** Służy do audytu dostępu do obiektów, gdzie ACE definiują rodzaje dostępu, które mają być rejestrowane w dzienniku zdarzeń zabezpieczeń. Może to być niezwykle przydatne do wykrywania prób nieautoryzowanego dostępu lub rozwiązywania problemów z dostępem.

### **Interakcja systemu z ACL**

Każda sesja użytkownika jest powiązana z tokenem dostępu, który zawiera informacje związane z bezpieczeństwem dla tej sesji, w tym tożsamość użytkownika, grupy i uprawnienia. Token ten zawiera również SID logowania, który jednoznacznie identyfikuje sesję.

Lokalna służba zabezpieczeń (LSASS) przetwarza żądania dostępu do obiektów, sprawdzając DACL w poszukiwaniu ACE, które pasują do podmiotu bezpieczeństwa próbującego uzyskać dostęp. Jeśli nie zostaną znalezione odpowiednie ACE, dostęp jest natychmiast udzielany. W przeciwnym razie LSASS porównuje ACE z SID podmiotu bezpieczeństwa w tokenie dostępu, aby określić uprawnienia dostępu.

### **Podsumowany proces**

- **ACL:** Definiuje uprawnienia dostępu za pomocą DACL i zasady audytu za pomocą SACL.
- **Token dostępu:** Zawiera informacje o użytkowniku, grupie i uprawnieniach dla sesji.
- **Decyzja o dostępie:** Podejmowana jest przez porównanie ACE z DACL z tokenem dostępu; SACL są używane do audytu.


### ACE

Istnieją **trzy główne typy wpisów kontroli dostępu (ACE)**:

- **ACE odrzucający dostęp**: Ten ACE wyraźnie odmawia dostępu do obiektu określonym użytkownikom lub grupom (w DACL).
- **ACE zezwalający na dostęp**: Ten ACE wyraźnie przyznaje dostęp do obiektu określonym użytkownikom lub grupom (w DACL).
- **ACE audytu systemowego**: Umieszczony w Systemowej liście kontroli dostępu (SACL), ten ACE jest odpowiedzialny za generowanie dzienników audytu po próbach dostępu do obiektu przez użytkowników lub grupy. Dokumentuje, czy dostęp został zezwolony lub odmówiony oraz charakter dostępu.

Każdy ACE ma **cztery kluczowe składniki**:

1. **Identyfikator zabezpieczeń (SID)** użytkownika lub grupy (lub ich nazwa główna w reprezentacji graficznej).
2. **Flaga**, która identyfikuje typ ACE (odmowa dostępu, zezwolenie na dostęp lub audyt systemowy).
3. **Flagi dziedziczenia**, które określają, czy obiekty podrzędne mogą dziedziczyć ACE od swojego rodzica.
4. **[Maska dostępu](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN)**, 32-bitowa wartość określająca przyznane prawa obiektu.

Decyzja o dostępie jest podejmowana przez sekwencyjne badanie każdego ACE, aż do:

- ACE **odmawiającego dostęp** wyraźnie odmawiającego żądanych prawom dostępu do powiernika zidentyfikowanego w tokenie dostępu.
- ACE **zezwala na dostęp**, które wyraźnie przyznają wszystkie żądane prawa powiernikowi w tokenie dostępu.
- Po sprawdzeniu wszystkich ACE, jeśli żadne żądane prawo nie zostało wyraźnie zezwolone, dostęp jest domyślnie **odmawiany**.


### Kolejność ACE

Sposób, w jaki **ACE** (zasady określające, kto może mieć dostęp do czegoś) są umieszczane na liście zwanej **DACL**, jest bardzo ważny. Wynika to z faktu, że po tym, jak system udzieli lub odmówi dostępu na podstawie tych zasad, przestaje przeglądać resztę.

Istnieje najlepszy sposób organizacji tych ACE, nazywany **"kolejnością kanoniczną"**. Ta metoda pomaga upewnić się, że wszystko działa sprawnie i sprawiedliwie. Oto jak to wygląda w przypadku systemów takich jak **Windows 2000** i **Windows Server 2003**:

- Na początku umieść wszystkie zasady, które są **specjalnie dla tego elementu**, przed tymi, które pochodzą z innego miejsca, takiego jak folder nadr
### Przykład w interfejsie graficznym

**[Przykład stąd](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)**

To jest klasyczna karta zabezpieczeń folderu, która pokazuje ACL, DACL i ACE:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../.gitbook/assets/classicsectab.jpg)

Jeśli klikniemy przycisk **Zaawansowane**, otrzymamy więcej opcji, takich jak dziedziczenie:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../.gitbook/assets/aceinheritance.jpg)

Jeśli dodasz lub edytujesz podmiot zabezpieczeń:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../.gitbook/assets/editseprincipalpointers1.jpg)

Na koniec mamy SACL w karcie Audytowanie:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../.gitbook/assets/audit-tab.jpg)

### Wyjaśnienie kontroli dostępu w uproszczony sposób

Podczas zarządzania dostępem do zasobów, takich jak folder, używamy list i reguł znanych jako listy kontroli dostępu (ACL) i wpisy kontroli dostępu (ACE). Określają one, kto może lub nie może uzyskać dostęp do określonych danych.

#### Odmawianie dostępu określonej grupie

Wyobraź sobie, że masz folder o nazwie "Koszt" i chcesz, aby wszyscy mieli do niego dostęp, z wyjątkiem zespołu marketingowego. Poprzez odpowiednie skonfigurowanie reguł, możemy zapewnić, że zespół marketingowy jest wyraźnie pozbawiony dostępu przed udzieleniem dostępu wszystkim innym. Dokonuje się tego poprzez umieszczenie reguły odmowy dostępu dla zespołu marketingowego przed regułą, która zezwala na dostęp dla wszystkich.

#### Udzielanie dostępu określonemu członkowi zespołu, który jest pozbawiony dostępu

Powiedzmy, że Bob, dyrektor marketingu, potrzebuje dostępu do folderu "Koszt", chociaż zespół marketingowy generalnie nie powinien mieć dostępu. Możemy dodać konkretną regułę (ACE) dla Boba, która przyznaje mu dostęp i umieścić ją przed regułą, która odmawia dostępu zespołowi marketingowemu. W ten sposób Bob uzyskuje dostęp pomimo ogólnego ograniczenia dla jego zespołu.

#### Zrozumienie wpisów kontroli dostępu

ACE to indywidualne reguły w ACL. Określają one użytkowników lub grupy, określają, jakie uprawnienia są dozwolone lub zabronione, i określają, jak te reguły są dziedziczone przez inne obiekty. Istnieją dwa główne typy ACE:

- **ACE ogólne**: Dotyczą one szeroko pojętej kontroli dostępu, mającej wpływ albo na wszystkie typy obiektów, albo tylko na kontenery (takie jak foldery) i niekontenery (takie jak pliki). Na przykład reguła, która pozwala użytkownikom zobaczyć zawartość folderu, ale nie uzyskać dostępu do plików wewnątrz niego.

- **ACE specyficzne dla obiektów**: Zapewniają one bardziej precyzyjną kontrolę, umożliwiając ustawienie reguł dla konkretnych typów obiektów lub nawet poszczególnych właściwości w obrębie obiektu. Na przykład w katalogu użytkowników reguła może pozwalać użytkownikowi na aktualizację numeru telefonu, ale nie na godziny logowania.

Każdy ACE zawiera ważne informacje, takie jak do kogo odnosi się reguła (za pomocą identyfikatora zabezpieczeń lub SID), co reguła zezwala lub odmawia (za pomocą maski dostępu) i jak jest dziedziczona przez inne obiekty.

#### Kluczowe różnice między typami ACE

- **ACE ogólne** są odpowiednie dla prostych scenariuszy kontroli dostępu, w których ta sama reguła dotyczy wszystkich aspektów obiektu lub wszystkich obiektów w kontenerze.

- **ACE specyficzne dla obiektów** są używane w bardziej złożonych scenariuszach, zwłaszcza w środowiskach takich jak Active Directory, gdzie może być konieczne kontrolowanie dostępu do konkretnych właściwości obiektu w inny sposób.

Podsumowując, ACL i ACE pomagają określić precyzyjne kontrole dostępu, zapewniając, że tylko odpowiednie osoby lub grupy mają dostęp do poufnych informacji lub zasobów, z możliwością dostosowania praw dostępu do poziomu poszczególnych właściwości lub typów obiektów.

### Układ wpisu kontroli dostępu

| Pole wpisu kontroli dostępu | Opis                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Typ                        | Flaga wskazująca typ wpisu kontroli dostępu. Systemy Windows 2000 i Windows Server 2003 obsługują sześć typów wpisów kontroli dostępu: trzy ogólne typy wpisów kontroli dostępu, które są dołączone do wszystkich obiektów zabezpieczalnych, oraz trzy specyficzne typy wpisów kontroli dostępu, które mogą występować dla obiektów Active Directory.                                                                                                                                                                                                                                                            |
| Flagi                      | Zbiór bitowych flag kontrolujących dziedziczenie i audytowanie.                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Rozmiar                    | Liczba bajtów pamięci, które są przydzielane dla wpisu kontroli dostępu.                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Maska dostępu              | 32-bitowa wartość, której bity odpowiadają prawom dostępu do obiektu. Bity mogą być ustawione na wartość 1 lub 0, ale znaczenie ustawienia zależy od typu wpisu kontroli dostępu. Na przykład, jeśli bit odpowiadający prawu do odczytu uprawnień jest ustawiony na wartość 1, a typ wpisu kontroli dostępu to Odmowa, wpis kontroli dostępu odmawia prawo do odczytu uprawnień obiektu. Jeśli ten sam bit jest ustawiony na wartość 1, ale typ wpisu kontroli dostępu to Zezwolenie, wpis kontroli dostępu przyznaje prawo do odczytu uprawnień obiektu. Szczegółowe informacje na temat maski dostępu znajdują się w następnej tabeli. |
| SID                        | Identyfikuje użytkownika lub grupę, której dostęp jest kontrolowany lub monitorowany przez ten wpis kontroli dostępu.                                                                                                                                                                                                                                                                                                                                                                                     |

### Układ maski dostępu

| Bit (Zakres) | Znaczenie                          | Opis/Przykład                             |
| ------------ | ---------------------------------- | ----------------------------------------- |
| 0 - 15       | Prawa dostępu specyficzne dla obiektu | Odczyt danych, Wykonanie, Dołączanie danych |
| 16 - 22      | Standardowe prawa dostępu          | Usuwanie, Zapisywanie listy ACL, Zapisywanie właściciela |
| 23           | Może uzyskać dostęp do listy ACL zabezpieczeń |                                           |
| 24 - 27      | Zarezerwowane                       |                                           |
| 28           | Ogólny ALL (Odczyt, Zapis, Wykonanie) | Wszystko poniżej                          |
| 29           | Ogólny Wykonanie                    | Wszystko, co jest niezbędne do uruchomienia programu |
| 30           | Ogólny Zapis                        | Wszystko, co jest niezbędne do zapisu do pliku |
| 31           | Ogólny Odczyt                       | Wszystko, co jest niezbędne do odczytu pliku |

## Odwołania

* [https://www.ntfs.com/ntfs-permissions-acl-use.htm](https
