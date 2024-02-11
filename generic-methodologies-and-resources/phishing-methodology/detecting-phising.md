# Wykrywanie Phishingu

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Wprowadzenie

Aby wykryć próbę phishingu, ważne jest **zrozumienie technik phishingowych, które są obecnie stosowane**. Na stronie nadrzędnej tego postu znajdziesz te informacje, więc jeśli nie wiesz, jakie techniki są obecnie stosowane, zalecam przeczytanie przynajmniej tej sekcji na stronie nadrzędnej.

Ten post opiera się na założeniu, że **atakujący będą próbowali naśladować lub używać nazwy domeny ofiary**. Jeśli twoja domena nazywa się `example.com`, a zostaniesz zhakowany za pomocą zupełnie innej nazwy domeny, na przykład `youwonthelottery.com`, te techniki nie odkryją tego.

## Wariacje nazw domenowych

Dość **łatwo** odkryć próby **phishingowe**, które będą używać **podobnej nazwy domeny** wewnątrz wiadomości e-mail.\
Wystarczy **wygenerować listę najbardziej prawdopodobnych nazw phishingowych**, które atakujący mogą użyć i **sprawdzić**, czy są **zarejestrowane**, lub po prostu sprawdzić, czy istnieje jakieś **IP**, które z nich korzysta.

### Wyszukiwanie podejrzanych domen

W tym celu można użyć dowolnego z poniższych narzędzi. Należy zauważyć, że te narzędzia automatycznie wykonują również żądania DNS, aby sprawdzić, czy domena ma przypisane jakieś IP:

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### Bitflipping

**Krótkie wyjaśnienie tej techniki znajdziesz na stronie nadrzędnej. Lub przeczytaj oryginalne badania na stronie [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**

Na przykład, 1-bitowa modyfikacja domeny microsoft.com może przekształcić ją w _windnws.com._\
**Atakujący mogą zarejestrować jak najwięcej domen z bit-flippingiem związanych z ofiarą, aby przekierować prawowitych użytkowników na swoją infrastrukturę**.

**Wszystkie możliwe nazwy domen z bit-flippingiem powinny być również monitorowane.**

### Podstawowe sprawdzenia

Po utworzeniu listy potencjalnie podejrzanych nazw domenowych powinieneś je **sprawdzić** (głównie porty HTTP i HTTPS), aby **sprawdzić, czy używają formularza logowania podobnego** do formularza logowania ofiary.\
Możesz również sprawdzić port 3333, aby sprawdzić, czy jest otwarty i uruchamia instancję `gophish`.\
Interesujące jest również **sprawdzenie, jak długo istnieje każda odkryta podejrzana domena**, im młodsza, tym większe ryzyko.\
Możesz również uzyskać **zrzuty ekranu** podejrzanej strony internetowej HTTP i/lub HTTPS, aby sprawdzić, czy jest podejrzana, a w takim przypadku **wejść na nią, aby dokładniej się przyjrzeć**.

### Zaawansowane sprawdzenia

Jeśli chcesz pójść o krok dalej, polecam **monitorować te podejrzane domeny i regularnie szukać kolejnych** (codziennie? to zajmuje tylko kilka sekund/minut). Powinieneś również **sprawdzić** otwarte **porty** powiązanych adresów IP i **szukać instancji `gophish` lub podobnych narzędzi** (tak, atakujący też popełniają błędy) oraz **monitorować strony internetowe HTTP i HTTPS podejrzanych domen i subdomen**, aby sprawdzić, czy skopiowano jakikolwiek formularz logowania z stron internetowych ofiary.\
Aby to **zautomatyzować**, zalecam posiadanie listy formularzy logowania domen ofiary, przeszukiwanie podejrzanych stron internetowych i porównywanie każdego znalezionego formularza logowania w podejrzanych domenach z każdym formularzem logowania domeny ofiary za pomocą czegoś takiego jak `ssdeep`.\
Jeśli zlokalizowałeś formularze logowania podejrzanych domen, możesz spróbować **wysłać fałszywe dane uwierzytelniające** i **sprawdzić, czy przekierowuje cię do domeny ofiary**.

## Nazwy domen z użyciem słów kluczowych

Na stronie nadrzędnej wspomniano również o technice wariacji nazw domenowych, polegającej na umieszczeniu **nazwy domeny ofiary w większej domenie** (np. paypal-financial.com dla paypal.com).

### Transparentność certyfikatów

Nie jest możliwe zastosowanie poprzedniego podejścia "Brute-Force", ale faktycznie **można odkryć takie próby phishingowe** również dzięki transparentności certyfikatów. Za każdym razem, gdy certyfikat jest wydawany przez CA, szczegóły są udostępniane publicznie. Oznacza to, że czytając transparentność certyfikatów lub nawet monitorując ją, **można znaleźć domeny, które używają słowa kluczowego w swojej nazwie**. Na przykład, jeśli atakujący generuje certyfikat [https://paypal-financial.com](https://paypal-financial.com), przeglądając certyfikat, można znaleźć słowo kluczowe "paypal" i wiedzieć, że używana jest podejrzana wiadomość e-mail.

Post [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) sugeruje, że można użyć Censys do wyszukiwania certyfikatów dotyczących określonego słowa kluczowego i filtrowania ich według daty (tylko "nowe" certyfikaty) oraz według wydawcy CA "Let's Encrypt":

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../.gitbook/assets/image (390).png>)

Jednak można to zrobić "tak samo" za pomocą bezpłatnej strony internetowej [**crt.sh**](https://crt.sh). Możesz **wyszukać słowo kluczowe** i **filtrować wyniki według daty i CA**, jeśli chcesz.

![](<../../.gitbook/assets/image (391).png>)

Korzystając z tej ostatniej opcji, możesz nawet użyć pola "Matching Identities", aby sprawdzić, czy jakakolwiek tożsamość z prawdziwej domeny pasuje do którejś z podejrzanych domen (należy pamiętać, że podejrzana domena może być fałszywym alarmem).

**Inną alternatywą** jest fantastyczny projekt o nazwie [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream dostarcza strumień w czasie rzeczywistym nowo generowanych certyfikatów, które można użyć do wykrywania określonych słów kluczowych
### **Nowe domeny**

**Jedną ostatnią alternatywą** jest zebranie listy **nowo zarejestrowanych domen** dla niektórych TLD ([Whoxy](https://www.whoxy.com/newly-registered-domains/) dostarcza taką usługę) i **sprawdzenie słów kluczowych w tych domenach**. Jednak długie domeny zazwyczaj używają jednej lub więcej subdomen, dlatego słowo kluczowe nie pojawi się wewnątrz FLD i nie będzie można znaleźć subdomeny phishingowej.

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
