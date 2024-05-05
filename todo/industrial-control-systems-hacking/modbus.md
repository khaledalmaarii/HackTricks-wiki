# Protokół Modbus

## Wprowadzenie do protokołu Modbus

Protokół Modbus jest powszechnie używanym protokołem w systemach automatyzacji i sterowania przemysłowego. Modbus umożliwia komunikację między różnymi urządzeniami, takimi jak programowalne sterowniki logiczne (PLC), sensory, aktuatory i inne urządzenia przemysłowe. Zrozumienie protokołu Modbus jest kluczowe, ponieważ jest to najczęściej używany protokół komunikacyjny w systemach ICS i posiada wiele potencjalnych powierzchni ataku do podsłuchiwania oraz wstrzykiwania poleceń do PLC.

Tutaj koncepcje są przedstawione punkt po punkcie, zapewniając kontekst protokołu i jego charakterystykę działania. Największym wyzwaniem w zakresie bezpieczeństwa systemów ICS jest koszt implementacji i aktualizacji. Te protokoły i standardy zostały zaprojektowane w latach 80. i 90., a mimo to są wciąż powszechnie używane. Ponieważ przemysł posiada wiele urządzeń i połączeń, aktualizacja urządzeń jest bardzo trudna, co daje hakerom przewagę w radzeniu sobie z przestarzałymi protokołami. Ataki na Modbus są praktycznie nieuniknione, ponieważ będzie on używany bez aktualizacji, a jego działanie jest kluczowe dla przemysłu.

## Architektura klient-serwer

Protokół Modbus jest zazwyczaj używany w architekturze klient-serwer, gdzie urządzenie nadrzędne (klient) inicjuje komunikację z jednym lub większą ilością urządzeń podrzędnych (serwerów). Jest to również nazywane architekturą master-slave, która jest szeroko stosowana w elektronice i IoT z SPI, I2C, itp.

## Wersje szeregowe i Ethernet

Protokół Modbus jest zaprojektowany zarówno do komunikacji szeregowej, jak i komunikacji Ethernetowej. Komunikacja szeregowa jest powszechnie używana w systemach dziedzicznych, podczas gdy nowoczesne urządzenia obsługują Ethernet, który oferuje wysokie prędkości transmisji danych i jest bardziej odpowiedni dla nowoczesnych sieci przemysłowych.

## Reprezentacja danych

Dane są przesyłane w protokole Modbus jako ASCII lub binarne, chociaż format binarny jest używany ze względu na jego kompatybilność z starszymi urządzeniami.

## Kody funkcji

Protokół Modbus działa poprzez przesyłanie określonych kodów funkcji, które służą do operowania na PLC i różnych urządzeniach sterujących. Ta część jest ważna do zrozumienia, ponieważ ataki typu replay mogą być wykonywane poprzez ponowne przesyłanie kodów funkcji. Starsze urządzenia nie obsługują żadnego szyfrowania w stosunku do transmisji danych i zazwyczaj posiadają długie przewody, co prowadzi do manipulacji tymi przewodami oraz przechwytywania/wstrzykiwania danych.

## Adresowanie w protokole Modbus

Każde urządzenie w sieci ma swój unikalny adres, który jest niezbędny do komunikacji między urządzeniami. Protokoły takie jak Modbus RTU, Modbus TCP, itp. są używane do implementacji adresowania i pełnią rolę warstwy transportowej dla transmisji danych. Dane przesyłane są w formacie protokołu Modbus zawierającym wiadomość.

Ponadto, Modbus również implementuje sprawdzanie błędów w celu zapewnienia integralności przesyłanych danych. Ale przede wszystkim, Modbus jest standardem otwartym i każdy może go zaimplementować w swoich urządzeniach. Spowodowało to, że ten protokół stał się globalnym standardem i jest powszechnie stosowany w przemyśle automatyki.

Ze względu na swoje szerokie zastosowanie i brak aktualizacji, atakowanie Modbus daje znaczną przewagę ze względu na jego powierzchnię ataku. ICS jest w dużej mierze zależny od komunikacji między urządzeniami, a jakiekolwiek ataki na nie mogą być niebezpieczne dla działania systemów przemysłowych. Ataki takie jak replay, wstrzykiwanie danych, podsłuchiwanie i ujawnianie danych, Denial of Service, fałszowanie danych, itp. mogą być przeprowadzane, jeśli medium transmisji zostanie zidentyfikowane przez atakującego.
