# Artefatos de Navegador

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) no github.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir e **automatizar fluxos de trabalho** com as ferramentas comunitárias **mais avançadas** do mundo.\
Obtenha Acesso Hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Artefatos de Navegadores <a href="#3def" id="3def"></a>

Quando falamos sobre artefatos de navegadores, nos referimos a histórico de navegação, favoritos, lista de arquivos baixados, dados de cache, etc.

Esses artefatos são arquivos armazenados em pastas específicas no sistema operacional.

Cada navegador armazena seus arquivos em um local diferente dos outros navegadores e todos têm nomes diferentes, mas todos armazenam (na maioria das vezes) o mesmo tipo de dados (artefatos).

Vamos dar uma olhada nos artefatos mais comuns armazenados pelos navegadores.

* **Histórico de Navegação:** Contém dados sobre o histórico de navegação do usuário. Pode ser usado para rastrear se o usuário visitou alguns sites maliciosos, por exemplo.
* **Dados de Autocompletar:** São os dados que o navegador sugere com base no que você pesquisa mais. Pode ser usado em conjunto com o histórico de navegação para obter mais informações.
* **Favoritos:** Autoexplicativo.
* **Extensões e Add-ons:** Autoexplicativo.
* **Cache:** Ao navegar em sites, o navegador cria todos os tipos de dados de cache (imagens, arquivos javascript... etc) por vários motivos. Por exemplo, para acelerar o tempo de carregamento dos sites. Esses arquivos de cache podem ser uma grande fonte de dados durante uma investigação forense.
* **Logins:** Autoexplicativo.
* **Favicons:** São os pequenos ícones encontrados em abas, URLs, favoritos e similares. Podem ser usados como outra fonte para obter mais informações sobre o site ou locais visitados pelo usuário.
* **Sessões do Navegador:** Autoexplicativo.
* **Downloads:** Autoexplicativo.
* **Dados de Formulário:** Qualquer coisa digitada dentro de formulários é frequentemente armazenada pelo navegador, então na próxima vez que o usuário digitar algo em um formulário, o navegador pode sugerir dados previamente inseridos.
* **Miniaturas:** Autoexplicativo.
* **Custom Dictionary.txt**: Palavras adicionadas ao dicionário pelo usuário.

## Firefox

O Firefox cria a pasta de perfis em \~/_**.mozilla/firefox/**_ (Linux), em **/Users/$USER/Library/Application Support/Firefox/Profiles/** (MacOS), _**%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\\**_ (Windows)_**.**_\
Dentro desta pasta, o arquivo _**profiles.ini**_ deve aparecer com o(s) nome(s) do(s) perfil(is) do usuário.\
Cada perfil tem uma variável "**Path**" com o nome da pasta onde seus dados serão armazenados. A pasta deve estar **presente no mesmo diretório onde o \_profiles.ini**\_\*\* existe\*\*. Se não estiver, provavelmente foi excluída.

Dentro da pasta **de cada perfil** (_\~/.mozilla/firefox/\<ProfileName>/_) você deve ser capaz de encontrar os seguintes arquivos interessantes:

* _**places.sqlite**_ : Histórico (moz_places), favoritos (moz_bookmarks) e downloads (moz_annos). No Windows, a ferramenta [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) pode ser usada para ler o histórico dentro de _**places.sqlite**_.
* Consulta para extrair histórico: `select datetime(lastvisitdate/1000000,'unixepoch') as visit_date, url, title, visit_count, visit_type FROM moz_places,moz_historyvisits WHERE moz_places.id = moz_historyvisits.place_id;`
* Observe que um tipo de link é um número que indica:
* 1: Usuário seguiu um link
* 2: Usuário digitou a URL
* 3: Usuário usou um favorito
* 4: Carregado de Iframe
* 5: Acessado via redirecionamento HTTP 301
* 6: Acessado via redirecionamento HTTP 302
* 7: Arquivo baixado
* 8: Usuário seguiu um link dentro de um Iframe
* Consulta para extrair downloads: `SELECT datetime(lastModified/1000000,'unixepoch') AS down_date, content as File, url as URL FROM moz_places, moz_annos WHERE moz_places.id = moz_annos.place_id;`
*
* _**bookmarkbackups/**_ : Backups de favoritos
* _**formhistory.sqlite**_ : **Dados de formulários web** (como e-mails)
* _**handlers.json**_ : Manipuladores de protocolo (como, qual aplicativo vai lidar com o protocolo _mailto://_)
* _**persdict.dat**_ : Palavras adicionadas ao dicionário
* _**addons.json**_ e _**extensions.sqlite**_ : Addons e extensões instalados
* _**cookies.sqlite**_ : Contém **cookies.** [**MZCookiesView**](https://www.nirsoft.net/utils/mzcv.html) pode ser usado no Windows para inspecionar este arquivo.
*   _**cache2/entries**_ ou _**startupCache**_ : Dados de cache (\~350MB). Técnicas como **data carving** também podem ser usadas para obter os arquivos salvos no cache. [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html) pode ser usado para ver os **arquivos salvos no cache**.

Informações que podem ser obtidas:

* URL, Contagem de Buscas, Nome do Arquivo, Tipo de Conteúdo, Tamanho do Arquivo, Última Modificação, Última Busca, Última Modificação do Servidor, Resposta do Servidor
* _**favicons.sqlite**_ : Favicons
* _**prefs.js**_ : Configurações e Preferências
* _**downloads.sqlite**_ : Antigo banco de dados de downloads (agora está dentro de places.sqlite)
* _**thumbnails/**_ : Miniaturas
* _**logins.json**_ : Nomes de usuário e senhas criptografados
* **Proteção anti-phishing integrada do navegador:** `grep 'browser.safebrowsing' ~/Library/Application Support/Firefox/Profiles/*/prefs.js`
* Retornará “safebrowsing.malware.enabled” e “phishing.enabled” como falso se as configurações de pesquisa segura estiverem desativadas
* _**key4.db**_ ou _**key3.db**_ : Chave mestra?

Para tentar descriptografar a senha mestra, você pode usar [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
Com o seguinte script e chamada, você pode especificar um arquivo de senha para força bruta:

{% code title="brute.sh" %}
```bash
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
```markdown
{% endcode %}

![](<../../../.gitbook/assets/image (417).png>)

## Google Chrome

O Google Chrome cria o perfil dentro do diretório do usuário _**\~/.config/google-chrome/**_ (Linux), em _**C:\Users\XXX\AppData\Local\Google\Chrome\User Data\\**_ (Windows), ou em _**/Users/$USER/Library/Application Support/Google/Chrome/**_ (MacOS).
A maioria das informações será salva dentro das pastas _**Default/**_ ou _**ChromeDefaultData/**_ nos caminhos indicados anteriormente. Aqui você pode encontrar os seguintes arquivos interessantes:

* _**History**_: URLs, downloads e até palavras-chave pesquisadas. No Windows, você pode usar a ferramenta [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) para ler o histórico. A coluna "Tipo de Transição" significa:
  * Link: Usuário clicou em um link
  * Typed: A URL foi digitada
  * Auto Bookmark
  * Auto Subframe: Adicionar
  * Start page: Página inicial
  * Form Submit: Um formulário foi preenchido e enviado
  * Reloaded
* _**Cookies**_: Cookies. [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) pode ser usado para inspecionar os cookies.
* _**Cache**_: Cache. No Windows, você pode usar a ferramenta [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) para inspecionar o cache.
* _**Bookmarks**_: Favoritos
* _**Web Data**_: Histórico de formulários
* _**Favicons**_: Favicons
* _**Login Data**_: Informações de login (nomes de usuário, senhas...)
* _**Current Session**_ e _**Current Tabs**_: Dados da sessão atual e abas atuais
* _**Last Session**_ e _**Last Tabs**_: Estes arquivos contêm sites que estavam ativos no navegador quando o Chrome foi fechado pela última vez.
* _**Extensions**_: Pasta de extensões e complementos
* **Thumbnails** : Miniaturas
* **Preferences**: Este arquivo contém uma infinidade de informações úteis, como plugins, extensões, sites que usam geolocalização, pop-ups, notificações, prefetching de DNS, exceções de certificados e muito mais. Se você está tentando pesquisar se uma configuração específica do Chrome estava ativada, provavelmente encontrará essa configuração aqui.
* **Proteção anti-phishing integrada ao navegador:** `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`
* Você pode simplesmente usar grep para "**safebrowsing**" e procurar por `{"enabled: true,"}` no resultado para indicar que a proteção contra phishing e malware está ativada.

## **Recuperação de Dados do SQLite DB**

Como você pode observar nas seções anteriores, tanto o Chrome quanto o Firefox usam bancos de dados **SQLite** para armazenar dados. É possível **recuperar entradas excluídas usando a ferramenta** [**sqlparse**](https://github.com/padfoot999/sqlparse) **ou** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

O Internet Explorer armazena **dados** e **metadados** em locais diferentes. Os metadados permitirão encontrar os dados.

Os **metadados** podem ser encontrados na pasta `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` onde VX pode ser V01, V16 ou V24.
Na pasta anterior, você também pode encontrar o arquivo V01.log. Caso o **tempo modificado** deste arquivo e do arquivo WebcacheVX.data **sejam diferentes**, você pode precisar executar o comando `esentutl /r V01 /d` para **corrigir** possíveis **incompatibilidades**.

Uma vez **recuperado** este artefato (é um banco de dados ESE, photorec pode recuperá-lo com as opções Exchange Database ou EDB) você pode usar o programa [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) para abri-lo. Uma vez **aberto**, vá para a tabela chamada "**Containers**".

![](<../../../.gitbook/assets/image (446).png>)

Dentro desta tabela, você pode encontrar em quais outras tabelas ou contêineres cada parte da informação armazenada é salva. Seguindo isso, você pode encontrar as **localizações dos dados** armazenados pelos navegadores e os **metadados** que estão dentro.

**Observe que esta tabela indica metadados do cache para outras ferramentas da Microsoft também (por exemplo, skype)**

### Cache

Você pode usar a ferramenta [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) para inspecionar o cache. Você precisa indicar a pasta onde extraiu a data do cache.

#### Metadados

As informações de metadados sobre o cache armazenam:

* Nome do arquivo no disco
* SecureDIrectory: Localização do arquivo dentro dos diretórios de cache
* AccessCount: Número de vezes que foi salvo no cache
* URL: A origem da URL
* CreationTime: Primeira vez que foi armazenado no cache
* AccessedTime: Tempo em que o cache foi utilizado
* ModifiedTime: Última versão da página web
* ExpiryTime: Tempo em que o cache expirará

#### Arquivos

As informações do cache podem ser encontradas em _**%userprofile%\Appdata\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5**_ e _**%userprofile%\Appdata\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5\low**_

As informações dentro dessas pastas são um **instantâneo do que o usuário estava vendo**. Os caches têm um tamanho de **250 MB** e os timestamps indicam quando a página foi visitada (primeira vez, data de criação do NTFS, última vez, tempo de modificação do NTFS).

### Cookies

Você pode usar a ferramenta [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) para inspecionar os cookies. Você precisa indicar a pasta onde extraiu os cookies.

#### **Metadados**

As informações de metadados sobre os cookies armazenados:

* Nome do cookie no sistema de arquivos
* URL
* AccessCount: Número de vezes que os cookies foram enviados ao servidor
* CreationTime: Primeira vez que o cookie foi criado
* ModifiedTime: Última vez que o cookie foi modificado
* AccessedTime: Última vez que o cookie foi acessado
* ExpiryTime: Tempo de expiração do cookie

#### Arquivos

Os dados dos cookies podem ser encontrados em _**%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies**_ e _**%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies\low**_

Cookies de sessão residirão na memória e cookies persistentes no disco.

### Downloads

#### **Metadados**

Verificando a ferramenta [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) você pode encontrar o contêiner com os metadados dos downloads:

![](<../../../.gitbook/assets/image (445).png>)

Obtendo a informação da coluna "ResponseHeaders" você pode transformar de hex essa informação e obter a URL, o tipo de arquivo e a localização do arquivo baixado.

#### Arquivos

Procure no caminho _**%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory**_

### **Histórico**

A ferramenta [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) pode ser usada para ler o histórico. Mas primeiro, você precisa indicar o navegador nas opções avançadas e a localização dos arquivos de histórico extraídos.

#### **Metadados**

* ModifiedTime: Primeira vez que uma URL é encontrada
* AccessedTime: Última vez
* AccessCount: Número de vezes acessado

#### **Arquivos**

Pesquise em _**userprofile%\Appdata\Local\Microsoft\Windows\History\History.IE5**_ e _**userprofile%\Appdata\Local\Microsoft\Windows\History\Low\History.IE5**_

### **URLs Digitadas**

Essa informação pode ser encontrada dentro do registro NTDUSER.DAT no caminho:

* _**Software\Microsoft\InternetExplorer\TypedURLs**_
* Armazena as últimas 50 URLs digitadas pelo usuário
* _**Software\Microsoft\InternetExplorer\TypedURLsTime**_
* última vez que a URL foi digitada

## Microsoft Edge

Para analisar artefatos do Microsoft Edge, todas as **explicações sobre cache e localizações da seção anterior (IE 11) permanecem válidas** com a única diferença de que a localização base, neste caso, é _**%userprofile%\Appdata\Local\Packages**_ (como pode ser observado nos seguintes caminhos):

* Caminho do Perfil: _**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC**_
* Histórico, Cookies e Downloads: _**C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat**_
* Configurações, Favoritos e Lista de Leitura: _**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb**_
* Cache: _**C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC#!XXX\MicrosoftEdge\Cache**_
* Últimas sessões ativas: _**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active**_

## **Safari**

Os bancos de dados podem ser encontrados em `/Users/$User/Library/Safari`

* **History.db**: As tabelas `history_visits` _e_ `history_items` contêm informações sobre o histórico e timestamps.
* `sqlite3 ~/Library/Safari/History.db "SELECT h.visit_time, i.url FROM history_visits h INNER JOIN history_items i ON h.history_item = i.id"`
* **Downloads.plist**: Contém informações sobre os arquivos baixados.
* **Book-marks.plist**: URLs favoritas.
* **TopSites.plist**: Lista dos sites mais visitados que o usuário navega.
* **Extensions.plist**: Para recuperar uma lista antiga de extensões do navegador Safari.
* `plutil -p ~/Library/Safari/Extensions/Extensions.plist| grep "Bundle Directory Name" | sort --ignore-case`
* `pluginkit -mDvvv -p com.apple.Safari.extension`
* **UserNotificationPermissions.plist**: Domínios que têm permissão para enviar notificações.
* `plutil -p ~/Library/Safari/UserNotificationPermissions.plist | grep -a3 '"Permission" => 1'`
* **LastSession.plist**: Abas que estavam abertas na última vez que o usuário saiu do Safari.
* `plutil -p ~/Library/Safari/LastSession.plist | grep -iv sessionstate`
* **Proteção anti-phishing integrada ao navegador:** `defaults read com.apple.Safari WarnAboutFraudulentWebsites`
* A resposta deve ser 1 para indicar que a configuração está ativa

## Opera

Os bancos de dados podem ser encontrados em `/Users/$USER/Library/Application Support/com.operasoftware.Opera`

O Opera **armazena o histórico do navegador e os dados de download exatamente no mesmo formato que o Google Chrome**. Isso se aplica aos nomes dos arquivos, bem como aos nomes das tabelas.

* **Proteção anti-phishing integrada ao navegador:** `grep --color 'fraud_protection_enabled' ~/Library/Application Support/com.operasoftware.Opera/Preferences`
* **fraud_protection_enabled** deve ser **true**

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir e **automatizar fluxos de trabalho** facilmente, alimentados pelas ferramentas comunitárias **mais avançadas do mundo**.\
Obtenha Acesso Hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**merchandising oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas dicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
```
