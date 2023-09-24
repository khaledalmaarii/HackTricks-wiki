# Artefatos do Navegador

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e **automatizar fluxos de trabalho** com as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Artefatos dos Navegadores <a href="#3def" id="3def"></a>

Quando falamos sobre artefatos dos navegadores, estamos nos referindo ao histórico de navegação, favoritos, lista de arquivos baixados, dados em cache, etc.

Esses artefatos são arquivos armazenados em pastas específicas no sistema operacional.

Cada navegador armazena seus arquivos em um local diferente dos outros navegadores e todos eles têm nomes diferentes, mas geralmente armazenam o mesmo tipo de dados (artefatos).

Vamos dar uma olhada nos artefatos mais comuns armazenados pelos navegadores.

* **Histórico de Navegação:** Contém dados sobre o histórico de navegação do usuário. Pode ser usado para rastrear se o usuário visitou alguns sites maliciosos, por exemplo.
* **Dados de Autocompletar:** Esses são os dados que o navegador sugere com base no que você mais pesquisa. Pode ser usado em conjunto com o histórico de navegação para obter mais informações.
* **Favoritos:** Autoexplicativo.
* **Extensões e Complementos:** Autoexplicativo.
* **Cache:** Ao navegar em sites, o navegador cria todos os tipos de dados em cache (imagens, arquivos JavaScript, etc.) por muitas razões. Por exemplo, para acelerar o tempo de carregamento dos sites. Esses arquivos em cache podem ser uma ótima fonte de dados durante uma investigação forense.
* **Logins:** Autoexplicativo.
* **Favicons:** São os pequenos ícones encontrados em guias, URLs, favoritos e outros. Eles podem ser usados como outra fonte para obter mais informações sobre o site ou os lugares visitados pelo usuário.
* **Sessões do Navegador:** Autoexplicativo.
* **Downloads**: Autoexplicativo.
* **Dados de Formulário:** Qualquer coisa digitada em formulários geralmente é armazenada pelo navegador, para que da próxima vez que o usuário digitar algo em um formulário, o navegador possa sugerir dados inseridos anteriormente.
* **Miniaturas:** Autoexplicativo.
* **Custom Dictionary.txt**: Palavras adicionadas ao dicionário pelo usuário.

## Firefox

O Firefox cria a pasta de perfis em \~/_**.mozilla/firefox/**_ (Linux), em **/Users/$USER/Library/Application Support/Firefox/Profiles/** (MacOS), _**%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\\**_ (Windows)_**.**_\
Dentro desta pasta, o arquivo _**profiles.ini**_ deve aparecer com o nome(s) do(s) perfil(s) do usuário.\
Cada perfil tem uma variável "**Path**" com o nome da pasta onde seus dados serão armazenados. A pasta deve estar **presente no mesmo diretório onde o \_profiles.ini**\_\*\* existe\*\*. Se não estiver, provavelmente foi excluída.

Dentro da pasta **de cada perfil** (_\~/.mozilla/firefox/\<NomeDoPerfil>/_) você deve ser capaz de encontrar os seguintes arquivos interessantes:

* _**places.sqlite**_ : Histórico (moz\_\_places), favoritos (moz\_bookmarks) e downloads (moz\_\_annos). No Windows, a ferramenta [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html) pode ser usada para ler o histórico dentro do arquivo _**places.sqlite**_.
* Consulta para extrair o histórico: `select datetime(lastvisitdate/1000000,'unixepoch') as visit_date, url, title, visit_count, visit_type FROM moz_places,moz_historyvisits WHERE moz_places.id = moz_historyvisits.place_id;`
* Observe que o tipo de link é um número que indica:
* 1: Usuário seguiu um link
* 2: Usuário digitou a URL
* 3: Usuário usou um favorito
* 4: Carregado de um Iframe
* 5: Acessado via redirecionamento HTTP 301
* 6: Acessado via redirecionamento HTTP 302
* 7: Arquivo baixado
* 8: Usuário seguiu um link dentro de um Iframe
* Consulta para extrair downloads: `SELECT datetime(lastModified/1000000,'unixepoch') AS down_date, content as File, url as URL FROM moz_places, moz_annos WHERE moz_places.id = moz_annos.place_id;`
*
* _**bookmarkbackups/**_ : Backups de favoritos
* _**formhistory.sqlite**_ : **Dados de formulário da web** (como e-mails)
* _**handlers.json**_ : Manipuladores de protocolo (como, qual aplicativo vai lidar com o protocolo _mailto://_)
* _**persdict.dat**_ : Palavras adicionadas ao dicionário
* _**addons.json**_ e \_**extensions.sqlite** \_ : Complementos e extensões instalados
* _**cookies.sqlite**_ : Contém **cookies**. O [**MZCookiesView**](https://www.nirsoft.net/utils/mzcv.html) pode ser usado no Windows para inspecionar este arquivo.
*   _**cache2/entries**_ ou _**startupCache**_ : Dados em cache (\~350MB). Truques como **data carving** também podem ser usados para obter os arquivos salvos em cache. O [MozillaCacheView](https://www.nirsoft.net/utils/mozilla\_cache\_viewer.html) pode ser usado para ver os **arquivos salvos em cache**.

Informações que podem ser obtidas:

* URL, Contagem de busca, Nome do arquivo, Tipo de conteúdo, Tamanho do arquivo, Última modificação, Última busca, Última modificação do servidor, Resposta do servidor
* _**favicons.sqlite**_ : Favicons
* _**prefs.js**_ : Configurações e Preferências
* _**downloads.sqlite**_ : Banco de dados antigo de downloads (agora está dentro de places.sqlite)
* _**thumbnails/**_ : Miniaturas
* _**logins.json**_ : Nomes de usuário e senhas criptografados
* **Anti-phishing integrado no navegador:** `grep 'browser.safebrowsing' ~/Library/Application Support/Firefox/Profiles/*/prefs.js`
* Retornará "safebrowsing.malware.enabled" e "phishing.enabled" como falso se as configurações de pesquisa segura tiverem sido desativadas
* _**key4.db**_ ou _**key3.db**_ : Chave mestra?

Para tentar descriptografar a senha mestra, você pode usar [https://github.com/unode/firefox\_decrypt](https://github.com/unode/firefox\_decrypt)\
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
{% endcode %}

![](<../../../.gitbook/assets/image (417).png>)

## Google Chrome

O Google Chrome cria o perfil dentro da pasta do usuário _**\~/.config/google-chrome/**_ (Linux), em _**C:\Users\XXX\AppData\Local\Google\Chrome\User Data\\**_ (Windows), ou em \_**/Users/$USER/Library/Application Support/Google/Chrome/** \_ (MacOS).\
A maioria das informações será salva dentro das pastas _**Default/**_ ou _**ChromeDefaultData/**_ nos caminhos indicados anteriormente. Aqui você pode encontrar os seguintes arquivos interessantes:

* _**History**_: URLs, downloads e até palavras-chave pesquisadas. No Windows, você pode usar a ferramenta [ChromeHistoryView](https://www.nirsoft.net/utils/chrome\_history\_view.html) para ler o histórico. A coluna "Tipo de Transição" significa:
* Link: Usuário clicou em um link
* Digitado: A URL foi digitada
* Auto Favorito
* Auto Subframe: Adicionar
* Página inicial: Página inicial
* Enviar formulário: Um formulário foi preenchido e enviado
* Recarregado
* _**Cookies**_: Cookies. [ChromeCookiesView](https://www.nirsoft.net/utils/chrome\_cookies\_view.html) pode ser usado para inspecionar os cookies.
* _**Cache**_: Cache. No Windows, você pode usar a ferramenta [ChromeCacheView](https://www.nirsoft.net/utils/chrome\_cache\_view.html) para inspecionar o cache.
* _**Favoritos**_: Favoritos
* _**Dados da Web**_: Histórico de formulários
* _**Favicons**_: Favicons
* _**Dados de Login**_: Informações de login (nomes de usuário, senhas...)
* _**Sessão Atual**_ e _**Guias Atuais**_: Dados da sessão atual e guias atuais
* _**Última Sessão**_ e _**Últimas Guias**_: Esses arquivos contêm os sites que estavam ativos no navegador quando o Chrome foi fechado pela última vez.
* _**Extensões**_: Pasta de extensões e complementos
* **Miniaturas** : Miniaturas
* **Preferências**: Este arquivo contém uma infinidade de informações úteis, como plugins, extensões, sites que usam geolocalização, pop-ups, notificações, pré-busca DNS, exceções de certificado e muito mais. Se você está tentando pesquisar se uma configuração específica do Chrome estava ativada ou não, provavelmente encontrará essa configuração aqui.
* **Anti-phishing integrado do navegador:** `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`
* Você pode simplesmente usar o comando grep para "safebrowsing" e procurar por `{"enabled: true,"}` no resultado para indicar que a proteção contra phishing e malware está ativada.

## **Recuperação de Dados do Banco de Dados SQLite**

Como você pode observar nas seções anteriores, tanto o Chrome quanto o Firefox usam bancos de dados **SQLite** para armazenar os dados. É possível **recuperar entradas excluídas usando a ferramenta** [**sqlparse**](https://github.com/padfoot999/sqlparse) **ou** [**sqlparse\_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

O Internet Explorer armazena **dados** e **metadados** em locais diferentes. Os metadados permitirão encontrar os dados.

Os **metadados** podem ser encontrados na pasta `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data`, onde VX pode ser V01, V16 ou V24.\
Na pasta anterior, você também pode encontrar o arquivo V01.log. Caso o **horário de modificação** deste arquivo e o arquivo WebcacheVX.data **sejam diferentes**, pode ser necessário executar o comando `esentutl /r V01 /d` para **corrigir** possíveis **incompatibilidades**.

Uma vez que este artefato seja **recuperado** (é um banco de dados ESE, o photorec pode recuperá-lo com as opções Banco de Dados Exchange ou EDB), você pode usar o programa [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html) para abri-lo. Uma vez **aberto**, vá para a tabela chamada "**Containers**".

![](<../../../.gitbook/assets/image (446).png>)

Dentro desta tabela, você pode encontrar em quais outras tabelas ou contêineres cada parte das informações armazenadas é salva. Em seguida, você pode encontrar as **localizações dos dados** armazenados pelos navegadores e os **metadados** que estão dentro.

**Observe que esta tabela indica metadados do cache para outras ferramentas da Microsoft também (por exemplo, skype)**

### Cache

Você pode usar a ferramenta [IECacheView](https://www.nirsoft.net/utils/ie\_cache\_viewer.html) para inspecionar o cache. Você precisa indicar a pasta onde extraiu os dados do cache.

#### Metadados

As informações de metadados sobre o cache armazenam:

* Nome do arquivo no disco
* SecureDIrectory: Localização do arquivo dentro dos diretórios de cache
* AccessCount: Número de vezes que foi salvo no cache
* URL: A origem da URL
* CreationTime: Primeira vez que foi armazenado em cache
* AccessedTime: Hora em que o cache foi usado
* ModifiedTime: Última versão da página
* ExpiryTime: Hora em que o cache expirará

#### Arquivos

As informações do cache podem ser encontradas em _**%userprofile%\Appdata\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5**_ e _**%userprofile%\Appdata\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5\low**_

As informações dentro dessas pastas são um **instantâneo do que o usuário estava vendo**. Os caches têm um tamanho de **250 MB** e os carimbos de data e hora indicam quando a página foi visitada (primeira vez, data de criação do NTFS, última vez, data de modificação do NTFS).

### Cookies

Você pode usar a ferramenta [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) para inspecionar os cookies. Você precisa indicar a pasta onde extraiu os cookies.

#### **Metadados**

As informações de metadados sobre os cookies armazenados:

* Nome do cookie no sistema de arquivos
* URL
* AccessCount: Número de vezes que os cookies foram enviados para o servidor
* CreationTime: Primeira vez que o cookie foi criado
* ModifiedTime: Última vez que o cookie foi modificado
* AccessedTime: Última vez que o cookie foi acessado
* ExpiryTime: Hora de expiração do cookie

#### Arquivos

Os dados dos cookies podem ser encontrados em _**%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies**_ e _**%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies\low**_

Os cookies de sessão residirão na memória e os cookies persistentes no disco.
### Downloads

#### **Metadados**

Verificando a ferramenta [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html), você pode encontrar o contêiner com os metadados dos downloads:

![](<../../../.gitbook/assets/image (445).png>)

Obtendo as informações da coluna "ResponseHeaders", você pode transformar essas informações de hexadecimal e obter a URL, o tipo de arquivo e a localização do arquivo baixado.

#### Arquivos

Procure no caminho _**%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory**_

### **Histórico**

A ferramenta [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html) pode ser usada para ler o histórico. Mas primeiro, você precisa indicar o navegador nas opções avançadas e a localização dos arquivos de histórico extraídos.

#### **Metadados**

* ModifiedTime: Primeira vez que uma URL é encontrada
* AccessedTime: Última vez
* AccessCount: Número de vezes acessado

#### **Arquivos**

Pesquise em _**userprofile%\Appdata\Local\Microsoft\Windows\History\History.IE5**_ e _**userprofile%\Appdata\Local\Microsoft\Windows\History\Low\History.IE5**_

### **URLs digitadas**

Essas informações podem ser encontradas no registro NTDUSER.DAT no caminho:

* _**Software\Microsoft\InternetExplorer\TypedURLs**_
* Armazena as últimas 50 URLs digitadas pelo usuário
* _**Software\Microsoft\InternetExplorer\TypedURLsTime**_
* última vez que a URL foi digitada

## Microsoft Edge

Para analisar os artefatos do Microsoft Edge, todas as **explicações sobre cache e localizações da seção anterior (IE 11) permanecem válidas**, com a única diferença de que a localização base, neste caso, é _**%userprofile%\Appdata\Local\Packages**_ (como pode ser observado nos seguintes caminhos):

* Caminho do perfil: _**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC**_
* Histórico, Cookies e Downloads: _**C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat**_
* Configurações, Favoritos e Lista de Leitura: _**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb**_
* Cache: _**C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC#!XXX\MicrosoftEdge\Cache**_
* Últimas sessões ativas: _**C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge\_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active**_

## **Safari**

Os bancos de dados podem ser encontrados em `/Users/$User/Library/Safari`

* **History.db**: As tabelas `history_visits` _e_ `history_items` contêm informações sobre o histórico e os carimbos de data e hora.
* `sqlite3 ~/Library/Safari/History.db "SELECT h.visit_time, i.url FROM history_visits h INNER JOIN history_items i ON h.history_item = i.id"`
* **Downloads.plist**: Contém informações sobre os arquivos baixados.
* **Book-marks.plist**: URLs marcadas como favoritas.
* **TopSites.plist**: Lista dos sites mais visitados pelo usuário.
* **Extensions.plist**: Para recuperar uma lista antiga de extensões do navegador Safari.
* `plutil -p ~/Library/Safari/Extensions/Extensions.plist| grep "Bundle Directory Name" | sort --ignore-case`
* `pluginkit -mDvvv -p com.apple.Safari.extension`
* **UserNotificationPermissions.plist**: Domínios que têm permissão para enviar notificações.
* `plutil -p ~/Library/Safari/UserNotificationPermissions.plist | grep -a3 '"Permission" => 1'`
* **LastSession.plist**: Abas que foram abertas da última vez que o usuário saiu do Safari.
* `plutil -p ~/Library/Safari/LastSession.plist | grep -iv sessionstate`
* **Anti-phishing integrado do navegador:** `defaults read com.apple.Safari WarnAboutFraudulentWebsites`
* A resposta deve ser 1 para indicar que a configuração está ativa

## Opera

Os bancos de dados podem ser encontrados em `/Users/$USER/Library/Application Support/com.operasoftware.Opera`

O Opera **armazena o histórico do navegador e os dados de download no mesmo formato que o Google Chrome**. Isso se aplica aos nomes dos arquivos, bem como aos nomes das tabelas.

* **Anti-phishing integrado do navegador:** `grep --color 'fraud_protection_enabled' ~/Library/Application Support/com.operasoftware.Opera/Preferences`
* **fraud\_protection\_enabled** deve ser **true**

<figure><img src="../../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para criar e **automatizar fluxos de trabalho** com facilidade, usando as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje mesmo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? Ou gostaria de ter acesso à **versão mais recente do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo Telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
