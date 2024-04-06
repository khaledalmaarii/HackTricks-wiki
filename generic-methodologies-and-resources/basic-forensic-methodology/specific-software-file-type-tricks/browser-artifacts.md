# Artefatos do Navegador

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e **automatizar fluxos de trabalho** facilmente com as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Artefatos dos Navegadores <a href="#id-3def" id="id-3def"></a>

Os artefatos do navegador incluem vários tipos de dados armazenados pelos navegadores da web, como histórico de navegação, favoritos e dados de cache. Esses artefatos são mantidos em pastas específicas dentro do sistema operacional, diferindo em localização e nome entre os navegadores, mas geralmente armazenando tipos de dados semelhantes.

Aqui está um resumo dos artefatos de navegador mais comuns:

* **Histórico de Navegação**: Registra as visitas do usuário a sites, útil para identificar visitas a sites maliciosos.
* **Dados de Autocompletar**: Sugestões com base em pesquisas frequentes, oferecendo insights quando combinados com o histórico de navegação.
* **Favoritos**: Sites salvos pelo usuário para acesso rápido.
* **Extensões e Complementos**: Extensões do navegador ou complementos instalados pelo usuário.
* **Cache**: Armazena conteúdo da web (por exemplo, imagens, arquivos JavaScript) para melhorar os tempos de carregamento do site, valioso para análise forense.
* **Logins**: Credenciais de login armazenadas.
* **Favicons**: Ícones associados a sites, aparecendo em abas e favoritos, úteis para obter informações adicionais sobre as visitas do usuário.
* **Sessões do Navegador**: Dados relacionados a sessões de navegador abertas.
* **Downloads**: Registros de arquivos baixados pelo navegador.
* **Dados de Formulário**: Informações inseridas em formulários da web, salvos para sugestões de preenchimento automático futuras.
* **Miniaturas**: Imagens de visualização de sites.
* **Dicionário Personalizado.txt**: Palavras adicionadas pelo usuário ao dicionário do navegador.

## Firefox

O Firefox organiza os dados do usuário em perfis, armazenados em locais específicos com base no sistema operacional:

* **Linux**: `~/.mozilla/firefox/`
* **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
* **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Um arquivo `profiles.ini` dentro desses diretórios lista os perfis de usuário. Os dados de cada perfil são armazenados em uma pasta nomeada com a variável `Path` dentro do `profiles.ini`, localizada no mesmo diretório que o `profiles.ini` em si. Se a pasta de um perfil estiver ausente, ela pode ter sido excluída.

Dentro de cada pasta de perfil, você pode encontrar vários arquivos importantes:

* **places.sqlite**: Armazena histórico, favoritos e downloads. Ferramentas como [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html) no Windows podem acessar os dados de histórico.
* Use consultas SQL específicas para extrair informações de histórico e downloads.
* **bookmarkbackups**: Contém backups de favoritos.
* **formhistory.sqlite**: Armazena dados de formulários da web.
* **handlers.json**: Gerencia manipuladores de protocolo.
* **persdict.dat**: Palavras do dicionário personalizado.
* **addons.json** e **extensions.sqlite**: Informações sobre extensões e complementos instalados.
* **cookies.sqlite**: Armazenamento de cookies, com [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) disponível para inspeção no Windows.
* **cache2/entries** ou **startupCache**: Dados de cache, acessíveis por meio de ferramentas como [MozillaCacheView](https://www.nirsoft.net/utils/mozilla\_cache\_viewer.html).
* **favicons.sqlite**: Armazena favicons.
* **prefs.js**: Configurações e preferências do usuário.
* **downloads.sqlite**: Banco de dados de downloads antigos, agora integrado ao places.sqlite.
* **miniaturas**: Miniaturas de sites.
* **logins.json**: Informações de login criptografadas.
* **key4.db** ou **key3.db**: Armazena chaves de criptografia para proteger informações sensíveis.

Além disso, verificar as configurações anti-phishing do navegador pode ser feito pesquisando por entradas `browser.safebrowsing` em `prefs.js`, indicando se os recursos de navegação segura estão ativados ou desativados.

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

O Google Chrome armazena perfis de usuários em locais específicos com base no sistema operacional:

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Dentro desses diretórios, a maioria dos dados do usuário pode ser encontrada nas pastas **Default/** ou **ChromeDefaultData/**. Os seguintes arquivos contêm dados significativos:

- **Histórico**: Contém URLs, downloads e palavras-chave de pesquisa. No Windows, [ChromeHistoryView](https://www.nirsoft.net/utils/chrome\_history\_view.html) pode ser usado para ler o histórico. A coluna "Tipo de Transição" tem vários significados, incluindo cliques do usuário em links, URLs digitadas, envios de formulários e recarregamentos de página.
- **Cookies**: Armazena cookies. Para inspeção, [ChromeCookiesView](https://www.nirsoft.net/utils/chrome\_cookies\_view.html) está disponível.
- **Cache**: Mantém dados em cache. Para inspeção, usuários do Windows podem utilizar [ChromeCacheView](https://www.nirsoft.net/utils/chrome\_cache\_view.html).
- **Favoritos**: Favoritos do usuário.
- **Dados da Web**: Contém histórico de formulários.
- **Favicons**: Armazena favicons de sites.
- **Dados de Login**: Inclui credenciais de login como nomes de usuário e senhas.
- **Sessão Atual**/**Abas Atuais**: Dados sobre a sessão de navegação atual e abas abertas.
- **Última Sessão**/**Últimas Abas**: Informações sobre os sites ativos durante a última sessão antes do fechamento do Chrome.
- **Extensões**: Diretórios para extensões e complementos do navegador.
- **Miniaturas**: Armazena miniaturas de sites.
- **Preferências**: Um arquivo rico em informações, incluindo configurações para plugins, extensões, pop-ups, notificações e mais.
- **Anti-phishing integrado do navegador**: Para verificar se a proteção contra phishing e malware está ativada, execute `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Procure por `{"enabled: true,"}` na saída.

## **Recuperação de Dados do Banco de Dados SQLite**

Como observado nas seções anteriores, tanto o Chrome quanto o Firefox usam bancos de dados **SQLite** para armazenar os dados. É possível **recuperar entradas excluídas usando a ferramenta** [**sqlparse**](https://github.com/padfoot999/sqlparse) **ou** [**sqlparse\_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

O Internet Explorer 11 gerencia seus dados e metadados em vários locais, auxiliando na separação das informações armazenadas e seus detalhes correspondentes para fácil acesso e gerenciamento.

### Armazenamento de Metadados

Os metadados do Internet Explorer são armazenados em `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (sendo VX V01, V16 ou V24). Além disso, o arquivo `V01.log` pode mostrar discrepâncias de tempo de modificação com `WebcacheVX.data`, indicando a necessidade de reparo usando `esentutl /r V01 /d`. Esses metadados, alojados em um banco de dados ESE, podem ser recuperados e inspecionados usando ferramentas como photorec e [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html), respectivamente. Na tabela **Containers**, é possível discernir as tabelas ou contêineres específicos onde cada segmento de dados é armazenado, incluindo detalhes de cache para outras ferramentas da Microsoft, como o Skype.

### Inspeção de Cache

A ferramenta [IECacheView](https://www.nirsoft.net/utils/ie\_cache\_viewer.html) permite a inspeção de cache, exigindo a localização da pasta de extração de dados de cache. Os metadados para cache incluem nome do arquivo, diretório, contagem de acessos, origem do URL e carimbos de data e hora indicando a criação, acesso, modificação e expiração do cache.

### Gerenciamento de Cookies

Os cookies podem ser explorados usando [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), com metadados que abrangem nomes, URLs, contagens de acesso e vários detalhes relacionados ao tempo. Cookies persistentes são armazenados em `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, enquanto cookies de sessão residem na memória.

### Detalhes de Downloads

Metadados de downloads são acessíveis via [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html), com contêineres específicos contendo dados como URL, tipo de arquivo e localização do download. Os arquivos físicos podem ser encontrados em `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Histórico de Navegação

Para revisar o histórico de navegação, pode-se usar [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html), exigindo a localização dos arquivos de histórico extraídos e a configuração para o Internet Explorer. Os metadados aqui incluem tempos de modificação e acesso, juntamente com contagens de acesso. Os arquivos de histórico estão localizados em `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### URLs Digitadas

URLs digitadas e seus horários de uso são armazenados no registro em `NTUSER.DAT` em `Software\Microsoft\InternetExplorer\TypedURLs` e `Software\Microsoft\InternetExplorer\TypedURLsTime`, rastreando as últimas 50 URLs inseridas pelo usuário e seus últimos horários de entrada.

## Microsoft Edge

O Microsoft Edge armazena dados do usuário em `%userprofile%\Appdata\Local\Packages`. Os caminhos para vários tipos de dados são:

- **Caminho do Perfil**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **Histórico, Cookies e Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Configurações, Favoritos e Lista de Leitura**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Últimas Sessões Ativas**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Os dados do Safari são armazenados em `/Users/$User/Library/Safari`. Arquivos-chave incluem:

- **History.db**: Contém tabelas `history_visits` e `history_items` com URLs e horários de visita. Use `sqlite3` para consultar.
- **Downloads.plist**: Informações sobre arquivos baixados.
- **Bookmarks.plist**: Armazena URLs marcadas como favoritas.
- **TopSites.plist**: Sites mais visitados.
- **Extensions.plist**: Lista de extensões do navegador Safari. Use `plutil` ou `pluginkit` para recuperar.
- **UserNotificationPermissions.plist**: Domínios permitidos para enviar notificações. Use `plutil` para analisar.
- **LastSession.plist**: Abas da última sessão. Use `plutil` para analisar.
- **Anti-phishing integrado do navegador**: Verifique usando `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Uma resposta de 1 indica que o recurso está ativo.

## Opera

Os dados do Opera estão em `/Users/$USER/Library/Application Support/com.operasoftware.Opera` e compartilham o formato de histórico e downloads do Chrome.

- **Anti-phishing integrado do navegador**: Verifique se `fraud_protection_enabled` no arquivo Preferences está definido como `true` usando `grep`.

Esses caminhos e comandos são cruciais para acessar e entender os dados de navegação armazenados por diferentes navegadores da web.

## Referências

- [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
- **Livro: OS X Incident Response: Scripting and Analysis By Jaron Bradley pag 123**

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e **automatizar fluxos de trabalho** com facilidade, utilizando as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Aprenda hacking AWS do zero ao avançado com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:
* Se deseja ver a **sua empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
