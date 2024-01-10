# Armazenamento Local na Nuvem

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) no github.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir e **automatizar fluxos de trabalho** facilmente, com as ferramentas comunitárias **mais avançadas** do mundo.\
Obtenha Acesso Hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## OneDrive

No Windows, você pode encontrar a pasta do OneDrive em `\Users\<username>\AppData\Local\Microsoft\OneDrive`. E dentro de `logs\Personal` é possível encontrar o arquivo `SyncDiagnostics.log` que contém dados interessantes sobre os arquivos sincronizados:

* Tamanho em bytes
* Data de criação
* Data de modificação
* Número de arquivos na nuvem
* Número de arquivos na pasta
* **CID**: ID único do usuário do OneDrive
* Tempo de geração do relatório
* Tamanho do HD do sistema operacional

Uma vez que você encontrou o CID, é recomendado **procurar arquivos contendo este ID**. Você pode ser capaz de encontrar arquivos com o nome: _**\<CID>.ini**_ e _**\<CID>.dat**_ que podem conter informações interessantes como os nomes dos arquivos sincronizados com o OneDrive.

## Google Drive

No Windows, você pode encontrar a pasta principal do Google Drive em `\Users\<username>\AppData\Local\Google\Drive\user_default`\
Esta pasta contém um arquivo chamado Sync_log.log com informações como o endereço de email da conta, nomes de arquivos, timestamps, hashes MD5 dos arquivos, etc. Até arquivos excluídos aparecem nesse arquivo de log com seu respectivo MD5.

O arquivo **`Cloud_graph\Cloud_graph.db`** é um banco de dados sqlite que contém a tabela **`cloud_graph_entry`**. Nesta tabela você pode encontrar o **nome** dos **arquivos sincronizados**, tempo de modificação, tamanho e o checksum MD5 dos arquivos.

Os dados da tabela do banco de dados **`Sync_config.db`** contêm o endereço de email da conta, o caminho das pastas compartilhadas e a versão do Google Drive.

## Dropbox

O Dropbox usa **bancos de dados SQLite** para gerenciar os arquivos. Neste\
Você pode encontrar os bancos de dados nas pastas:

* `\Users\<username>\AppData\Local\Dropbox`
* `\Users\<username>\AppData\Local\Dropbox\Instance1`
* `\Users\<username>\AppData\Roaming\Dropbox`

E os principais bancos de dados são:

* Sigstore.dbx
* Filecache.dbx
* Deleted.dbx
* Config.dbx

A extensão ".dbx" significa que os **bancos de dados** são **criptografados**. O Dropbox usa **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/ms995355\(v=msdn.10\)?redirectedfrom=MSDN))

Para entender melhor a criptografia que o Dropbox usa, você pode ler [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html).

No entanto, as informações principais são:

* **Entropia**: d114a55212655f74bd772e37e64aee9b
* **Salt**: 0D638C092E8B82FC452883F95F355B8E
* **Algoritmo**: PBKDF2
* **Iterações**: 1066

Além dessas informações, para descriptografar os bancos de dados você ainda precisa de:

* A **chave DPAPI criptografada**: Você pode encontrá-la no registro dentro de `NTUSER.DAT\Software\Dropbox\ks\client` (exporte esses dados como binário)
* As hives **`SYSTEM`** e **`SECURITY`**
* As **chaves mestras DPAPI**: Que podem ser encontradas em `\Users\<username>\AppData\Roaming\Microsoft\Protect`
* O **nome de usuário** e **senha** do usuário do Windows

Então você pode usar a ferramenta [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:**

![](<../../../.gitbook/assets/image (448).png>)

Se tudo correr como esperado, a ferramenta indicará a **chave primária** que você precisa **usar para recuperar a original**. Para recuperar a original, basta usar esta [receita do cyber_chef](https://gchq.github.io/CyberChef/#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)) colocando a chave primária como a "senha" dentro da receita.

O hex resultante é a chave final usada para criptografar os bancos de dados, que pode ser descriptografada com:
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
O banco de dados **`config.dbx`** contém:

* **Email**: O email do usuário
* **usernamedisplayname**: O nome do usuário
* **dropbox\_path**: Caminho onde a pasta do Dropbox está localizada
* **Host\_id: Hash** usado para autenticar na nuvem. Isso só pode ser revogado pela web.
* **Root\_ns**: Identificador do usuário

O banco de dados **`filecache.db`** contém informações sobre todos os arquivos e pastas sincronizados com o Dropbox. A tabela `File_journal` é a que possui informações mais úteis:

* **Server\_path**: Caminho onde o arquivo está localizado dentro do servidor (este caminho é precedido pelo `host_id` do cliente).
* **local\_sjid**: Versão do arquivo
* **local\_mtime**: Data de modificação
* **local\_ctime**: Data de criação

Outras tabelas dentro deste banco de dados contêm informações mais interessantes:

* **block\_cache**: hash de todos os arquivos e pastas do Dropbox
* **block\_ref**: Relaciona o ID do hash da tabela `block_cache` com o ID do arquivo na tabela `file_journal`
* **mount\_table**: Pastas compartilhadas do Dropbox
* **deleted\_fields**: Arquivos deletados do Dropbox
* **date\_added**

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e **automatizar fluxos de trabalho** com as ferramentas comunitárias **mais avançadas** do mundo.\
Obtenha Acesso Hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**merchandising oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
