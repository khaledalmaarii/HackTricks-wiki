<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>


Existem vários blogs na Internet que **destacam os perigos de deixar impressoras configuradas com LDAP com credenciais de login padrão/fracas**.\
Isso ocorre porque um atacante poderia **enganar a impressora para autenticar-se contra um servidor LDAP falso** (tipicamente um `nc -vv -l -p 444` é suficiente) e capturar as **credenciais da impressora em texto claro**.

Além disso, várias impressoras conterão **logs com nomes de usuários** ou até mesmo ser capazes de **baixar todos os nomes de usuários** do Controlador de Domínio.

Todas essas **informações sensíveis** e a **falta comum de segurança** tornam as impressoras muito interessantes para os atacantes.

Alguns blogs sobre o tema:

* [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
* [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## Configuração da Impressora
- **Localização**: A lista de servidores LDAP é encontrada em: `Rede > Configuração LDAP > Configuração do LDAP`.
- **Comportamento**: A interface permite modificações no servidor LDAP sem precisar reentrar com as credenciais, visando a conveniência do usuário, mas apresentando riscos de segurança.
- **Exploração**: A exploração envolve redirecionar o endereço do servidor LDAP para uma máquina controlada e aproveitar o recurso "Testar Conexão" para capturar credenciais.

## Capturando Credenciais

**Para passos mais detalhados, consulte a [fonte original](https://grimhacker.com/2018/03/09/just-a-printer/).**

### Método 1: Ouvinte Netcat
Um simples ouvinte netcat pode ser suficiente:
```bash
sudo nc -k -v -l -p 386
```
No entanto, o sucesso deste método varia.

### Método 2: Servidor LDAP Completo com Slapd
Uma abordagem mais confiável envolve configurar um servidor LDAP completo, pois a impressora realiza uma ligação nula seguida de uma consulta antes de tentar a ligação de credenciais.

1. **Configuração do Servidor LDAP**: O guia segue os passos deste [fonte](https://www.server-world.info/en/note?os=Fedora_26&p=openldap).
2. **Passos Principais**:
- Instalar o OpenLDAP.
- Configurar a senha do administrador.
- Importar esquemas básicos.
- Definir o nome de domínio no banco de dados LDAP.
- Configurar o TLS do LDAP.
3. **Execução do Serviço LDAP**: Uma vez configurado, o serviço LDAP pode ser executado usando:
```bash
slapd -d 2
```
## Referências
* [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)


<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
