{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}


Existem vários blogs na Internet que **destacam os perigos de deixar impressoras configuradas com LDAP com credenciais de logon padrão/fracas**.\
Isso ocorre porque um atacante poderia **enganar a impressora para autenticar contra um servidor LDAP malicioso** (tipicamente um `nc -vv -l -p 444` é suficiente) e capturar as **credenciais da impressora em texto claro**.

Além disso, várias impressoras conterão **logs com nomes de usuários** ou poderão até mesmo **baixar todos os nomes de usuários** do Controlador de Domínio.

Todas essas **informações sensíveis** e a comum **falta de segurança** tornam as impressoras muito interessantes para os atacantes.

Alguns blogs sobre o tema:

* [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
* [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## Configuração da Impressora
- **Localização**: A lista de servidores LDAP é encontrada em: `Network > LDAP Setting > Setting Up LDAP`.
- **Comportamento**: A interface permite modificações no servidor LDAP sem reintroduzir credenciais, visando a conveniência do usuário, mas apresentando riscos de segurança.
- **Exploit**: O exploit envolve redirecionar o endereço do servidor LDAP para uma máquina controlada e aproveitar o recurso "Test Connection" para capturar credenciais.

## Capturando Credenciais

**Para passos mais detalhados, consulte a [fonte original](https://grimhacker.com/2018/03/09/just-a-printer/).**

### Método 1: Listener Netcat
Um simples listener netcat pode ser suficiente:
```bash
sudo nc -k -v -l -p 386
```
No entanto, o sucesso deste método varia.

### Método 2: Servidor LDAP Completo com Slapd
Uma abordagem mais confiável envolve a configuração de um servidor LDAP completo, pois a impressora realiza um null bind seguido por uma consulta antes de tentar a vinculação de credenciais.

1. **Configuração do Servidor LDAP**: O guia segue os passos desta [fonte](https://www.server-world.info/en/note?os=Fedora_26&p=openldap).
2. **Passos Chave**:
- Instalar OpenLDAP.
- Configurar a senha do administrador.
- Importar esquemas básicos.
- Definir o nome do domínio no banco de dados LDAP.
- Configurar LDAP TLS.
3. **Execução do Serviço LDAP**: Uma vez configurado, o serviço LDAP pode ser executado usando:
```bash
slapd -d 2
```
## Referências
* [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)


{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}
