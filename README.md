# Security-Check-List
Uma lista de segurança voltada para DevSecOps


# Security Checklist
##### A equipe de segurança da informação preparou as mais atualizadas dicas de segurança para voce utilizar no seu dia-a-dia.  

##### Com essas dicas voce ficará muito mais seguro contra as ameaças que enfrentamos no dia a dia.  


## DevSecOps  
Este contem treinamentos, laboratorios, conferencias, guias e muito mais sobre DevSecOps para voce aplicar em sua equipe.

---
- [ ] O que é DevSecOps ? ([Introdução a DevSecOps](https://github.com/sottlmarek/DevSecOps#what-is-devsecops))  
- [ ] Introdução ao SAST ([Owasp SAST Intro](https://owasp.org/www-community/Source_Code_Analysis_Tools))  
- [ ] Aplique uma etapa para ferramentas de SAST em seu CI/CD ([Teste de segurança no codigo com SAST](https://github.com/sottlmarek/DevSecOps#sast))  
- [ ] Exemplos de SAST Open Source ([Tutorial SAST open Source](https://www.breachlock.com/top-3-open-source-tools-for-sast/))
- [ ] Aplique treinamentos periodicos (```1 vez por mês```) de DevSecOps para seu time baseado no conteudo da Awesome DevSecOps ([Awesome DevSecOps](https://github.com/devsecops/awesome-devsecops#training))  

## Wordpress  
As melhores e mais atuais dicas de segurança da CMS Wordpress.  

---

* ### wp-config  
- [ ] Altere as chaves de segurança ([Gerador disponibilizado pelo WordPress.org](https://api.wordpress.org/secret-key/1.1/salt/))  

- [ ] Certifique-se que seu arquivo wp-config.php não possa ser acessado por outras pessoas.  

- [ ] Desabilite o editor pelo wp-config.php com o código:``` define(‘DISALLOW_FILE_EDIT’,true)```.  

* ### Pagina de login  
- [ ] Bloqueie várias tentativas de login ([Login Lockdown](https://wordpress.org/plugins/login-lockdown/) ```ou``` [iThemes Security](https://wordpress.org/plugins/better-wp-security/))  
- [ ] Ative autenticação de 2 etapas ([Google Authenticator](https://wordpress.org/plugins/google-authenticator/))  
- [ ] Use um email para fazer login ao invés de um nome de usuario ([Force Login With Email](https://br.wordpress.org/plugins/force-login-with-email/))  
- [ ] Altere o endereço da sua página de login ([iThemes Security](https://wordpress.org/plugins/better-wp-security/) ```ou diretamente pelo .htaccess```)  
- [ ] Remova links para sua página de login (```caso exista algum em seu tema```)  
- [ ] Use senhas fortes com letras maiúsculas e minúsculas, números e caracteres especiais em todas as contas (```gerador de senhas``` [Aleatório](https://passwordsgenerator.net/)```ou``` [Baseado em palavras](https://www.safetydetectives.com/password-meter/))  
- [ ] Altere sua senha periodicamente (```Recomendamos um intervalo de 30 dias porem é tolerável utilizar até 90 dias no maximo.```)  
- [ ] Faça com que a mensagem de erro de login seja genérica (```user/pass```) ([Tutorial](https://gist.github.com/zergiocosta/72f87176b236ed0c6e13))  
- [ ] Desabilite a API REST do WP caso não esteja utilizando. ([Disable REST API](https://br.wordpress.org/plugins/disable-json-api/))  

* ### Painel Administrativo  
- [ ] Proteja a pasta wp-admin com senha ([Desbloqueie apenas os arquivos necessários](https://gist.github.com/rafaelfunchal/f9a41ea72d80600d753a))  
- [ ] Atualize o WordPress para sua versão mais recente  
- [ ] Não utilize uma conta com nome de usuário admin. Caso exista, crie uma nova conta e apague a antiga  
- [ ] Crie uma conta Editor e use-a somente para publicar seu conteúdo  
- [ ] Implemente SSL em toda seção administrativa  
- [ ] Instale algum plugin para verificar se algum arquivo foi editado ([Wp Security Scan](https://wordpress.org/plugins/wp-security-scan/) ou[Wordfence](https://wordpress.org/plugins/wordfence/) ```ou``` [iThemes Security](https://wordpress.org/plugins/better-wp-security/))
- [ ] Escaneie o site a procura de vírus, malwares e falhas de segurança periodicamente (```Ao menos 1 vez por mês.```) ([Tutorial](https://geekflare.com/website-malware-scanning/))  
* ### Tema  
- [ ] Atualize o tema ativo para sua versão mais recente  
- [ ] Apague temas inativos  
- [ ] Apenas instale temas de fontes confiáveis  
- [ ] Remova a versão do WordPress no tema([Tutorial](https://www.wpbeginner.com/wp-tutorials/the-right-way-to-remove-wordpress-version-number/))  
* ### Plugins  
- [ ] Atualize todos os plugins para suas versões mais recentes  
- [ ] Apague plugins inativos  
- [ ] Apenas instale plugins de fontes confiáveis  
- [ ] Substitua plugins desatualizados por versões alternativas atualizadas  
- [ ] Pense bem antes de instalar uma centena de plugins  
* ### Banco de dados
- [ ] Altere o prefixo das tabelas ([Tutorial](https://www.maketecheasier.com/the-safe-way-to-change-your-wordpress-database-table-prefix/))  
- [ ] Configure backups semanais do seu banco de dados ([Backup WP](https://wordpress.org/plugins/backup-wp/), [WP DB Backup](https://wordpress.org/plugins/wp-db-backup/), ```etc.```)  
- [ ] Use senhas fortes com letras maiúsculas e minúsculas, números e caracteres especiais no usuário do banco de dados ([Gerador de Senhas](https://passwordsgenerator.net/) ou [Password Meter](https://www.safetydetectives.com/password-meter/))  
* ### Hospedagem  
- [ ] Contrate uma hospedagem de confiança```(Realize uma pesquisa sobre vazamentos e incidentes de segurança do provedor.)```  
- [ ] Acesse seu servidor apenas por SFTP ou SSH  
- [ ] Configure as permissões das pastas para 755 e arquivos para 644([Conforme a documentação](https://wordpress.org/support/article/hardening-wordpress/))  
- [ ] Certifique-se que seu arquivo wp-config.php não possa ser acessado por outras pessoas  
- [ ] Remova ou bloqueie via .htaccess os arquivos license.txt, wp-config-sample.php e readme.html  
- [ ] Desabilite o editor pelo wp-config.php com o código:```define('DISALLOW_FILE_EDIT',true);```  
- [ ] Previna a pesquisa de diretórios via .htaccess com o código:```Options All -Indexes```  


## Github  
Siga as dicas abaixo para evitar vazamentos de segredos e vulnerabilidades em seu codigo.  

---
* ### Segurança no Codigo  
- [ ] Utilize o ```ShhGit``` para escanear o codigo em busca de segredos ([shhgit](https://github.com/eth0izzle/shhgit))  
- [ ] Criptografe o codigo usando Git-Crypt ([Tutorial](https://buddy.works/guides/git-crypt))  
- [ ] Utilize uma folha de dicas para agilizar a produção e/ou evitar erros de codigo ([DevCode CheatSheets](https://github.com/LeCoupa/awesome-cheatsheets))  
- [ ] Utilize boas praticas de FrontEnd recomendadas por desenvolvedores de todo o mundo ([Front End Checklist](https://github.com/thedaviddias/Front-End-Checklist))  
- [ ] Siga as boas praticas em Node.JS ([Node Best Practices](https://github.com/goldbergyoni/nodebestpractices))  
- [ ] Utilize um gerenciador de senhas ([KeePassXC](https://keepassxc.org/download/))  
- [ ] Utilize cabeçalhos de segurança para evitar ataques de XSS, CSRF, XXE e etc ([Analisador de cabeçalhos da web](https://securityheaders.com/))  
- [ ] WebHint é uma extensão de navegador que fornece dicas de boas praticas e segurança enquanto voce navega em seu site. ([Web Hint](https://webhint.io/))  
- [ ] Aqui temos uma lista de softwares e dicas relacionadas para segurança ([Security Tools](https://www.privacyguides.org/tools/))  
- [ ] Um codigo limpo e bem estrutura ajuda a evitar erros por outros programadores que atuarem no codigo ([Clean Code](https://www.amazon.com.br/C%C3%B3digo-limpo-Robert-C-Martin/dp/8576082675))  
- [ ] Utilize cookies de segurança em suas aplicações web ([Security Cookies WhitePapper](https://www.invicti.com/security-cookies-whitepaper/))  
- [ ] Gerencie seus segredos e variaveis com ```Teller``` ([Teller](https://github.com/spectralops/teller))  
- [ ] Realize consultorias de segurança em seus projetos conforme recomenda Github ([Consultorias de segurança do repositório](https://docs.github.com/pt/code-security/repository-security-advisories))

## API Security Checklist  
Lista das mais importantes medidas de segurança para o desenvolvimento, teste e publicação da sua API.  

---
* ### Autenticação (_Authentication_)  
- [ ] Não use `Basic Auth`. Use padrões de autenticação (exemplo: JWT, OAuth).  
- [ ] Não reinvente a roda nos quesitos `Autenticação`, `geração de tokens` e `armazenamento de senhas`. Use os padrões recomendados para cada caso.  
- [ ] Implemente funcionalidades de limite (_`Max Retry`_) e bloqueio de tentativas de autenticação.  
- [ ] Use criptografia em todos os dados confidenciais.  
* ### JWT (JSON Web Token)  
- [ ] Use uma chave de segurança aleatória e complicada (`JWT Secret`) para tornar ataques de força bruta menos eficientes.  
- [ ] Não utilize o algoritmo de criptografia informado no cabeçalho do payload. Force o uso de um algoritmo específico no _back-end_ (`HS256` ou `RS256`).  
- [ ] Defina o tempo de vida do _token_ (`TTL`, `RTTL`) o menor possível.  
- [ ] Não armazene informações confidenciais no JWT, pois elas podem ser [facilmente decodificadas](https://jwt.io/#debugger-io).  

* ### OAuth  
- [ ] Sempre valide o `redirect_uri` no seu servidor através de uma lista de URLs conhecidas (previamente cadastradas).  
- [ ] Tente sempre retornar códigos de negociação, não o _token_ de acesso (não permita `response_type=token`).  
- [ ] Utilize o parâmetro `state` com um _hash_ aleatório para previnir CSRF no processo de autenticação OAuth.  
- [ ] Defina escopo de dados, e valide o parâmetro `scope` para cada aplicação.  

* ### Acesso (_Access_)  
- [ ] Limite a quantidade de requisições (_Throttling_) para evitar ataques DDoS e de força bruta.  
- [ ] Use HTTPS no seu servidor para evitar ataques MITM (_Man In The Middle Attack_).  
- [ ] Use cabeçalho `HSTS` com SSL para evitar ataques _SSL Strip_.  

* ### Requisição (_Input_)  
- [ ] Utilize o método HTTP apropriado para cada operação, `GET (obter)`, `POST (criar)`, `PUT/PATCH (trocar/atualizar)` e `DELETE (apagar)`.  
- [ ] Valide o tipo de conteúdo informado no cabeçalho `Accept` da requisição (_Content Negotiation_) para permitir apenas os formatos suportados pela sua API (ex. `application/xml`, `application/json` ... etc), respondendo com o status `406 Not Acceptable` se ele não for suportado.  
- [ ] Valide o tipo de conteúdo do conteúdo da requisição informado no cabeçalho `Content-Type` da requisição para permitir apenas os formatos suportados pela sua API (ex. `application/x-www-form-urlencoded`, `multipart/form-data, application/json` ... etc).  
- [ ] Valide o conteúdo da requisição para evitar as vulnerabilidades mais comuns (ex. `XSS`, `SQL-Injection`, `Remote Code Execution` ... etc).  
- [ ] Não utilize nenhuma informação sensível (credenciais, senhas, _tokens_ de autenticação) na URL. Use o cabeçalho `Authorization` da requisição.  
- [ ] Use um serviço _gateway_ para a sua API para habilitar _cache_, limitar acessos sucessivos (ex. por quantidade máxima permitida (_Quota_), por limitar tráfego em situações de estresse (_spike arrest_) ou por limitar o número de conexões simultâneas na sua API (_Concurrent Rate Limit_)), e facilitar o _deploy_ de novas funcionalidades.  

* ### Processamento (_Processing_)  
- [ ] Verifique continuamente os _endpoints_ protegidos por autenticação para evitar falhas na proteção de acesso aos dados.  
- [ ] Não utilize a identificação do próprio usuário. Use `/me/orders` no lugar de `/user/654321/orders`.  
- [ ] Não utilize ID's incrementais. Use UUID.  
- [ ] Se você estiver processando arquivos XML, verifique que _entity parsing_ não está ativada para evitar ataques de XML externo (XXE - _XML external entity attack_).  
- [ ] Se você estiver processando arquivos XML, verifique que _entity expansion_ não está ativada para evitar _Billion Laughs/XML bomb_ através de ataques exponenciais de expansão de XML.  
- [ ] Use CDN para _uploads_ de arquivos.  
- [ ] Se você estiver trabalhando com uma grande quantidade de dados, use _workers_ e _queues_ (fila de processos) para retornar uma resposta rapidamente e evitar o bloqueio de requisições HTTP.  
- [ ] Não se esqueça de desativar o modo de depuração (_DEBUG mode OFF_).  

* ### Resposta (_Output_)  
- [ ] Envie o cabeçalho `X-Content-Type-Options: nosniff`.  
- [ ] Envie o cabeçalho `X-Frame-Options: deny`.  
- [ ] Envie o cabeçalho `Content-Security-Policy: default-src 'none'`.  
- [ ] Remova os cabeçalhos de identificação dos _softwares_ do servidor - `X-Powered-By`, `Server`, `X-AspNet-Version`.  
- [ ] Envie um cabeçalho `Content-Type` na sua resposta com o valor apropriado (ex. se você retorna um JSON, então envie um `Content-Type: application/json`).  
- [ ] Não retorne dados sensíveis como senhas, credenciais e tokens de autenticação.  
- [ ] Utilize o código de resposta apropriado para cada operação. Ex. `200 OK` (respondido com sucesso), `201 Created` (novo recurso criado), `400 Bad Request` (requisição inválida), `401 Unauthorized` (não autenticado), `405 Method Not Allowed` (método HTTP não permitido) ... etc.  

* ### CI & CD  
- [ ] Monitore a especificação e implementação do escopo da sua API através de testes unitários e de integração.  
- [ ] Use um processo de revisão de código, ignorando sistemas de auto-aprovação.  
- [ ] Certifique-se de que todos os componentes de seus serviços sejam validados por _softwares_ AV (anti-vírus, anti-_malware_) antes de enviar para produção, incluindo as dependências de terceiros utilizadas.  
- [ ] Implemente funcionalidade de reversão de _deploy_ (_rollback_).  

+ ### API Gateway  
- [ ] Utilize uma API gateway dedicada e segura ([KONG](https://github.com/Kong/kong))  


## Hardening  

Aqui se encontrará diversos modelos de hardening em uma diversidade de tecnologias.

---

- [ ] Estes são baselines de hardening para as tecnologias que voce utiliza em seu ambiente como:```MySQL, PostgreSQL, Nginx, SSH, Docker e muito mais...```  ([Dev -> Sec](https://dev-sec.io/baselines/))  
- [ ] Base lines para Linux ([Linux Base Lines](https://github.com/dev-sec/linux-baseline) ```puppet, chef e ansible```)  
- [ ] CIS Kubernetes ([CIS BenchMark](https://github.com/dev-sec/cis-kubernetes-benchmark))  
- [ ] Segurança no Nginx ([Nginx Security Base line](https://github.com/dev-sec/nginx-baseline))  
- [ ] Base line para PostgreSQL ([Security in PostgreSQL](https://github.com/dev-sec/postgres-baseline))  
- [ ] Base line para MySQL ([MySQL security](https://github.com/dev-sec/mysql-baseline))
- [ ] Base line para SSH ([Hardening SSH](https://github.com/dev-sec/ssh-baseline))  
- [ ] Hardening para servidores da web ([Web Server Hardening](https://github.com/dev-sec/hardening))  
- [ ] Hardening em containers ([Docker Bench](https://github.com/docker/docker-bench-security))  
- [ ] Hardening completo para sistemas linux ([O Guia Pratico do Linux Harning](https://github.com/trimstray/the-practical-linux-hardening-guide))


## Auditoria  
Estas dicas ajudaram a rastrear eventos que acontecem no sistema seja eventos de segurança ou tecnicos.

Elas tambem forneceram uma serie de ferramentas que combinadas com agendadores de tarefas como cron, fornerá uma visão geral de segurança em seu ambiente.

---

### Linux  
- [ ] Configure o ```auditd``` ([AUDITORIA DO SISTEMA](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security_guide/chap-system_auditing))  
- [ ] Utilize o ```Tiger``` para melhorar a postura de segurança em seu ambiente, ele pode realiza auditorias (```1 vez por mês```) automaticas em seu ambiente ([Tutorial](https://www.tecmint.com/tiger-linux-security-audit-intrusion-detection-tool/))  
- [ ] Realize auditorias periodicas (```1 vez por mês```) com ```Lynis``` ([Tutorial](https://cisofy.com/lynis/))  
- [ ] Utilize o ```Wazuh``` para manter um controle de inventario e FIM (```File Integrity Monitoring```) ([Wazuh Open Source](https://wazuh.com/))  
- [ ] Rode o ```LinEnum``` periodicamente (```1 vez por mês```) em seu ambiente para obter uma visão geral de segurança ([LinEnum](https://github.com/rebootuser/LinEnum))  
- [ ] Utilize o ```RkHunter``` para procurar rootkits periodicamente em seu ambiente ([RootKit Hunter](https://github.com/installation/rkhunter))  
- [ ] Utilize ```trivy``` para escanear imagens de containers em busca de vulnerabilidaes ([TriVy](https://github.com/aquasecurity/trivy))  
- [ ] Utilize GoHarbor para escaner suas imagens containers em busca de malware ([GoHarbor](https://goharbor.io/))  


### Windows  
- [ ] Utilize o ```pe-sieve``` periodicamente em busca de malware escondidos no sistema ([PE Sieve](https://github.com/hasherezade/pe-sieve))  
- [ ] Rode o ```PEASS``` periodicamente (1 vez por mês) em busca de meios para escalar os privilegios em seu ambiente ([PEASS](https://github.com/carlospolop/PEASS-ng))  
