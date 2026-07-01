# Limites verificáveis de cobertura

O projeto possui implementações locais e adaptadores para as 16 categorias,
mas “100% completo” não é uma propriedade tecnicamente demonstrável para este
escopo aberto. Em especial:

- análise AST nativa para toda linguagem requer parsers/gramáticas e toolchains
  de cada ecossistema; o IR semântico atual é completo para seu modelo e o
  frontend Python, não para todas as linguagens;
- Helm, Kustomize, apktool, TPM/FIDO2, KMS, Kafka, RabbitMQ e serviços cloud
  dependem de executáveis, hardware, endpoints e credenciais externos;
- GitHub/GitLab/Bitbucket/Azure DevOps, Jira, Confluence e notificadores usam
  adaptadores testáveis, mas a execução real depende do ambiente do cliente;
- validação de precisão em Juliet/OWASP exige baixar e rotular esses datasets;
- verificações formais de contratos e blockchains dependem de solvers e
  compiladores específicos.

O código deve falhar explicitamente quando uma dependência externa não está
disponível, nunca fingir que uma operação foi executada.
