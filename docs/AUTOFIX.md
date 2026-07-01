# Remediação automática

O motor gera `Patch` com SHA-256 do conteúdo original. Antes da aplicação ele
recalcula o hash, rejeita alterações concorrentes, valida intervalos e impede
paths fora da raiz. Codemods determinísticos são preferidos; sugestões LLM
continuam como propostas revisáveis e nunca são aplicadas implicitamente.

Quick fixes são publicados por `textDocument/codeAction` no LSP. Provedores de
PR implementam uma interface mínima para que GitHub, GitLab, Bitbucket ou Azure
DevOps recebam conteúdo sem acoplar credenciais ao motor.
