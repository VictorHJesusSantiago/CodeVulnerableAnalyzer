# Tutorial rápido

1. Execute `vulnscan caminho/ --severity HIGH`.
2. Exporte SARIF com `--sarif resultado.sarif`.
3. Revise o fluxo e a remediação de cada achado.
4. Gere patches determinísticos pela API de `RemediationEngine`.
5. Aplique quality gates somente depois de calibrar baselines e falsos positivos.
