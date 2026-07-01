;;; vulnscan.el --- CodeVulnerableAnalyzer integration
(defun vulnscan-buffer ()
  "Scan the current buffer with CodeVulnerableAnalyzer."
  (interactive)
  (compile (format "python main.py %s --sarif vulnscan.sarif" (shell-quote-argument buffer-file-name))))
(provide 'vulnscan)
