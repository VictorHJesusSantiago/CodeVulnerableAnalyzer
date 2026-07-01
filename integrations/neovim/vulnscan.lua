local M = {}
function M.scan()
  vim.fn.jobstart({"python", "main.py", vim.fn.expand("%:p"), "--json", "-"}, {
    stdout_buffered = true,
    on_stdout = function(_, data)
      if data then vim.notify(table.concat(data, "\n"), vim.log.levels.INFO, {title="VulnScan"}) end
    end
  })
end
vim.api.nvim_create_user_command("VulnScan", M.scan, {})
return M
