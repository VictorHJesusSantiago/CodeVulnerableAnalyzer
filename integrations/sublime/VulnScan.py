import sublime_plugin
class VulnscanCommand(sublime_plugin.WindowCommand):
    def run(self):
        view=self.window.active_view()
        self.window.run_command("exec",{"cmd":["python","main.py",view.file_name(),"--json","vulnscan.json"]})
