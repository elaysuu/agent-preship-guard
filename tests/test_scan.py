import os, subprocess, sys, tempfile, unittest
SCAN=os.path.join(os.path.dirname(__file__),"..","scan.py")
def run(code):
    d=tempfile.mkdtemp(); 
    with open(os.path.join(d,"a.py"),"w") as fh: fh.write(code)
    r=subprocess.run([sys.executable,SCAN,d,"none"],capture_output=True,text=True); return r.stdout
class T(unittest.TestCase):
    def test_capture_output_not_ag001(self):
        o=run('import subprocess\nsubprocess.run("uptime", shell=True, capture_output=True)\n')
        self.assertNotIn("AG001",o); self.assertIn("AG004",o); self.assertNotIn("AG008",o)
    def test_llm_output_to_shell_ag001(self):
        self.assertIn("AG001",run('import subprocess\nsubprocess.run(llm_response, shell=True)\n'))
    def test_model_picks_rmtree_ag008(self):
        o=run('import shutil, json\nTOOLS={"rm":shutil.rmtree}\nstep=json.loads(plan)\nTOOLS[step["tool"]](step["arg"])\n')
        self.assertIn("AG008",o)
    def test_gated_not_ag008(self):
        o=run('import shutil, json\nTOOLS={"rm":shutil.rmtree}\nstep=json.loads(plan)\nif require_approval(step):\n    TOOLS[step["tool"]](step["arg"])\n')
        self.assertNotIn("AG008",o)
    def test_sql_drop_from_tool_call(self):
        self.assertIn("AG008",run('for c in msg.tool_calls:\n    db.execute("DROP TABLE users")\n'))
    def test_comment_is_not_a_gate(self):
        self.assertIn("AG008",run('import shutil, json\nT={"rm":shutil.rmtree}\ns=json.loads(x)  # no approval gate\nT[s["t"]](s["a"])\n'))
    def test_no_model_no_ag008(self):
        self.assertNotIn("AG008",run('import shutil\nshutil.rmtree("/tmp/build")\n'))
if __name__=="__main__": unittest.main()

























