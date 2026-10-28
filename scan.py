#!/usr/bin/env python3
"""Agent PreShip Guard: heuristic static scan for risky AI-agent patterns. MIT."""
import os, re, sys
RULES = [
 ("high","AG001","Model/LLM output passed to shell",r"(subprocess\.(run|call|Popen)|os\.system|exec\()\s*\(?.*(response|completion|output|content|llm|model)"),
 ("high","AG002","eval/exec of dynamic content",r"\b(eval|exec)\s*\((?!\s*['\"])"),
 ("high","AG003","Hardcoded API key in source",r"(sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36})"),
 ("medium","AG004","shell=True in tool code",r"shell\s*=\s*True"),
 ("medium","AG005","Secrets interpolated into prompt",r"(prompt|system|messages).{0,40}(os\.environ|getenv|API_KEY|SECRET)"),
 ("medium","AG006","Unrestricted URL fetch tool (SSRF risk)",r"requests\.(get|post)\(\s*(url|args|params|input)"),
 ("medium","AG007","Agent auto-approve / no human-in-loop flag",r"(auto_approve|dangerously|skip_confirm|yolo)\s*[=:]\s*(True|true|1)"),
]
EXT=(".py",".js",".ts",".mjs",".tsx",".jsx")
def main():
    root=sys.argv[1] if len(sys.argv)>1 else "."; fail=sys.argv[2] if len(sys.argv)>2 else "high"
    hits=[]
    for d,dirs,files in os.walk(root):
        dirs[:]=[x for x in dirs if x not in("node_modules",".git","venv",".venv","dist","build")]
        for f in files:
            if not f.endswith(EXT): continue
            p=os.path.join(d,f)
            try: lines=open(p,errors="ignore").read().splitlines()
            except OSError: continue
            for i,l in enumerate(lines,1):
                for sev,rid,msg,rx in RULES:
                    if re.search(rx,l,re.I):
                        hits.append((sev,rid,msg,p,i))
                        print(f"::{'error' if sev=='high' else 'warning'} file={p},line={i}::{rid} {msg}")
    h=sum(1 for x in hits if x[0]=="high"); m=len(hits)-h
    print(f"\nAgent PreShip Guard: {h} high, {m} medium findings.")
    print("Heuristic scan only. Full 40-check manual review: https://setrov.gumroad.com/l/vldkkl")
    if (fail=="high" and h) or (fail=="medium" and hits): sys.exit(1)
if __name__=="__main__": main()
