#!/usr/bin/env python3
"""Agent PreShip Guard v1.1: heuristic static scan for risky AI-agent patterns. MIT."""
import os, re, sys
RULES = [
 ("high","AG001","Model/LLM output passed to shell",r"(subprocess\.(run|call|Popen)|os\.system|exec\()\s*\(?.*\b(response|completion|output|content|llm|model)"),
 ("high","AG002","eval/exec of dynamic content",r"\b(eval|exec)\s*\((?!\s*['\"])"),
 ("high","AG003","Hardcoded API key in source",r"(sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36})"),
 ("medium","AG004","shell=True in tool code",r"shell\s*=\s*True"),
 ("medium","AG005","Secrets interpolated into prompt",r"(prompt|system|messages).{0,40}(os\.environ|getenv|API_KEY|SECRET)"),
 ("medium","AG006","Unrestricted URL fetch tool (SSRF risk)",r"requests\.(get|post)\(\s*(url|args|params|input)"),
 ("medium","AG007","Agent auto-approve / no human-in-loop flag",r"(auto_approve|dangerously|skip_confirm|yolo)\s*[=:]\s*(True|true|1)"),
]
# AG008 (file-level): model/LLM output picks a destructive call, and no approval gate appears in the file.
MODEL_RX=r"(\bllm|completion|tool_calls?\b|function_call|json\.loads|\bplan\b|\bstep\[|model_output|response\.choices)"
DESTRUCT_RX=r"(shutil\.rmtree|os\.(remove|unlink|rmdir|system)|subprocess\.|shell\s*=\s*True|\bDROP\s+(TABLE|DATABASE)|\bDELETE\s+FROM|\.delete\(|\btransfer\w*\()"
GATE_RX=r"(approv|confirm|human_in_the_loop|\bhitl\b|\binput\()"
def file_rules(lines):
    text="\n".join(re.sub(r"(#|//).*$","",l) for l in lines)  # comments don't count as gates
    if not re.search(MODEL_RX,text,re.I) or re.search(GATE_RX,text,re.I): return []
    for i,l in enumerate(lines,1):
        if re.search(DESTRUCT_RX,l,re.I):
            return [("high","AG008","Model output selects a destructive call with no approval gate",i)]
    return []
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
            for sev,rid,msg,i in file_rules(lines):
                hits.append((sev,rid,msg,p,i))
                print(f"::error file={p},line={i}::{rid} {msg}")
    h=sum(1 for x in hits if x[0]=="high"); m=len(hits)-h
    print(f"\nAgent PreShip Guard: {h} high, {m} medium findings.")
    print("Heuristic scan only. Full 40-check manual review: https://setrov.gumroad.com/l/vldkkl")
    if (fail=="high" and h) or (fail=="medium" and hits): sys.exit(1)
if __name__=="__main__": main()
