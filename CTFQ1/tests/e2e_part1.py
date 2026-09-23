import os, sys, time, socket, subprocess, random
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT); sys.path.insert(0, os.path.join(ROOT,"solver"))
import circuitlib as C
from part1_solver import parse_circuit_txt, SocketOracle, solve_part1

OUT=os.path.join(ROOT,"tests","e2e"); os.makedirs(OUT,exist_ok=True)
PORT=31355
subprocess.run([sys.executable, os.path.join(ROOT,"generate_circuits.py"),
                "--seed","98","--out-dir",OUT], check=True,
               stderr=subprocess.DEVNULL)
env=dict(os.environ, CTF_SECRET=os.path.join(OUT,"circuit_secret.json"),
         CTF_HOST="127.0.0.1", CTF_PORT=str(PORT))
srv=subprocess.Popen([sys.executable, os.path.join(ROOT,"nc_server.py")], env=env,
                     stderr=subprocess.PIPE)
try:
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1",PORT),timeout=0.3).close(); break
        except OSError:
            time.sleep(0.05)
    info=parse_circuit_txt(os.path.join(OUT,"circuit.txt"))
    widths={n:b["w_in"] for n,b in info["blocks"].items()}
    orc=SocketOracle("127.0.0.1",PORT,widths)
    t0=time.time()
    k1,resp,per=solve_part1(orc,info,random.Random(1),verbose=True)
    dt=time.time()-t0
    print("K1 =",k1)
    print("SUBMIT response:",resp)
    print("total queries:",sum(per.values()),"per-block:",per,"(%.2fs)"%dt)
    # cross-check vs secret
    import json
    sec=json.load(open(os.path.join(OUT,"circuit_secret.json")))
    exp=C.derive_key(sec,sec["meta"]["key_order"]).hex()
    assert k1==exp, "key mismatch"
    assert resp.startswith("flag{PART1"), "no flag"
    # budget check: also try to bust the budget on one block
    orc.close()
    print("E2E PART1: OK  (flag matches, key matches secret)")
finally:
    srv.terminate()
    try: srv.wait(timeout=3)
    except Exception: srv.kill()
