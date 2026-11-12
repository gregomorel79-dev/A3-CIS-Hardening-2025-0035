#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cis_hardening.py  -  Auditoria y hardening automatizado (CIS Cisco IOS Benchmark)
Estudiante: Gregorys Morel Duluc | Matricula 2025-0035 | Seguridad de Redes - ITLA

Escanea los equipos de la topologia (R1, SW1, SW2) por la consola Telnet de GNS3
y evalua las recomendaciones CIS elegidas.

Modos:
  --mode audit   Solo crea el informe (NO aplica ninguna regla).
  --mode apply   Audita, aplica las reglas que fallan, vuelve a auditar y crea
                 el informe posterior (antes / despues).
  --offline-dir  Audita archivos de running-config guardados (sin conectarse).

Ejemplos:
  python cis_hardening.py --mode audit
  python cis_hardening.py --mode apply
  python cis_hardening.py --mode audit --devices R1,SW1
  python cis_hardening.py --mode audit --offline-dir ../configs
"""
import argparse, socket, time, re, os, sys, datetime, html

DEFAULT_HOST = "192.168.56.102"                      # GNS3 VM
DEFAULT_PORTS = {"R1": 5000, "SW1": 5001, "SW2": 5003}  # consolas telnet (Topology Summary)
DEVTYPE = {"R1": "router", "SW1": "switch", "SW2": "switch"}

ADMIN_USER = "admin"
ADMIN_PASS = "Local2025Lab"
ENABLE_SECRET = "Enable2025Lab"
DOMAIN = "lab20250035.local"
BANNER = "ACCESO RESTRINGIDO - Solo personal autorizado. Toda actividad es monitoreada."

IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240
PROMPT_RE = re.compile(r"(?:^|\n)([A-Za-z0-9_.\-]+(?:\([A-Za-z0-9_.\-/ ]+\))?[#>])\s*$")


# ----------------------------------------------------------------- consola telnet
class Console:
    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port), timeout=10)
        self.sock.settimeout(0.5)

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass

    def _recv(self):
        try:
            d = self.sock.recv(4096)
        except socket.timeout:
            return b""
        if d == b"":
            raise ConnectionError("La consola cerro la conexion")
        out, i = bytearray(), 0
        while i < len(d):
            b = d[i]
            if b == IAC and i + 1 < len(d):
                c = d[i + 1]
                if c in (DO, DONT, WILL, WONT) and i + 2 < len(d):
                    opt = d[i + 2]
                    resp = WONT if c == DO else (DONT if c == WILL else None)
                    if resp:
                        self.sock.sendall(bytes([IAC, resp, opt]))
                    i += 3
                    continue
                if c == SB:
                    j = d.find(bytes([IAC, SE]), i)
                    i = j + 2 if j != -1 else len(d)
                    continue
                if c == IAC:
                    out.append(255)
                i += 2
                continue
            out.append(b)
            i += 1
        return bytes(out)

    def drain(self, t=0.4):
        end = time.time() + t
        while time.time() < end:
            self._recv()

    def read_until_prompt(self, timeout=20):
        buf, end = "", time.time() + timeout
        while time.time() < end:
            d = self._recv()
            if d:
                buf += d.decode("latin-1")
                if "--More--" in buf[-30:]:
                    self.sock.sendall(b" ")
                    buf = buf.replace("--More--", "")
                continue
            if PROMPT_RE.search(buf.replace("\r", "")):
                return buf
        return buf

    def sync(self):
        """Deja la consola en modo privilegiado (#)."""
        self.drain(0.6)
        for _ in range(8):
            self.sock.sendall(b"\r")
            buf = self.read_until_prompt(4).replace("\r", "")
            m = PROMPT_RE.search(buf)
            if m:
                p = m.group(1)
                if "(" in p:
                    self.sock.sendall(b"end\r"); self.read_until_prompt(4); continue
                if p.endswith(">"):
                    self.sock.sendall(b"enable\r"); self.read_until_prompt(4); continue
                return p
            if "Username:" in buf or "Password:" in buf:
                raise RuntimeError("La consola pide credenciales (Username/Password). "
                                   "Entra una vez a mano y deja el prompt en R1#.")
        raise RuntimeError("No se encontro el prompt del equipo en la consola.")

    def run(self, cmd, timeout=20):
        self.drain(0.15)
        self.sock.sendall(cmd.encode("latin-1") + b"\r")
        text = self.read_until_prompt(timeout).replace("\r", "")
        lines = text.split("\n")
        key = cmd.strip()[:10]
        if lines and key and key in lines[0]:
            lines = lines[1:]
        if lines and PROMPT_RE.search("\n" + lines[-1]):
            lines = lines[:-1]
        return "\n".join(lines).strip("\n")


# ----------------------------------------------------------------- parser de running-config
class Cfg:
    def __init__(self, text):
        self.text = text
        self.top = []          # [(cabecera, [hijos])]
        cur = None
        for raw in text.splitlines():
            l = raw.rstrip()
            if not l.strip() or l.strip() == "!":
                cur = None
                continue
            if l.startswith(" "):
                if cur is not None:
                    cur[1].append(l.strip())
            else:
                cur = (l.strip(), [])
                self.top.append(cur)

    def has(self, rx):
        return any(re.search(rx, h) for h, _ in self.top)

    def blocks(self, rx):
        return [(h, c) for h, c in self.top if re.search(rx, h)]


def child(children, rx):
    return any(re.search(rx, c) for c in children)


# ----------------------------------------------------------------- controles CIS
CHECKS = []


def check(cid, cis, title, why, scope="all"):
    def deco(fn):
        CHECKS.append(dict(id=cid, cis=cis, title=title, why=why, scope=scope, fn=fn))
        return fn
    return deco


# cada funcion devuelve (estado, detalle, comandos_de_correccion)
# estado: True/False/None(N/A)

@check("H01", "Enable 'service password-encryption'",
       "Cifra las contrasenas en texto claro del running-config",
       "Evita que alguien que vea la configuracion (hombro, respaldo, TFTP) lea contrasenas.")
def c01(c, t):
    ok = c.has(r"^service password-encryption$")
    return ok, "presente" if ok else "no configurado", ["service password-encryption"]


@check("H02", "Set 'enable secret'",
       "Contrasena de modo privilegiado con hash (enable secret)",
       "'enable secret' guarda un hash, 'enable password' es reversible.")
def c02(c, t):
    ok = c.has(r"^enable secret ") and not c.has(r"^enable password ")
    return ok, "enable secret presente" if ok else "falta enable secret o hay enable password", \
        ["?no enable password", "enable secret " + ENABLE_SECRET]


@check("H03", "Set 'username secret' for all local users",
       "Usuarios locales con secret (hash) y sin contrasenas en texto claro",
       "El usuario local de respaldo debe almacenarse con hash.")
def c03(c, t):
    plain = [h.split()[1] for h, _ in c.top if re.match(r"^username \S+( privilege \d+)? (password|nopassword)", h)]
    sec = c.has(r"^username \S+ .*secret ")
    ok = sec and not plain
    cmds = []
    for u in plain:
        cmds.append("?no username " + u)
    if not sec or plain:
        cmds.append("username %s privilege 15 secret %s" % (ADMIN_USER, ADMIN_PASS))
    return ok, "usuarios con secret" if ok else ("sin usuario con secret" if not sec else "usuarios con password: " + ",".join(plain)), cmds


def _vty(c):
    return c.blocks(r"^line vty")


@check("H04", "Set 'transport input ssh' for 'line vty' connections",
       "Solo SSH en las lineas vty (sin Telnet)",
       "Telnet envia usuario y contrasena en texto claro; SSH cifra la sesion.")
def c04(c, t):
    bad = [h for h, ch in _vty(c) if not child(ch, r"^transport input ssh$")]
    cmds = []
    for h in bad:
        cmds += [h, "transport input ssh", "exit"]
    return not bad, "todas las vty solo SSH" if not bad else "falla en: " + "; ".join(bad), cmds


@check("H05", "Set 'login local' (authentication) for 'line vty'",
       "Las vty exigen usuario y contrasena locales",
       "Sin autenticacion de usuario cualquiera que llegue a la vty entra.")
def c05(c, t):
    bad = [h for h, ch in _vty(c) if not child(ch, r"^login local$")]
    cmds = []
    for h in bad:
        cmds += [h, "login local", "exit"]
    return not bad, "todas las vty con login local" if not bad else "falla en: " + "; ".join(bad), cmds


def _timeout_ok(ch):
    for x in ch:
        m = re.match(r"^exec-timeout (\d+)(?: (\d+))?$", x)
        if m:
            tot = int(m.group(1)) * 60 + int(m.group(2) or 0)
            return 0 < tot <= 600
    return False


@check("H06", "Set 'exec-timeout' to <= 10 minutes (con 0 / aux 0 / vty)",
       "Cierra sesiones inactivas (maximo 10 min)",
       "Una sesion abierta y olvidada es una puerta abierta a la configuracion.")
def c06(c, t):
    blks = c.blocks(r"^line (con|aux|vty)")
    bad = [h for h, ch in blks if not _timeout_ok(ch)]
    cmds = []
    for h in bad:
        cmds += [h, "exec-timeout 5 0", "exit"]
    return not bad, "todas las lineas <= 10 min" if not bad else "sin timeout valido en: " + "; ".join(bad), cmds


@check("H07", "Set 'no exec' for 'line aux 0'",
       "Deshabilita el puerto auxiliar",
       "El puerto AUX es un acceso fisico/modem que casi nadie vigila.")
def c07(c, t):
    blks = c.blocks(r"^line aux")
    if not blks:
        return None, "N/A (el equipo no tiene aux)", []
    bad = [h for h, ch in blks if not child(ch, r"^no exec$")]
    cmds = []
    for h in bad:
        cmds += [h, "no exec", "exit"]
    return not bad, "aux con no exec" if not bad else "aux con exec activo", cmds


@check("H08", "Set 'ip domain-name'",
       "Dominio configurado (requisito para generar claves SSH)",
       "SSH necesita hostname y dominio para crear la clave RSA del equipo.")
def c08(c, t):
    ok = c.has(r"^ip domain[- ]name \S+")
    return ok, "dominio configurado" if ok else "sin dominio", ["ip domain-name " + DOMAIN]


@check("H09", "Set version 2 for 'ip ssh version'",
       "SSH version 2 (clave RSA creada si no existe)",
       "SSHv1 tiene fallas criptograficas conocidas.")
def c09(c, t):
    ok = c.has(r"^ip ssh version 2$")
    return ok, "SSH v2" if ok else "SSH v2 no configurado", ["@RSA", "ip ssh version 2"]


@check("H10", "Set 'ip ssh time-out' <= 60 and 'ip ssh authentication-retries' <= 3",
       "Tiempo de negociacion y reintentos SSH limitados",
       "Reduce el margen para ataques de fuerza bruta por SSH.")
def c10(c, t):
    ok = c.has(r"^ip ssh time-out ([1-9]|[1-5]\d|60)$") and c.has(r"^ip ssh authentication-retries [1-3]$")
    return ok, "time-out y reintentos limitados" if ok else "faltan time-out/reintentos", \
        ["ip ssh time-out 60", "ip ssh authentication-retries 3"]


@check("H11", "Set the 'banner-text' for 'banner login'",
       "Aviso legal al conectarse",
       "Da base legal para actuar contra accesos no autorizados.")
def c11(c, t):
    ok = c.has(r"^banner (login|motd|exec) ")
    return ok, "banner presente" if ok else "sin banner", ["banner login # %s #" % BANNER]


@check("H12", "Set 'no ip http server' / 'no ip http secure-server'",
       "Servidor web del equipo deshabilitado",
       "Reduce la superficie de ataque: la administracion se hace por SSH.")
def c12(c, t):
    ok = not c.has(r"^ip http server$") and not c.has(r"^ip http secure-server$")
    return ok, "HTTP/HTTPS deshabilitado" if ok else "servidor web activo", \
        ["no ip http server", "no ip http secure-server"]


@check("H13", "Set 'no ip source-route'",
       "Deshabilita el enrutamiento de origen (source routing)",
       "Permite a un atacante dictar la ruta de sus paquetes y saltarse controles.")
def c13(c, t):
    ok = c.has(r"^no ip source-route$")
    return ok, "deshabilitado" if ok else "habilitado (por defecto)", ["no ip source-route"]


@check("H14", "Set 'no ip bootp server'",
       "Servicio BOOTP deshabilitado",
       "Servicio obsoleto que no se usa; menos servicios, menos riesgo.")
def c14(c, t):
    ok = c.has(r"^no ip bootp server$")
    return ok, "deshabilitado" if ok else "no deshabilitado", ["no ip bootp server"]


@check("H15", "Set 'no cdp run'",
       "CDP deshabilitado globalmente",
       "CDP revela modelo, IOS e IPs del equipo a cualquier vecino.")
def c15(c, t):
    ok = c.has(r"^no cdp run$")
    return ok, "CDP deshabilitado" if ok else "CDP activo", ["no cdp run"]


@check("H16", "Set 'service timestamps log datetime'",
       "Logs con fecha y hora",
       "Sin hora exacta no se pueden correlacionar eventos en una investigacion.")
def c16(c, t):
    ok = c.has(r"^service timestamps log datetime")
    return ok, "timestamps en logs" if ok else "sin timestamps", ["service timestamps log datetime msec"]


@check("H17", "Set 'logging buffered' (severity level)",
       "Registro local de eventos en memoria",
       "Conserva evidencia local de lo ocurrido en el equipo.")
def c17(c, t):
    ok = c.has(r"^logging buffered \d+")
    return ok, "logging buffered activo" if ok else "sin logging buffered", ["logging buffered 16384 informational"]


@check("H18", "Enable login protection ('login block-for')",
       "Bloqueo temporal tras intentos fallidos de login",
       "Frena ataques de adivinacion de contrasenas contra las vty.")
def c18(c, t):
    ok = c.has(r"^login block-for \d+ attempts \d+ within \d+")
    return ok, "login block-for activo" if ok else "sin login block-for", ["login block-for 60 attempts 5 within 60"]


@check("H19", "Set 'no ip proxy-arp', 'no ip redirects', 'no ip unreachables' on L3 interfaces",
       "Servicios IP innecesarios apagados en cada interfaz con IP",
       "Evitan fuga de informacion y abuso (proxy ARP, redirects, ICMP unreachable).")
def c19(c, t):
    bad, cmds = [], []
    for h, ch in c.blocks(r"^interface "):
        if child(ch, r"^ip address \d") :
            miss = [x for x in ("no ip proxy-arp", "no ip redirects", "no ip unreachables") if x not in ch]
            if miss:
                bad.append(h.replace("interface ", ""))
                cmds += [h] + miss + ["exit"]
    return not bad, "interfaces L3 endurecidas" if not bad else "faltan en: " + ", ".join(bad), cmds


@check("H20", "Enable 'spanning-tree portfast bpduguard default'",
       "BPDU Guard por defecto en puertos de acceso (solo switches)",
       "Un switch pirata conectado a un puerto de acceso no puede alterar el STP.", scope="switch")
def c20(c, t):
    if t != "switch":
        return None, "N/A (solo switches)", []
    ok = c.has(r"^spanning-tree portfast bpduguard default$")
    return ok, "bpduguard default activo" if ok else "no configurado", ["spanning-tree portfast bpduguard default"]


@check("H21", "Do not use default SNMP community strings (public/private)",
       "SNMP sin comunidades por defecto",
       "'public' y 'private' son lo primero que prueba un atacante.")
def c21(c, t):
    bad = re.findall(r"^snmp-server community (public|private)\b", c.text, re.M)
    cmds = ["?no snmp-server community " + b for b in set(bad)]
    return not bad, "sin comunidades por defecto" if not bad else "comunidad por defecto: " + ",".join(set(bad)), cmds


def evaluate(cfg, dtype):
    rows = []
    for k in CHECKS:
        st, det, fix = k["fn"](cfg, dtype)
        rows.append(dict(id=k["id"], cis=k["cis"], title=k["title"], why=k["why"], ok=st, detail=det, fix=fix))
    return rows


def score(rows):
    app = [r for r in rows if r["ok"] is not None]
    p = sum(1 for r in app if r["ok"])
    return p, len(app), (100.0 * p / len(app) if app else 0)


# ----------------------------------------------------------------- acceso al equipo
def get_config(con):
    con.run("terminal length 0")
    out = con.run("show running-config", timeout=90)
    out = re.sub(r"^(Building configuration\.\.\.|Current configuration.*)\n?", "", out, flags=re.M)
    return out


def apply_fixes(con, rows, log):
    cmds = []
    for r in rows:
        if r["ok"] is False:
            cmds += r["fix"]
    if not cmds:
        return [], []
    errors, applied = [], []
    con.run("configure terminal")
    for cmd in cmds:
        opt = cmd.startswith("?")
        cmd = cmd.lstrip("?")
        if cmd == "@RSA":
            k = con.run("do show crypto key mypubkey rsa")
            if "Key name" not in k:
                log("    generando clave RSA 2048 (puede tardar) ...")
                con.run("crypto key generate rsa modulus 2048", timeout=360)
                applied.append("crypto key generate rsa modulus 2048")
            continue
        out = con.run(cmd, timeout=40)
        applied.append(cmd)
        if re.search(r"^% ", out, re.M) and not opt and "already" not in out.lower():
            errors.append("%s -> %s" % (cmd, out.strip().splitlines()[0]))
    con.run("end")
    con.run("write memory", timeout=90)
    return applied, errors


# ----------------------------------------------------------------- informes
def txt_report(mode, results, stamp):
    L = ["INFORME CIS HARDENING (%s) - %s" % ("SOLO AUDITORIA" if mode == "audit" else "APLICACION + INFORME POSTERIOR", stamp),
         "Estudiante: Gregorys Morel Duluc | Matricula 2025-0035", "=" * 78]
    for dev, d in results.items():
        L.append("")
        L.append("EQUIPO %s (%s)" % (dev, DEVTYPE.get(dev, "?")))
        for tag, rows in (("ANTES", d["before"]), ("DESPUES", d.get("after"))):
            if rows is None:
                continue
            p, n, pc = score(rows)
            L.append("  -- %s: %d/%d controles (%.0f%%)" % (tag, p, n, pc))
            for r in rows:
                s = "N/A " if r["ok"] is None else ("PASS" if r["ok"] else "FAIL")
                L.append("   [%s] %s %s | %s" % (s, r["id"], r["title"], r["detail"]))
        if d.get("applied"):
            L.append("  Comandos aplicados: %d" % len(d["applied"]))
        for e in d.get("errors", []):
            L.append("  ERROR: " + e)
    return "\n".join(L) + "\n"


def html_report(mode, results, stamp):
    css = ("body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#222}h1{color:#1a2b4a}"
           "table{border-collapse:collapse;width:100%;margin:8px 0 24px}th,td{border:1px solid #ccc;padding:6px 8px;font-size:13px;text-align:left}"
           "th{background:#1a2b4a;color:#fff}.PASS{background:#e3f6e8;color:#157a35;font-weight:600}"
           ".FAIL{background:#fde4e1;color:#b32a1c;font-weight:600}.NA{background:#eee;color:#666}.score{font-size:18px;font-weight:700}")
    h = ["<html><head><meta charset='utf-8'><title>Informe CIS</title><style>%s</style></head><body>" % css,
         "<h1>Informe CIS Hardening &mdash; %s</h1>" % ("Solo auditor&iacute;a (sin aplicar reglas)" if mode == "audit" else "Aplicaci&oacute;n de reglas + informe posterior"),
         "<p>Estudiante: Gregorys Morel Duluc &middot; Matr&iacute;cula 2025-0035 &middot; Generado: %s</p>" % stamp]

    def cell(r):
        s = "NA" if r["ok"] is None else ("PASS" if r["ok"] else "FAIL")
        return "<td class='%s'>%s</td>" % (s, "N/A" if s == "NA" else s)

    for dev, d in results.items():
        h.append("<h2>%s <small>(%s)</small></h2>" % (dev, DEVTYPE.get(dev, "")))
        p, n, pc = score(d["before"])
        line = "Antes: <span class='score'>%d/%d (%.0f%%)</span>" % (p, n, pc)
        if d.get("after") is not None:
            p2, n2, pc2 = score(d["after"])
            line += " &rarr; Despu&eacute;s: <span class='score'>%d/%d (%.0f%%)</span>" % (p2, n2, pc2)
        h.append("<p>%s</p>" % line)
        h.append("<table><tr><th>ID</th><th>Recomendaci&oacute;n CIS</th><th>Por qu&eacute;</th><th>Antes</th>%s<th>Detalle</th></tr>" %
                 ("<th>Despu&eacute;s</th>" if d.get("after") is not None else ""))
        aft = {r["id"]: r for r in d["after"]} if d.get("after") is not None else {}
        for r in d["before"]:
            h.append("<tr><td>%s</td><td>%s</td><td>%s</td>%s%s<td>%s</td></tr>" % (
                r["id"], html.escape(r["cis"]), html.escape(r["why"]), cell(r),
                cell(aft[r["id"]]) if aft else "",
                html.escape((aft[r["id"]] if aft else r)["detail"])))
        h.append("</table>")
        if d.get("applied"):
            h.append("<details><summary>Comandos aplicados (%d)</summary><pre>%s</pre></details>" % (len(d["applied"]), html.escape("\n".join(d["applied"]))))
        for e in d.get("errors", []):
            h.append("<p style='color:#b32a1c'>ERROR: %s</p>" % html.escape(e))
    h.append("</body></html>")
    return "\n".join(h)


# ----------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description="Auditoria / hardening CIS Cisco IOS")
    ap.add_argument("--mode", choices=["audit", "apply"], default="audit")
    ap.add_argument("--devices", default="R1,SW1,SW2")
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--ports", default="", help="R1=5000,SW1=5001,SW2=5003")
    ap.add_argument("--offline-dir", default="", help="audita <EQUIPO>*.txt guardados, sin conectarse")
    ap.add_argument("--configs-dir", default="configs")
    ap.add_argument("--reports-dir", default="reports")
    ap.add_argument("--yes", action="store_true", help="no pedir confirmacion en modo apply")
    a = ap.parse_args()

    ports = dict(DEFAULT_PORTS)
    for kv in filter(None, a.ports.split(",")):
        k, v = kv.split("=")
        ports[k.strip()] = int(v)
    devs = [d.strip() for d in a.devices.split(",") if d.strip()]
    if a.offline_dir and a.mode == "apply":
        sys.exit("--offline-dir solo permite --mode audit")
    if a.mode == "apply" and not a.yes:
        if input("Se APLICARAN cambios de hardening a %s. Escribe SI para continuar: " % ",".join(devs)).strip().upper() != "SI":
            sys.exit("Cancelado.")

    os.makedirs(a.configs_dir, exist_ok=True)
    os.makedirs(a.reports_dir, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    fstamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    results = {}
    log = lambda s: print(s, flush=True)

    for dev in devs:
        dtype = DEVTYPE.get(dev, "router")
        log("\n=== %s (%s) ===" % (dev, dtype))
        d = {"after": None, "applied": [], "errors": []}
        if a.offline_dir:
            fn = [f for f in sorted(os.listdir(a.offline_dir)) if f.upper().startswith(dev.upper()) and f.endswith(".txt")]
            if not fn:
                log("  sin archivo offline para " + dev); continue
            text = open(os.path.join(a.offline_dir, fn[0]), encoding="utf-8", errors="replace").read()
            d["before"] = evaluate(Cfg(text), dtype)
        else:
            con = Console(a.host, ports[dev])
            try:
                con.sync()
                text = get_config(con)
                open(os.path.join(a.configs_dir, "%s-running-config-ANTES.txt" % dev), "w", encoding="utf-8").write(text)
                d["before"] = evaluate(Cfg(text), dtype)
                p, n, pc = score(d["before"])
                log("  ANTES: %d/%d controles (%.0f%%)" % (p, n, pc))
                if a.mode == "apply":
                    log("  aplicando reglas ...")
                    d["applied"], d["errors"] = apply_fixes(con, d["before"], log)
                    con.sync()
                    text2 = get_config(con)
                    open(os.path.join(a.configs_dir, "%s-running-config-DESPUES.txt" % dev), "w", encoding="utf-8").write(text2)
                    d["after"] = evaluate(Cfg(text2), dtype)
                    p, n, pc = score(d["after"])
                    log("  DESPUES: %d/%d controles (%.0f%%)" % (p, n, pc))
            finally:
                con.close()
        last = d["after"] if d["after"] is not None else d["before"]
        for r in last:
            s = "N/A " if r["ok"] is None else ("PASS" if r["ok"] else "FAIL")
            log("   [%s] %s %s - %s" % (s, r["id"], r["title"], r["detail"]))
        for e in d["errors"]:
            log("   ERROR: " + e)
        results[dev] = d

    if not results:
        sys.exit("Sin resultados.")
    base = os.path.join(a.reports_dir, "informe_%s_%s" % ("auditoria" if a.mode == "audit" else "aplicacion", fstamp))
    open(base + ".txt", "w", encoding="utf-8").write(txt_report(a.mode, results, stamp))
    open(base + ".html", "w", encoding="utf-8").write(html_report(a.mode, results, stamp))
    log("\nInforme: %s.html  /  %s.txt" % (base, base))


if __name__ == "__main__":
    main()
