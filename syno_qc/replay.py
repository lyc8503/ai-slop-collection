#!/usr/bin/env python3
# synorelayd replayer — protocol-aligned with official synorelayd (from full TLS capture)
# Standalone (works without DSM). python3 stdlib only.
import http.client, ssl, json, time, os, subprocess, signal, sys, socket, threading

HERE = os.path.dirname(os.path.abspath(__file__))
CFG = json.load(open(os.path.join(HERE, 'replay_config.json')))
LOG = open('/tmp/replay.log', 'a', buffering=1)

def _log(*a):
    s = ' '.join(str(x) for x in a)
    ts = time.strftime('%F %T')
    LOG.write(ts + ' ' + s + '\n')
    print(ts, s, flush=True)

ssl_ctx = ssl.create_default_context()

class Cli:
    UA = CFG['user_agent']
    def __init__(self):
        self.phpsessid = None
    def post(self, host, path, body, cookie=False, timeout=75):
        c = http.client.HTTPSConnection(host, 443, context=ssl_ctx, timeout=timeout)
        hdrs = {
            'Host': host,
            'User-Agent': self.UA,
            'Accept': '*/*',
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        if cookie:
            if self.phpsessid:
                hdrs['Cookie'] = 'PHPSESSID=%s; PHPSESSID=%s' % (self.phpsessid, self.phpsessid)
            else:
                hdrs['Cookie'] = ''
        c.request('POST', path, body=body, headers=hdrs)
        resp = c.getresponse()
        data = resp.read().decode('utf8', 'replace')
        for k, v in resp.getheaders():
            if k.lower() == 'set-cookie' and 'PHPSESSID=' in v:
                self.phpsessid = v.split('PHPSESSID=')[1].split(';')[0]
        _log('HTTP %s %s -> %s | %s' % (path, host, resp.status, data[:220].replace('\n', ' ')))
        c.close()
        return resp.status, data

def do_register(cli):
    b0 = [{"command": "get_register_site", "version": 1}]
    st, d = cli.post('global.quickconnect.to', '/Serv.php',
                     json.dumps(b0, separators=(',', ':')))
    arr = json.loads(d)[0]
    if arr.get('errno') != 0 or arr.get('command') != 'get_register_site':
        _log('BAD get_register_site', d); sys.exit(2)
    cnc = arr['host']
    _log('register site:', cnc)

    reg = {"auth": CFG['auth'], "command": "register", "version": 1}
    net = dict(CFG['update_network'])
    svc = {"command": "update_service",
           "service_add": CFG['services'],
           "service_rm": [], "service_update": [], "version": 1}
    body = json.dumps([reg, net, svc], separators=(',', ':'))
    st, d = cli.post(cnc, '/Serv.php', body, cookie=True)
    arr = json.loads(d)
    reg_resp = next((x for x in arr if x.get('command') == 'register'), None)
    if not reg_resp or reg_resp.get('errno') != 0:
        _log('REGISTER FAILED', d); sys.exit(3)
    _log('REGISTER OK')
    wa = reg_resp['server_wait_cmd']
    dsconf = {"ca_fingerprints": CFG['ca_fingerprints'],
              "command": "update_ds_config", "relay_enabled": True,
              "serverID": CFG['auth']['serverID'], "version": 1}
    st, d = cli.post(cnc, '/Serv.php', json.dumps(dsconf, separators=(',', ':')), cookie=True)
    return cnc, wa['host'], wa['page']

UP_TMPL = """#!/bin/sh
/bin/echo "local_ip=${ifconfig_local} peer=${route_network_1} gw=${route_vpn_gateway}" > /tmp/replay_tunnel_info
ip rule add from ${ifconfig_local} lookup 100 2>/dev/null || true
ip route add default via ${route_vpn_gateway} dev ${dev} table 100 2>/dev/null || true

# ---- tunnel-only firewall: allow inbound tcp to 5001, drop everything else ----
iptables -D INPUT -i ${dev} -j DROP 2>/dev/null
iptables -D INPUT -i ${dev} -p tcp --dport 5001 -j ACCEPT 2>/dev/null
iptables -A INPUT -i ${dev} -p tcp --dport 5001 -j ACCEPT
iptables -A INPUT -i ${dev} -j DROP

/bin/kill -USR2 %d
"""
DOWN_TMPL = """#!/bin/sh
ip rule del from ${ifconfig_local} lookup 100 2>/dev/null || true
ip route flush table 100 2>/dev/null || true
iptables -D INPUT -i ${dev} -p tcp --dport 5001 -j ACCEPT 2>/dev/null
iptables -D INPUT -i ${dev} -j DROP 2>/dev/null
"""

def spawn_openvpn(cand, service, ready_event):
    proto = cand['protocol']
    port = cand['port']
    mtu = cand.get('mtu', 1400)
    relay_ip = service['relay_ip']
    user = service.get('relay_user') or CFG['auth']['serverID']
    pw = service['relay_pass']
    dev = CFG['tun_dev']
    creds = CFG['creds_file']
    with open(creds, 'w') as f:
        f.write('%s\n%s\n' % (user, pw))
    os.chmod(creds, 0o600)
    upf = '/tmp/replay_up.sh'
    downf = '/tmp/replay_down.sh'
    open(upf, 'w').write(UP_TMPL % os.getpid())
    open(downf, 'w').write(DOWN_TMPL)
    os.chmod(upf, 0o755); os.chmod(downf, 0o755)
    args = [CFG['openvpn_bin'], '--client', '--mute-replay-warnings', '--auth-nocache', '--nobind',
            '--tun-mtu', str(mtu), '--ping-exit', '10', '--connect-retry-max', '1',
            '--proto', proto, '--remote', relay_ip, '--port', str(port),
            '--dev', dev, '--ca', CFG['ca_crt'], '--script-security', '2',
            '--auth-user-pass', creds, '--remap-usr1', 'SIGTERM',
            '--cipher', 'none', '--comp-lzo', 'adaptive', '--reneg-sec', '0',
            '--verb', '4', '--log-append', '/tmp/replay.openvpn.log',
            '--route-up', upf, '--down', downf,
            '--syno-no-verify', '--allow-recursive-routing']
    _log('SPAWN:', ' '.join(args))
    p = subprocess.Popen(args, stdout=open('/tmp/replay.stdout.log', 'ab'),
                         stderr=subprocess.STDOUT)
    def watch():
        for _ in range(120):
            time.sleep(0.5)
            if os.path.exists('/tmp/replay_tunnel_info'):
                ready_event.set(); return
    threading.Thread(target=watch, daemon=True).start()
    def rm():
        time.sleep(5)
        try: os.remove(creds)
        except OSError: pass
    threading.Thread(target=rm, daemon=True).start()
    return p

def tunnel_up_cmd(svc):
    b = {"command": "tunnel_ready", "service": svc, "version": 1}
    return bodyof(b)

def bodyof(cmdobj):
    return json.dumps(cmdobj, separators=(',', ':'))

def main():
    cli = Cli()
    running = {'v': True}
    tun = {'p': None, 'svc': None}
    def stop(*a):
        _log('signal exit')
        running['v'] = False
        if tun['p']:
            try: tun['p'].terminate()
            except Exception: pass
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    ready = {'v': False}
    def on_usr2(*a):
        ready['v'] = True
    signal.signal(signal.SIGUSR2, on_usr2)

    cnc, wc_host, wc_page = do_register(cli)
    _log('waitcmd:', wc_host, wc_page)

    poll = 0
    while running['v']:
        body = bodyof({"command": "wait_command", "keepalive": 60, "version": 1})
        try:
            st, d = cli.post(wc_host, '/polling-sub/' + wc_page.split('/')[-1],
                             body, cookie=True, timeout=62)
        except (socket.timeout, ssl.SSLError, OSError) as e:
            poll += 1
            _log('poll #%d' % poll)
            _log(repr(e))
            continue
        if st != 200:
            _log('waitcmd httperr', st); time.sleep(5); continue
        try:
            cmd = json.loads(d)
        except ValueError:
            _log('waitcmd bad json', d); continue
        name = cmd.get('command', '')
        if name != 'create_tunnel':
            _log('CMD:', name, 'poll#', poll)
        poll += 1
        if name == 'create_tunnel':
            svc = cmd['service']
            cands = cmd.get('canidates', [])
            # prefer tcp (v4 then v6), then udp (v4 then v6); fall back to server order
            pref = ['tcp', 'tcp6', 'udp', 'udp6']
            openvpn_cands = [c for c in cmd.get('canidates', [])
                             if c.get('type') == 'openvpn']
            pick = min(openvpn_cands,
                       key=lambda c: pref.index(c.get('protocol')) if c.get('protocol') in pref else 99) if openvpn_cands else None
            if not pick:
                _log('no candidate'); continue
            _log('create tunnel cand=%s svc=%s' % (json.dumps(pick), json.dumps(svc)))
            if tun['p']:
                try: tun['p'].terminate()
                except Exception: pass
            try: os.remove('/tmp/replay_tunnel_info')
            except OSError: pass
            readyev = threading.Event()
            tun['p'] = spawn_openvpn(pick, svc, readyev)
            tun['svc'] = svc
            _log('waiting for tunnel...')
            if readyev.wait(40):
                _log('tunnel UP, sending tunnel_ready')
                st2, d2 = cli.post(cnc, '/Serv.php',
                                   bodyof({"command": "tunnel_ready", "service": svc, "version": 1}),
                                   cookie=True, timeout=10)
                _log('tunnel_ready ->', d2[:160])
            else:
                _log('tunnel not up in time, will wait for next create_tunnel')
        elif name == 'update_ds_config':
            pass
        elif name == 'unregister':
            _log('server unregister, exit'); running['v'] = False
        else:
            _log('unknown cmd', name, d[:200])

    if tun['p']:
        try: tun['p'].terminate()
        except Exception: pass
    try:
        cli.post(cnc, '/Serv.php', bodyof({"command": "unregister", "version": 1}),
                 cookie=True, timeout=10)
        _log('unregistered')
    except Exception as e:
        _log('unregister err', repr(e))

if __name__ == '__main__':
    main()
