import subprocess, atexit, threading, yaml, os, re, socket, time
from collections.abc import Mapping
from partition import Partition
from kbupd import Kbupd
from util import get_ppid, choices

DEV='lo'

first_netem = True

checked_ss = False
ss = './ss'

stopped = []

iptables = set()

first_rewrite = True

def netem_del():
    global first_netem
    subprocess.run(['sudo', 'tc', 'qdisc', 'del', 'dev', DEV, 'root'],
                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    first_netem = True

def iptables_add(rule):
    global iptables
    if len(iptables) == 0:
        atexit.register(iptables_flush)
    iptables.add(tuple(rule))

def iptables_commit():
    global iptables

    old_rules = subprocess.run(['sudo', 'iptables-save', '-c'], check=True,
                               stdout=subprocess.PIPE, universal_newlines=True).stdout.split('\n')

    new_rules = []
    table = None
    for rule in old_rules:
        if len(rule) > 0:
            if rule[0] == '*':
                table = rule[1:]
            elif table == 'filter' and 'OUTPUT' in rule.split():
                continue
            elif rule == 'COMMIT' and table == 'filter':
                new_rules.extend([' '.join(r) for r in iptables])
        new_rules.append(rule)

    subprocess.run(['sudo', 'iptables-restore', '-T', 'filter'],
                   input='\n'.join(new_rules), universal_newlines=True, check=True)

def iptables_flush():
    global iptables

    subprocess.run(['sudo', 'iptables', '-F', 'OUTPUT'], check=True)
    iptables = set()
    atexit.unregister(iptables_flush)

def iptables_nat_add(rule):
    global first_rewrite
    if first_rewrite:
        atexit.register(iptables_nat_flush)
        first_rewrite = False
    subprocess.run(rule, check=True)

def iptables_nat_commit():
    pass

def iptables_nat_flush():
    subprocess.run(['sudo', 'iptables', '-t', 'nat', '-F', 'OUTPUT'], check=True)

class PlaybackThread(threading.Thread):
    #XXX Add ability to apply loss or latency to specific nodes and/or nodepairs.
    def verb_netem(self, latency = None, loss = None):
        global first_netem
        if first_netem:
            netem_del()
            verb = 'add'
            atexit.register(netem_del)
            first_netem = False
        else:
            verb = 'change'
            assert(latency or loss)

        args = []

        if latency:
            latency_cpy = dict(latency)
            if 'ms' in latency:
                args.extend(['delay', str(latency['ms']) + 'ms'])
                del(latency_cpy['ms'])
            if 'variation_ms' in latency:
                assert('ms' in latency)
                args.extend([str(latency['variation_ms']) + 'ms'])
                del(latency_cpy['variation_ms'])
            if 'variation_correlation_pct' in latency:
                assert('variation_ms' in latency)
                args.extend([str(latency['variation_correlation_pct']) + '%'])
                del(latency_cpy['variation_correlation_pct'])
            if 'variation_distribution' in latency:
                assert('variation_ms' in latency)
                args.extend(['distribution', str(latency['variation_distribution'])])
                del(latency_cpy['variation_distribution'])
                assert(latency_cpy == {})

        if loss:
            loss_cpy = dict(loss)
            if 'pct' in loss:
                args.extend(['loss', str(loss['pct']) + '%'])
                del(loss_cpy['pct'])
            if 'correlation_pct' in loss:
                assert('pct' in loss)
                args.extend([str(loss['correlation_pct']) + '%'])
                del(loss_cpy['correlation_pct'])
                assert(loss_cpy == {})

        print('NETEM:',
              ' '.join(['sudo', 'tc', 'qdisc', verb, 'dev', DEV, 'root', 'netem', *args]),
              flush=True)
        subprocess.run(['sudo', 'tc', 'qdisc', verb, 'dev', DEV, 'root', 'netem', *args],
                       check=True)

    def verb_randstop(self, replicas_per_partition = 1, num_partitions = 0):
        global stopped
        if len(Partition.partitions) == 0:
            return
        if num_partitions == 0:
            partitions = Partition.partitions
        else:
            partitions = choices(Partition.partitions, k=num_partitions)
        for partition in partitions:
            if len(partition.peers) == 0:
                continue
            for replica in choices(partition.peers, k=replicas_per_partition):
                print('RANDSTOP:', replica, flush=True)
                replica.sigstop()
                stopped.append(replica)

    def verb_contall(self):
        global stopped
        for replica in set(stopped):
            print('CONTALL:', replica, flush=True)
            replica.sigcont()
            stopped = []

    def verb_randtcpkill(self, num_replicas = 1):
        global checked_ss, ss
        if not checked_ss:
            if not os.access(ss, os.X_OK):
                ss = 'ss'
            out = subprocess.run([ss, '-h'], stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT).stdout.decode()
            if not '-K,' in out.split():
                #Try putting a newer 'ss' binary in the same dir as the tests.
                raise Exception("randtcpkill requires 'ss' to support -K")
            checked_ss = True

        replicas = []
        if len(Partition.partitions) == 0:
            return
        for partition in Partition.partitions:
            if len(partition.peers) == 0:
                continue
            for replica in partition.peers:
                replicas.append(replica)
        if num_replicas == 0:
            num_replicas = len(replicas)
        for replica in choices(replicas, k=num_replicas):
            cmd = ['sudo', ss, '-K', 'dst', '127.0.0.1',
                   'dport', '=', str(replica.peer_port)]
            print('RANDTCPKILL:', ' '.join(cmd), flush=True)
            subprocess.run(cmd)

    def verb_adddrop(self, src, dst, single_conn=False):
        for partition in Partition.partitions:
            leader, followers = partition.get_replicas()

            rule = ['-A', 'OUTPUT']

            if dst == 'any':
                dstport = None
            elif dst == 'FE':
                assert(False) #replicas don't connect back to FEs.
            elif dst == 'leader':
                if not leader:
                    continue
                dstport = leader.peer_port
            elif dst.startswith('replica'):
                num = int(dst[7:])
                if num >= len(followers):
                    continue
                dstport = followers[num].peer_port
            else:
                assert(False)
            if dstport:
                rule.extend(['-p', 'tcp', '-m', 'tcp', '--dport', '%s' % dstport])

            if single_conn:
                assert(dstport)
                conns = subprocess.run(['ss', '-n', '-p',
                                        'state', 'established', '( dport = :%s )' % dstport],
                                       stdout=subprocess.PIPE, universal_newlines=True, check=True).stdout
                for conn in conns.split('\n')[1:]:
                    m = re.search(r'tcp +[0-9]+ +[0-9]+ +[0-9.]+:([0-9]+).*pid=([0-9]+)', conn)
                    if m:
                        srcport = int(m[1])
                        kbuptlsd_pid = int(m[2])
                        kbupd_pid = get_ppid(kbuptlsd_pid)

                        if not os.readlink('/proc/%s/exe' % kbuptlsd_pid).endswith('/kbuptlsd'):
                            continue

                        if src == 'FE':
                            assert(len(Kbupd.frontends) <= 1) #XXX We only support 1 FE
                            if len(Kbupd.frontends) > 0 and Kbupd.frontends[0].proc.pid == kbupd_pid:
                                break
                        elif src == 'leader':
                            if not leader:
                                continue
                            if leader.proc.pid == kbupd_pid:
                                break
                        elif src.startswith('replica'):
                            num = int(src[7:])
                            if num >= len(followers):
                                continue
                            if followers[num].proc.pid == kbupd_pid:
                                break
                        else:
                            assert(False)
                else:
                    #Didn't find any connections.
                    continue
                rule.extend(['--sport', '%s' % srcport])
            else:
                if src == 'any':
                    classid = None
                elif src == 'FE':
                    classid = 1337
                elif src == 'leader':
                    if not leader:
                        continue
                    classid = leader.net_cls_id
                elif src.startswith('replica'):
                    num = int(src[7:])
                    if num >= len(followers):
                        continue
                    classid = followers[num].net_cls_id
                else:
                    assert(False)
                if classid:
                    rule.extend(['-m', 'cgroup', '--cgroup', '%s' % classid])

            rule.extend(['-j', 'DROP'])
            print('ADDDROP:', rule, flush=True)
            iptables_add(rule)
        iptables_commit()

    def verb_droptohost(self, host, send_rst=False):
        try:
            iplist = socket.gethostbyname_ex(host)[2]
        except OSError as e:
            print(e, "Retrying")
            time.sleep(5)
            iplist = socket.gethostbyname_ex(host)[2]
        for ip in iplist:
            rule = ['-A', 'OUTPUT', '-p', 'tcp', '-d', ip ]
            if send_rst:
                #XXX Don't fail attestation for FEs, because that causes them to crash.
                rule.extend(['-m', 'cgroup', '!', '--cgroup', '1337'])
                rule.extend(['-j', 'REJECT'])
            else:
                rule.extend(['-j', 'DROP'])
            print('DROPTOHOST:', rule, flush=True)
            iptables_add(rule)
        iptables_commit()

    def verb_flushdrop(self):
        print('FLUSHDROP', flush=True)
        iptables_flush()

    def verb_rewritedst(self, old_dst, new_dst):
        try:
            iplist = socket.gethostbyname_ex(old_dst)[2]
        except OSError as e:
            print(e, "Retrying")
            time.sleep(5)
            iplist = socket.gethostbyname_ex(old_dst)[2]
        try:
            new_dst_ip = socket.gethostbyname(new_dst)
        except OSError:
            print(e, "Retrying")
            time.sleep(5)
            new_dst_ip = socket.gethostbyname(new_dst)
        for ip in iplist:
            rule = ['sudo', 'iptables', '-t', 'nat', '-A', 'OUTPUT',
                    '-m', 'cgroup', '!', '--cgroup', '1337',
                    '-p', 'tcp', '-d', ip, '-j', 'DNAT', '--to-destination', new_dst_ip]
            print('REWRITEDST', rule, flush=True)
            iptables_nat_add(rule)
        iptables_nat_commit()

    def verb_flushrewrite(self):
        print('FLUSHREWRITE', flush=True)
        iptables_nat_flush()

    def verb_sleep_ms(self, ms):
        print('SLEEP_MS', ms, flush=True)
        self.exit.wait(ms / 1000.0)

    def verb_println(self, text):
        print('PRINTLN', text, flush=True)

    def run(self):
        def _run_cleanup():
            self.verb_flushrewrite()
            self.verb_flushdrop()
            netem_del()
            self.verb_contall()

        config = self.script_yaml.get('config', {})
        loop = config.get('loop', False)
        while not self.exit.is_set():
            for step in self.script_yaml['steps']:
                if self.exit.is_set():
                    break

                assert(len(step.keys()) == 1)
                verb, args = list(step.items())[0]
                boundfn = getattr(self, 'verb_' + verb, None)
                assert(boundfn)
                if args is None:
                    boundfn()
                elif isinstance(args, Mapping):
                    boundfn(**args)
                else:
                    boundfn(args) #arg, really.

                if not loop:
                    _run_cleanup()
                    return
        _run_cleanup()

def start_playback(*filenames):
    threads = []
    for filename in filenames:
        with open(filename, 'r') as f:
            script_yaml = yaml.safe_load(f)
        thread = PlaybackThread(name='netem_playback_' + filename, daemon=True)
        thread.script_yaml = script_yaml
        thread.exit = threading.Event()
        print('Playback thread for %s starting.' % filename, flush=True)
        thread.start()
        threads.append(thread)
    return threads

if __name__ == "__main__":
    import sys, time
    threads = start_playback(*sys.argv[1:])
    while [t for t in threads if t.is_alive()]:
        time.sleep(1)
