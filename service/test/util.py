import random, sys, subprocess

cgroups = set()

DIM = '\033[2m'
RED = '\033[31m'
GREEN = '\033[32m'
CLEAR = '\033[0m'

def eprint(*args, **kwargs):
    print(RED, end='', file=sys.stderr)
    print(*args, file=sys.stderr, **kwargs)
    print(CLEAR, end='', file=sys.stderr, flush=True)
def gprint(*args, **kwargs):
    print(GREEN, end='')
    print(*args, **kwargs)
    print(CLEAR, end='', flush=True)

def backup_id_to_str(bid):
    return hex(bid)[2:].rjust(64, '0')
def str_to_backup_id(str):
    return int(str, base=16)
def random_id(num_bytes):
    return hex(random.randint(0, 2**512-1)).rjust(num_bytes*2, '0')[2:2+num_bytes*2]

def create_cgroup(group, classid):
    global cgroups
    if group in cgroups:
        return

    subprocess.run(['sudo', 'mkdir', '-p', '/sys/fs/cgroup/net_cls/%s' % group], check=True)
    subprocess.run('echo %s | sudo tee /sys/fs/cgroup/net_cls/%s/net_cls.classid' % (classid, group),
                   shell=True, check=True, stdout=subprocess.DEVNULL)
    subprocess.run(['sudo', 'cgcreate', '-t', 'signal:signal', '-a', 'signal:signal',
                    '-g', 'net_cls:%s' % group], check=True)
    cgroups.add(group)

def choices(seq, k):
    ret = set()
    while len(ret) < min(len(seq), k):
        ret.add(random.choice(seq))
    return ret

def get_ppid(pid):
    with open('/proc/%s/stat' % pid, 'r') as stat:
        line = stat.readline()
        return int(line.split()[3])

