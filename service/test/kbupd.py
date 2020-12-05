import os, subprocess, tempfile, time, re, signal, time

from util import DIM, CLEAR, create_cgroup

class Kbupd():
    processes = []
    frontends = []

    def __init__(self, port, subcommand, ca, *args, **kwargs):
        for bd in (os.getenv("BIN_DIR"), ".", "build/target/debug"):
            if bd == None: continue
            if os.path.isfile(os.path.join(bd, "kbupd")):
                self.kbupd_bin = os.path.join(bd, "kbupd")
                self.kbupctl_bin = os.path.join(bd, "kbupctl")
                self.kbupd_api_client_bin = os.path.join(bd, "kbupd_api_client")
                self.kbuptlsd_bin = os.path.join(bd, "kbuptlsd")
                break
        for bd in (os.getenv("CONFIG_DIR"), ".", "config"):
            if bd == None: continue
            if os.path.isfile(os.path.join(bd, "replica.client_test.yml")):
                self.config_dir = bd
                break
        if os.getenv("ENCLAVE_PATH") != None:
            self.enclave_lib = os.getenv("ENCLAVE_PATH")
        else:
            for ed in (os.getenv("ENCLAVE_DIR"), ".", "build", "build/target/debug"):
                if ed == None: continue
                if os.path.exists(os.path.join(ed, "libkbupd_enclave.hardened.debug.so")):
                    self.enclave_lib = os.path.join(ed, "libkbupd_enclave.hardened.debug.so")
                    break
                elif os.path.exists(os.path.join(ed, "libkbupd_enclave.debug.so")):
                    self.enclave_lib = os.path.join(ed, "libkbupd_enclave.debug.so")
                    break
        if not hasattr(self, "kbupd_bin"):
            raise Exception("Couldn't find kbupd binary, maybe set BIN_DIR?")
        if not hasattr(self, "enclave_lib"):
            raise Exception("Couldn't find enclave .so, maybe set ENCLAVE_DIR?")
        if not hasattr(self, "config_dir"):
            raise Exception("Couldn't find replica.client_test.yml, maybe set CONFIG_DIR?")

        append_log = kwargs.get("append_log", False)

        if kwargs.get("debug", True):
            debug_args = ["--debug"]
        else:
            debug_args = []

        self.control_port = port

        self.log_file = "kbupd-%s.log" % self.control_port

        self.peer_ca_path = ca.cert_path()
        self.peer_key_file = tempfile.NamedTemporaryFile(prefix="server-", suffix=".pem")
        self.peer_key_file.write(ca.generate_peer_certificate())
        self.peer_key_file.flush()

        if os.getenv("ENCLAVE_DEBUG") != None:
            #XXX Add SGX_DBG_OPTIN=1 to env here?  And warn if SGX_SDK_SOURCE_DIR isn't set?
            enclave_debug_args = ["--enclave-debug", os.getenv("ENCLAVE_DEBUG")]
        else:
            enclave_debug_args = []

        if os.getenv("PROFILE") != None:
            perf_args = ["env", "SGX_DBG_OPTIN=1",
                         "perf", "record", "-F", "9997", "-g",
                         "-o", "kbupd-%s-perf.data" % self.control_port]
        else:
            perf_args = []

        if os.getenv("IAS_TLS_CONFIG") != None:
            if os.getenv("IAS_SPID") == None:
                raise Exception("Must set IAS_SPID with IAS_TLS_CONFIG")
            ias_args = ["--ias-tls-config-file", os.getenv("IAS_TLS_CONFIG"),
                            "--ias-spid", os.getenv("IAS_SPID")]
        else:
            ias_args = []

        if subcommand == "replica":
            self.peer_port = port + 1
            config_file = kwargs.get("config_file")
            if config_file == None:
                config_file = "replica.client_test.yml"
            config_file_args = ["--config-dir", self.config_dir, "--config-file", config_file]
            peer_port_args = ["--listen-peers", "127.0.0.1:%s" % self.peer_port]
            exit_signals_args = ["--exit-signals"]
        else:
            self.api_port = port + 1
            config_file = kwargs.get("config_file")
            if config_file == None:
                config_file = "frontend.client_test.yml"
            config_file_args = ["--config-dir", self.config_dir, "--config-file", config_file]
            peer_port_args = ["--listen-api", "127.0.0.1:%s" % self.api_port]
            exit_signals_args = []

        self.net_cls_group = kwargs.get('net_cls_group', None)
        self.net_cls_id = kwargs.get('net_cls_id', None)
        if not self.net_cls_group:
            self.net_cls_group = 'kbupd-FE'
            self.net_cls_id = 1337
            create_cgroup(self.net_cls_group, self.net_cls_id)
        kbupd_args = ['cgexec', '-g', 'net_cls:%s' % self.net_cls_group,
                          self.kbupd_bin, "--enclave-directory", os.path.dirname(self.enclave_lib),
                          "--listen-control", "127.0.0.1:%s" % self.control_port,
                          "--kbuptlsd-bin-file", self.kbuptlsd_bin,
                          *debug_args,
                          *config_file_args,
                          *ias_args,
                          subcommand,
                          "--enclave", os.path.basename(self.enclave_lib)[:-3],
                          "--peer-key-file", self.peer_key_file.name,
                          "--peer-ca-file", self.peer_ca_path,
                          *enclave_debug_args,
                          *exit_signals_args,
                          *peer_port_args,
                          *args]
        print(' '.join(kbupd_args))
        with open(self.log_file, 'a' if append_log else 'w') as logfd:
            self.proc = subprocess.Popen(perf_args + kbupd_args,
                                             stdin=subprocess.DEVNULL,
                                             stdout=logfd,
                                             stderr=subprocess.STDOUT,
                                             env={"RUST_BACKTRACE": "1"},
                                             close_fds=True)
        Kbupd.processes.append(self.proc)
        if subcommand == "frontend":
            Kbupd.frontends.append(self)

        while not hasattr(self, "node_id"):
            self.refresh_info()
            time.sleep(0.1)

    def __str__(self):
        return str(self.node_id)

    def kill(self):
        metrics = self.kbupctl('metrics').stdout.decode()
        self.proc.terminate()
        self.proc.wait()
        with open(self.log_file, 'a') as logfd:
            logfd.write(metrics)
            logfd.write('\n')
        try:
            Kbupd.processes.remove(self.proc)
        except ValueError:
            pass
        try:
            Kbupd.frontends.remove(self)
        except ValueError:
            pass

    def sigstop(self):
        self.proc.send_signal(signal.SIGSTOP)

    def sigcont(self):
        self.proc.send_signal(signal.SIGCONT)

    @classmethod
    def kill_all(cls):
        for proc in cls.processes:
            print(DIM + "Killing process %s" % proc.pid + CLEAR)
            proc.kill()

    def refresh_info(self):
        info = self.kbupctl("info")
        info_err = info.stderr.decode()
        info_out = info.stdout.decode()
        if info_err.find("Connection refused") != -1 or info_err.find("Connection reset") != -1:
            time.sleep(0.1)
            if self.proc.poll() != None:
                raise Exception("kbupd-%s terminated: %s" % (self.control_port, self.proc.returncode))
            return
        for key_val in [l for l in info_out.split('\n') if len(l) > 0]:
            key, val = key_val.split('=')
            if not hasattr(self, key.lower()):
                print(DIM + key_val + CLEAR)
                setattr(self, key.lower(), val)

    def kbupctl(self, *args):
        return subprocess.run([self.kbupctl_bin,
                                   "--connect", "127.0.0.1:%s" % self.control_port, *args],
                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, close_fds=True)

    def kbupctl_async(self, *args):
        return subprocess.Popen([self.kbupctl_bin,
                                 "--connect", "127.0.0.1:%s" % self.control_port, *args],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, close_fds=True)

    def kbupd_api_client(self, *args):
        return subprocess.run([self.kbupd_api_client_bin,
                               "--connect", "http://127.0.0.1:%s" % self.api_port, *args],
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, close_fds=True)

    def grep_log(self, regex):
        with open(self.log_file, 'r') as logfd:
            return [ line[:-1] for line in logfd if re.search(regex, line) ]

    def reconnect_peer(self, peer_node_id, address=None):
        address_args = []
        if address != None:
            address_args = ["--peer-address", address]
        self.kbupctl("reconnect-peer", "--peer-node-id", peer_node_id, *address_args)

    def disconnect_peer(self, peer_node_id):
        self.kbupctl("disconnect-peer", "--peer-node-id", peer_node_id)

    def get_backup_count(self):
        level = 0
        is_leader = False
        for line in self.kbupctl("status").stdout.decode().split('\n'):
            if line.strip().startswith("partition: EnclaveReplicaPartitionStatus"):
                level = 1
            elif level >= 1 and line.endswith('{'):
                level += 1
            elif level >= 1 and line.endswith('},'):
                level -= 1
            elif level == 1 and "is_leader:" in line:
                is_leader = 'true' in line.strip().split(':')[1]
            elif level == 1 and "backup_count:" in line:
                backup_count = int(line.strip().split(':')[1][1:-1])

        if is_leader:
            return backup_count
        else:
            return None
