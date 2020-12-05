import atexit, re, time
from datetime import datetime

from util import eprint

def timestamp():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

class KbupdApiClient():
    log = None

    def __init__(self, frontend, enclave_name, service_id,
                 username, shared_auth_secret = "0000000000000000000000000000000000000000000000000000000000000000"):
        self.frontend = frontend
        self.enclave_name = enclave_name
        self.service_id = service_id
        self.username = username
        self.shared_auth_secret = shared_auth_secret

        if not self.log:
            KbupdApiClient.log = open("api_client_test.log", 'w')
            atexit.register(KbupdApiClient.log.close)

    def request(self, regex, subcommand, pin = None, service_id = None, valid_from = None):
        if subcommand in ("backup", "restore", "delete"):
            if service_id is None:
                service_id = self.service_id

        cmd = ["--username", self.username, "--token-secret", self.shared_auth_secret, subcommand]

        if subcommand != "delete_all":
            cmd.extend(["--enclave-name", self.enclave_name])

        if pin is not None:
            cmd.extend(["--backup-pin", str(pin)])
        if service_id is not None:
            cmd.extend(["--service-id", str(service_id)])
        if valid_from is not None:
            cmd.extend(["--valid-from", str(valid_from)])

        self.log.write(timestamp() + " CMD: " + ' '.join(cmd) + '\n')

        kbupd_api_client = self.frontend.kbupd_api_client(*cmd)
        output = kbupd_api_client.stdout.decode()
        stderr = kbupd_api_client.stderr.decode()

        self.log.write(timestamp() + " COMPLETED\n")
        self.log.write(stderr)
        self.log.flush()

        if regex is not None and re.search(regex, output) == None and re.search(regex, stderr) == None:
            eprint()
            eprint("TEST '%s' FAILED, expecting %s, got:" % (" ".join(cmd), regex))
            eprint(output)
            raise Exception("Test failed")

        return dict(re.findall(r'(\S+)=(\S*)', output))
