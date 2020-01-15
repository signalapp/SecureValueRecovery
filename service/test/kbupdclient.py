import atexit, re, time
from datetime import datetime

from util import eprint

NUM_RETRIES=90

def timestamp():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

class KbupdClient():
    log = None

    def __init__(self, frontend, enclave_name, service_id):
        self.frontend = frontend
        self.enclave_name = enclave_name
        self.service_id = service_id
        if not self.log:
            KbupdClient.log = open("client_test.log", 'w')
            atexit.register(KbupdClient.log.close)

    def request(self, regex, subcommand, backup_id = None, pin = None,
                    data = None, tries = None, service_id = None, token = None, valid_from = None,
                    count = None):
        if subcommand == "backup" or subcommand == "restore":
            if service_id == None:
                service_id = self.service_id

        for retry in range(0, NUM_RETRIES):
            cmd = ["client", "--enclave-name", self.enclave_name, subcommand]
            if backup_id != None:
                cmd.extend(["--backup-id", backup_id])
            if pin != None:
                cmd.extend(["--backup-pin", str(pin)])
            if data != None:
                cmd.extend(["--backup-data", data])
            if tries != None:
                cmd.extend(["--backup-tries", str(tries)])
            if service_id != None:
                cmd.extend(["--service-id", str(service_id)])
            if token != None:
                cmd.extend(["--request-token", token])
            if valid_from != None:
                cmd.extend(["--request-valid-from", str(valid_from)])
            if count != None:
                cmd.extend(["--request-count", str(count)])

            if retry == 0:
                self.log.write(timestamp() + " CMD: " + ' '.join(cmd) + '\n')

            kbupctl = self.frontend.kbupctl(*cmd)
            output = kbupctl.stdout.decode()
            stderr = kbupctl.stderr.decode()

            #Some errors are normal and expected, the client must retry.  XferInProgress
            # causes cancelled requests.  And TokenMismatches can happen as a result of
            # a leader election.
            if re.search(regex, output) or re.search(regex, stderr): #Success
                break
            elif (re.search(r'request canceled by enclave', stderr) and \
                  re.search(r'ControlErrorSignal', stderr)) or \
                  re.search(r'status=TokenMismatch', output): #Retry
                match = re.search(r"token=([0-9a-fA-F]*)", output)
                if match != None:
                    token = match.groups()[0]
                time.sleep(2)
            else: #Fail
                self.log.write("CMD FAILED\n")
                break

        self.log.write(timestamp() + " COMPLETED" +
                       ("" if retry == 0 else " retried: %s" % (retry,)) + "\n")
        self.log.write(stderr)
        self.log.flush()

        if re.search(regex, output) == None and re.search(regex, stderr) == None:
            eprint()
            eprint("TEST '%s' FAILED, expecting %s, got:" % (" ".join(cmd), regex))
            eprint(output)
            raise Exception("Test failed")

        return dict(re.findall(r'(\S+)=(\S*)', output))
