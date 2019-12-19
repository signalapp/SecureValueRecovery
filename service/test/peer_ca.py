import subprocess, tempfile

class PeerCa():
    def __init__(self):
        self.ca_key_file  = tempfile.NamedTemporaryFile(prefix="ca-", suffix=".key")
        self.ca_cert_file = tempfile.NamedTemporaryFile(prefix="ca-", suffix=".pem")
        self.prev_serial  = 0
        self.openssl("ecparam", "-name", "secp384r1", "-genkey", "-out", self.ca_key_file.name)
        self.openssl("req", "-new", "-x509", "-batch", "-subj", "/CN=kbupd_client_test_ca/",
                     "-key", self.ca_key_file.name,
                     "-out", self.ca_cert_file.name)

    def cert_path(self):
        return self.ca_cert_file.name

    def generate_peer_certificate(self):
        self.prev_serial += 1
        key  = self.openssl("ecparam", "-name", "secp384r1", "-genkey")
        req  = self.openssl("req", "-new", "-batch", "-key", "-", "-subj", "/CN=kbupd_client_test_peer_%s/" % (self.prev_serial), stdin=key)
        cert = self.openssl("x509", "-req",
                            "-CA", self.ca_cert_file.name,
                            "-CAkey", self.ca_key_file.name,
                            "-set_serial", str(self.prev_serial),
                            stdin=req)
        return self.openssl("pkcs12", "-export", "-chain", "-passout", "pass:",
                            "-CAfile", self.ca_cert_file.name,
                            stdin=key + cert)

    def openssl(self, *args, **kwargs):
        openssl = subprocess.Popen(["openssl", *args],
                                   stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,
                                   close_fds=True)
        stdout, stderr = openssl.communicate(kwargs.get("stdin"))
        if openssl.returncode != 0:
            raise Exception("openssl %s terminated: %s\n%s" % (args, openssl.returncode, stderr))
        return stdout
