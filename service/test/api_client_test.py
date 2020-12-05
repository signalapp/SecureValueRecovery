#!/usr/bin/env python3

import os, signal, atexit, random, unittest

from util import eprint, gprint, backup_id_to_str, random_id
from kbupd import Kbupd
from partition import Partition
from peer_ca import PeerCa
from kbupdapiclient import KbupdApiClient
from netem import start_playback

BACKUP_DATA_LENGTH = 48

class NetemTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls.ca = PeerCa()

        scripts = os.environ.get('SCRIPT', '').split(',')
        cls.scripts = scripts if scripts != [''] else []
        if len(cls.scripts) > 0:
            cls.netem_threads = start_playback(*cls.scripts)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, 'netem_threads'):
            for thread in cls.netem_threads:
                thread.exit.set()
                thread.join()
            cls.netem_threads = None

        super().tearDownClass()

class KbupdTestCase(NetemTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls.partitions = []
        cls.enclave_name = "test"

        partition = Partition(cls.ca)
        cls.partitions.append(partition)
        gprint("Started service %s" % partition.service_id)
        gprint("Started partition %s" % partition.get_spec())
        gprint()

        partition = partition.split_partition()
        partition.start_partition()
        cls.partitions.append(partition)
        gprint("Started service %s" % partition.service_id)
        gprint("Started 2nd partition %s" % partition.get_spec())
        gprint()
        cls.partitions[0].wait_partition_started_source()
        cls.partitions[0].resume_partition()
        cls.partitions[0].pause_partition()
        cls.partitions[0].resume_partition()
        cls.partitions[0].wait_partition_source()
        partition.wait_partition_destination()
        partition.finish_partition()
        cls.partitions[0].finish_partition()

        cls.frontend = Kbupd(1337, "frontend", cls.ca,
                             "--enclave-name", cls.enclave_name,
                             "--max-backup-data-length", str(BACKUP_DATA_LENGTH),
                             "--partitions", ';'.join([ p.get_spec() for p in cls.partitions ]))
        gprint("Started frontend %s" % cls.frontend.node_id)
        gprint()

        cls.backup_data = random_id(BACKUP_DATA_LENGTH)
        cls.backup_pin = random_id(32)

        cls.client = KbupdApiClient(cls.frontend, cls.enclave_name, cls.partitions[0].service_id, "test_%030x" % random.randrange(16**32))

    @classmethod
    def tearDownClass(cls):
        for p in cls.partitions:
            p.kill()
        cls.frontend.kill()

        super().tearDownClass()

    def test_00_valid_requests(self):
        client = self.client

        # Verify we're starting without stale data
        print(client.request(r"status=Missing", "restore", pin = self.backup_pin, valid_from = 0))

        client.request(r"status=Ok", "backup", pin = self.backup_pin, valid_from = 0)
        client.request(r"status=Ok", "restore", pin = self.backup_pin, valid_from = 0)
        client.request(None, "delete")
        client.request(r"status=Missing", "restore", pin = self.backup_pin, valid_from = 0)

        client.request(r"status=Ok", "backup", pin = self.backup_pin, valid_from = 0)
        client.request(r"status=Ok", "restore", pin = self.backup_pin, valid_from = 0)
        client.request(None, "delete_all")
        client.request(r"status=Missing", "restore", pin = self.backup_pin, valid_from = 0)

def kill_all(*args):
    Kbupd.kill_all()
    raise(Exception("SIGTERM"))

def cleanup():
    if len(Kbupd.processes) > 0:
        Kbupd.kill_all()

if __name__ == "__main__":
    signal.signal(signal.SIGTERM, kill_all)
    atexit.register(cleanup)
    unittest.installHandler()
    unittest.main(failfast=True)
