#!/usr/bin/env python3

import os, signal, atexit, random, time, threading, unittest

from util import eprint, gprint, backup_id_to_str, random_id
from kbupd import Kbupd
from partition import Partition
from peer_ca import PeerCa
from kbupdclient import KbupdClient
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

def send_valid_requests(test):
    client = test.client

    for backup_id in test.backup_ids:
        # test backup valid_from checking
        client.request(r"status=NotYetValid", "backup",
                           backup_id, test.backup_pin, test.backup_data, 2, valid_from=2**64-1)
        # test backup and restore
        client.request(r"status=Ok", "backup",
                           backup_id, test.backup_pin, test.backup_data, 2)
        result = client.request(r"status=Ok", "restore",
                                    backup_id, test.backup_pin)
        test.assertEqual(result.get("data"), test.backup_data)
        token = result["token"]
        # test pin mismatch
        client.request(r"status=PinMismatch", "restore",
                           backup_id, random_id(32), token=token)
        # test restore with token reuse
        client.request(r"status=TokenMismatch", "restore",
                           backup_id, test.backup_pin, token=token)
        # test restore with random token
        client.request(r"status=Missing", "restore",
                           backup_id, test.backup_pin, token=random_id(32))
        # test restore with creation_token reuse
        result = client.request(r"status=TokenMismatch", "restore",
                                    backup_id, test.backup_pin, token=token[:32] + random_id(16))
        token = result["token"]
        # test restore valid_from checking
        client.request(r"status=NotYetValid", "restore",
                           backup_id, test.backup_pin, token=token, valid_from=2**64-1)
        # test restore after above tries decrement
        result = client.request(r"status=Ok", "restore",
                                    backup_id, test.backup_pin, token=token)
        test.assertEqual(result.get("data"), test.backup_data)
        # test restore token mismatch
        client.request(r"status=TokenMismatch", "restore",
                           backup_id, test.backup_pin, token=token)
        # test deletion on tries=0
        client.request(r"status=Missing", "restore",
                           backup_id, random_id(32))
        # test deletion persistence
        client.request(r"status=Missing", "restore",
                           backup_id, test.backup_pin)
        client.request(r"", "delete", backup_id)

    # test with different backup data lengths
    for backup_data_length in range(BACKUP_DATA_LENGTH):
        backup_id = test.backup_ids[0]
        backup_data = test.backup_data[:backup_data_length * 2]
        # test backup and restore
        client.request(r"status=Ok", "backup",
                           backup_id, test.backup_pin, backup_data, 1)
        result = client.request(r"status=Ok", "restore",
                                    backup_id, test.backup_pin)
        test.assertEqual(result.get("data"), backup_data)
        client.request(r"", "delete", backup_id)

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

        cls.backup_ids = (backup_id_to_str(0),
                              backup_id_to_str(2**256-1),
                              backup_id_to_str((2**256-1)//2),
                              backup_id_to_str((2**256-1)//2+1),
                              backup_id_to_str(random.randint(0, 2**256-1)),
                              backup_id_to_str(random.randint(0, 2**256-1)),
                              backup_id_to_str(random.randint(0, 2**256-1)),
                              backup_id_to_str(random.randint(0, 2**256-1)),
                              backup_id_to_str(random.randint(0, 2**256-1)),
                              backup_id_to_str(random.randint(0, 2**256-1)),)
        cls.backup_data = random_id(BACKUP_DATA_LENGTH)
        cls.backup_pin = random_id(32)

        cls.client = KbupdClient(cls.frontend, cls.enclave_name,
                                     cls.partitions[0].service_id)

    @classmethod
    def tearDownClass(cls):
        for p in cls.partitions:
            p.kill()
        cls.frontend.kill()

        super().tearDownClass()

    def test_00_invalid_requests(self):
        client = self.client
        service_id = self.partitions[0].service_id

        bad_input = r"ControlErrorSignal"
        # test backup with empty backup ID
        client.request(bad_input, "backup",
                           "", self.backup_pin, self.backup_data, 1, token=random_id(32))
        # test backup with too-short backup ID
        client.request(bad_input, "backup",
                           random_id(31), self.backup_pin, self.backup_data, 1,
                           token=random_id(32))
        # test backup with too-long backup ID
        client.request(bad_input, "backup",
                           random_id(33), self.backup_pin, self.backup_data, 1,
                           token=random_id(32))
        for backup_id in self.backup_ids:
            # test backup with too-long data
            client.request(bad_input, "backup",
                               backup_id, self.backup_pin, random_id(BACKUP_DATA_LENGTH + 1), 1,
                               token=random_id(32))
            # test backup with empty pin
            client.request(bad_input, "backup",
                               backup_id, "", self.backup_data, 1,token=random_id(32))
            # test backup with too-long pin
            client.request(bad_input, "backup",
                               backup_id, random_id(33), self.backup_data, 1,
                               token=random_id(32))
            # test backup with empty Service ID
            client.request(bad_input, "backup",
                               backup_id, self.backup_pin, self.backup_data, 1,
                               service_id="", token=random_id(32))
            # test restore with empty Backup ID
            client.request(bad_input, "restore", "", self.backup_pin, token=random_id(32))
            # test restore with too-short Backup ID
            client.request(bad_input, "restore", random_id(31), self.backup_pin,
                               token=random_id(32))
            # test restore with too-long Backup ID
            client.request(bad_input, "restore", random_id(33), self.backup_pin,
                               token=random_id(32))
            # test restore with empty pin
            client.request(bad_input, "restore", backup_id, "", token=random_id(32))
            # test restore with too-long pin
            client.request(bad_input, "restore", backup_id, random_id(33),
                               token=random_id(32))
            # test restore with empty Service ID
            client.request(bad_input, "restore",
                               backup_id, self.backup_pin, service_id="",
                               token=random_id(32))
            # test restore with too-short Service ID
            client.request(bad_input, "backup",
                               backup_id, self.backup_pin, self.backup_data, 1,
                               service_id=service_id[:62],
                               token=random_id(32))
            # test restore with too-long Service ID
            client.request(bad_input, "backup",
                               backup_id, self.backup_pin, self.backup_data, 1,
                               service_id=service_id + "00",
                               token=random_id(32))
            # test backup with empty token
            client.request(bad_input, "backup",
                               backup_id, self.backup_pin, self.backup_data, 1,
                               token="")
            # test backup with too-long token
            client.request(bad_input, "backup",
                               backup_id, self.backup_pin, self.backup_data, 1,
                               token=random_id(33))
            # test restore with empty token
            client.request(bad_input, "restore", backup_id, self.backup_pin,
                               token="")
            # test restore with too-long token
            client.request(bad_input, "restore", backup_id, self.backup_pin,
                               token=random_id(33))
            # test restore with wrong Service ID
            client.request(r"request canceled by enclave", "backup",
                               backup_id, self.backup_pin, self.backup_data, 1,
                               service_id=random_id(32), token=random_id(32))

    def test_00_valid_requests(self):
        client = self.client

        for backup_id in self.backup_ids:
            client.request(r"status=Missing", "restore",
                               backup_id, self.backup_pin, token=random_id(32))

        send_valid_requests(self)

    def test_10_reconnect(self):
        client = self.client
        backup_id = backup_id_to_str(random.randint(0, 2**256-1))

        client.request(r"status=Ok", "backup",
                           backup_id, self.backup_pin, self.backup_data, 1)
        result = client.request(r"status=Ok", "restore",
                                    backup_id, self.backup_pin)
        self.assertEqual(result.get("data"), self.backup_data)

        for partition in self.partitions:
            for peer in partition.peers:
                for other_partition in self.partitions:
                    for other_peer in other_partition.peers:
                        peer.disconnect_peer(other_peer.node_id)
                        peer.reconnect_peer(other_peer.node_id, "127.0.0.1:%s" % other_peer.peer_port)

        result = client.request(r"status=Ok", "restore",
                                    backup_id, self.backup_pin)
        self.assertEqual(result.get("data"), self.backup_data)

    def test_20_partitioning_split(self):
        self.do_test_partitioning(False, False)
    def test_21_partitioning_move_update_specs(self):
        self.do_test_partitioning(True, True)
    def test_22_partitioning_move(self):
        self.do_test_partitioning(False, True)

    def do_test_partitioning(self, update_specs, move):
        client = self.client

        client.request(r"status=Ok", "backup", count=100)

        backup_ids = list(self.backup_ids)
        if not move:
            backup_ids.append(backup_id_to_str((2**256-1)//4))
            backup_ids.append(backup_id_to_str((2**256-1)//4+1))

        for backup_id in backup_ids:
            client.request(r"status=Ok", "backup",
                               backup_id, self.backup_pin, self.backup_data, 2)

        pre_partition_count = sum([ i.get_backup_count() for i in self.partitions ])
        self.assertIsNotNone(pre_partition_count)
        pre_partition_specs =  [ p.get_spec() for p in self.partitions ]

        if move:
            partition = self.partitions[len(self.partitions)-1].move_partition()
        else:
            partition = self.partitions[len(self.partitions)-1].split_partition()
        self.partitions.append(partition)
        gprint("Started service %s" % partition.service_id)
        gprint("Started 3rd partition %s" % partition.get_spec())
        gprint()

        partition_specs = pre_partition_specs + [partition.get_spec_no_range()]

        KbupdTestCase.frontend.kill()
        KbupdTestCase.frontend = Kbupd(1337, "frontend", self.ca,
                                    "--enclave-name", self.enclave_name,
                                    "--max-backup-data-length", str(BACKUP_DATA_LENGTH),
                                    "--partitions", ';'.join(partition_specs),
                                    append_log=True)
        gprint("Started frontend %s" % KbupdTestCase.frontend.node_id)
        gprint()

        partition.start_partition()

        self.partitions[len(self.partitions)-2].wait_partition_started_source()

        for backup_id in backup_ids:
            result = client.request(r"status=Ok", "restore",
                                        backup_id, self.backup_pin)
            self.assertEqual(result.get("data"), self.backup_data)

        self.partitions[len(self.partitions)-2].resume_partition()

        if update_specs:
            self.partitions[len(self.partitions)-2].wait_partition_source()
            partition.wait_partition_destination()
            partition.finish_partition()
            self.partitions[len(self.partitions)-2].finish_partition()
            self.assertEqual(pre_partition_count, sum([ i.get_backup_count() for i in self.partitions ]))
            if move:
                self.partitions[len(self.partitions)-2].kill()
                del(self.partitions[len(self.partitions)-2])

            KbupdTestCase.frontend.kill()
            KbupdTestCase.frontend = Kbupd(1337, "frontend", self.ca,
                                        "--enclave-name", self.enclave_name,
                                        "--max-backup-data-length", str(BACKUP_DATA_LENGTH),
                                        "--partitions", ';'.join([ p.get_spec() for p in self.partitions ]),
                                        append_log = True)
            gprint("Started frontend %s" % KbupdTestCase.frontend.node_id)
            gprint()

        for backup_id in backup_ids:
            result = client.request(r"status=Ok", "restore",
                                        backup_id, self.backup_pin)
            self.assertEqual(result.get("data"), self.backup_data)

            result = client.request(r"status=PinMismatch", "restore",
                                        backup_id, random_id(32))
            token = result["token"]

            client.request(r"status=Missing", "restore",
                               backup_id, random_id(32), token=token)
            client.request(r"status=Missing", "restore",
                               backup_id, self.backup_pin, token=token)

        if not update_specs:
            self.partitions[len(self.partitions)-2].wait_partition_source()
            partition.wait_partition_destination()
            partition.finish_partition()
            self.partitions[len(self.partitions)-2].finish_partition()
            #XXX These asserts blow up trying to add None in sum() if a partition has no leader.
            self.assertEqual(pre_partition_count - len(backup_ids),
                             sum([ i.get_backup_count() for i in self.partitions ]))
            if move:
                self.partitions[len(self.partitions)-2].kill()
                del(self.partitions[len(self.partitions)-2])
            KbupdTestCase.frontend.kill()
            KbupdTestCase.frontend = Kbupd(1337, "frontend", self.ca,
                                               "--enclave-name", self.enclave_name,
                                               "--max-backup-data-length", str(BACKUP_DATA_LENGTH),
                                               "--partitions", ';'.join([ p.get_spec() for p in self.partitions ]),
                                               append_log = True)
            gprint("Started frontend %s" % KbupdTestCase.frontend.node_id)
            gprint()

    def test_30_leader_change(self):
        client = self.client
        backup_ids = list(self.backup_ids)
        backup_ids.append(backup_id_to_str((2**256-1)//4))
        backup_ids.append(backup_id_to_str((2**256-1)//4+1))
        backup_ids.append(backup_id_to_str(random.randint(0, 2**256-1)))
        backup_ids.append(backup_id_to_str(random.randint(0, 2**256-1)))

        for backup_id in backup_ids:
            client.request(r"status=Ok", "backup",
                               backup_id, self.backup_pin, self.backup_data, 1)
            result = client.request(r"status=Ok", "restore",
                                        backup_id, self.backup_pin)
            self.assertEqual(result.get("data"), self.backup_data)

        for partition in self.partitions:
            while True:
                leader= partition.get_replicas()[0]
                if leader:
                    break
                time.sleep(1)
            leader.kill()

        for backup_id in backup_ids:
            result = client.request(r"status=Ok", "restore",
                                        backup_id, self.backup_pin)
            self.assertEqual(result.get("data"), self.backup_data)

class KbupdFullStorageTestCase(NetemTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls.enclave_name = "test"
        cls.partition = Partition(cls.ca,
                                      replicas = 3,
                                      config_file = "replica.benchmark.yml",
                                      debug = False,
                                      storage_size = 10)
        gprint("Started service %s" % cls.partition.service_id)
        gprint("Started partition %s" % cls.partition.get_spec())
        gprint()

        cls.frontend = Kbupd(1337, "frontend", cls.ca,
                                 "--enclave-name", cls.enclave_name,
                                 "--max-backup-data-length", str(BACKUP_DATA_LENGTH),
                                 "--partitions", cls.partition.get_spec())

        gprint("Started frontend %s" % cls.frontend.node_id)
        gprint()

        cls.client = KbupdClient(cls.frontend, cls.enclave_name, cls.partition.service_id)

        cls.backup_ids = (backup_id_to_str(0),
                              backup_id_to_str(2**256-1),
                              backup_id_to_str((2**256-1)//2),
                              backup_id_to_str((2**256-1)//2+1),
                              backup_id_to_str(random.randint(0, 2**256-1)),
                              backup_id_to_str(random.randint(0, 2**256-1)),
                              backup_id_to_str(random.randint(0, 2**256-1)),
                              backup_id_to_str(random.randint(0, 2**256-1)),
                              backup_id_to_str(random.randint(0, 2**256-1)),
                              backup_id_to_str(random.randint(0, 2**256-1)),)
        cls.backup_data = backup_id_to_str(random.randint(0, 2**256-1))
        cls.backup_pin  = random_id(32)

    @classmethod
    def tearDownClass(cls):
        cls.partition.kill()
        cls.frontend.kill()

        super().tearDownClass()

    def test_10_storage_size(self):
        client = self.client

        for iteration in range(0, 2):
            with self.subTest(iteration = iteration):
                send_valid_requests(self)
                for backup_id in self.backup_ids:
                    client.request(r"status=Ok", "backup",
                                       backup_id, self.backup_pin, self.backup_data)

        backup_ids_2 = []

        backup_id = backup_id_to_str(random.randint(0, 2**256-1))
        client.request(r"request canceled by enclave", "backup",
                           backup_id, self.backup_pin, self.backup_data)

        client.request(r"", "delete", self.backup_ids[0])

        client.request(r"status=Ok", "backup",
                           backup_id, self.backup_pin, self.backup_data)
        result = client.request(r"status=Ok", "restore",
                                    backup_id, self.backup_pin)
        self.assertEqual(result.get("data"), self.backup_data)
        backup_ids_2.append(backup_id)

        backup_id = backup_id_to_str(random.randint(0, 2**256-1))
        client.request(r"request canceled by enclave", "backup",
                           backup_id, self.backup_pin, self.backup_data)

        for backup_id in self.backup_ids:
            client.request(r"", "delete", backup_id)

        for iteration in range(0, 9):
            with self.subTest(iteration = iteration):
                backup_id = backup_id_to_str(random.randint(0, 2**256-1))
                client.request(r"status=Ok", "backup",
                                   backup_id, self.backup_pin, self.backup_data)
                backup_ids_2.append(backup_id)

        backup_id = backup_id_to_str(random.randint(0, 2**256-1))
        client.request(r"request canceled by enclave", "backup",
                           backup_id, self.backup_pin, self.backup_data)

        for backup_id in backup_ids_2:
            result = client.request(r"status=Ok", "restore",
                                        backup_id, self.backup_pin)
            self.assertEqual(result.get("data"), self.backup_data)

class KbupdBenchmarkTestCase(NetemTestCase):
    @classmethod
    def setUpClass(cls, num_replicas=3):
        super().setUpClass()

        cls.enclave_name = "test"
        cls.partition = Partition(cls.ca,
                                      replicas = num_replicas,
                                      config_file = "replica.benchmark.yml",
                                      debug = False)
        gprint("Started service %s" % cls.partition.service_id)
        gprint("Started partition %s" % cls.partition.get_spec())
        gprint()

        cls.frontends = []
        frontend_count = 1
        for port in range(1337, 1337 + 2 * frontend_count, 2):
            cls.frontends.append(cls.start_frontend(port))

        cls.client = KbupdClient(cls.frontends[0], cls.enclave_name, cls.partition.service_id)

        cls.backup_ids = (backup_id_to_str(0),
                              backup_id_to_str(2**256-1),
                              backup_id_to_str((2**256-1)//2),
                              backup_id_to_str((2**256-1)//2+1),
                              backup_id_to_str(random.randint(0, 2**256-1)),
                              backup_id_to_str(random.randint(0, 2**256-1)),
                              backup_id_to_str(random.randint(0, 2**256-1)),
                              backup_id_to_str(random.randint(0, 2**256-1)),
                              backup_id_to_str(random.randint(0, 2**256-1)),
                              backup_id_to_str(random.randint(0, 2**256-1)),)
        cls.backup_data = random_id(BACKUP_DATA_LENGTH)
        cls.backup_pin  = random_id(32)

        cls.request_count = 10000
        cls.backup_count  = 0

    @classmethod
    def start_frontend(cls, port):
        frontend = Kbupd(port, "frontend", cls.ca,
                         "--enclave-name", cls.enclave_name,
                         "--max-backup-data-length", str(BACKUP_DATA_LENGTH),
                         "--partitions", cls.partition.get_spec(),
                         config_file = "frontend.benchmark.yml",
                         debug = False)
        gprint("Started frontend %s" % frontend.node_id)
        gprint()
        return frontend

    @classmethod
    def tearDownClass(cls):
        cls.partition.kill()
        for frontend in cls.frontends:
            frontend.kill()

        super().tearDownClass()

    def _about_to_xfer(self):
        pass

    def test_00_benchmark(self, max_time=30):
        cls = self.__class__

        cmd = ["client", "--enclave-name", self.enclave_name, "backup", "--request-count", str(self.request_count)]
        backup_count = 0
        start_time   = time.time()
        elapsed_time = 0
        while elapsed_time < max_time:
            kbupctls = []
            for frontend in self.frontends:
                self.client.log.write("CMD: " + " ".join(cmd) + "\n")
                self.client.log.flush()
                kbupctls.append(frontend.kbupctl_async(*cmd))
            for kbupctl in kbupctls:
                kbupctl_res = kbupctl.wait()
                if kbupctl_res != 0:
                    eprint()
                    eprint("TEST '%s' FAILED, returned %d" % (" ".join(cmd), kbupctl_res))
                    raise Exception("Test failed")
            elapsed_time = time.time() - start_time
            backup_count += self.request_count * len(self.frontends)
            gprint("performed %7d backups in %6.03fs (%4d/s)" % (backup_count, elapsed_time, backup_count / elapsed_time))
        cls.backup_count += backup_count
        gprint()

    def test_10_partition_transfer(self, num_keys=10**6):
        cls = self.__class__

        for backup_id in self.backup_ids:
            self.client.request(r"status=Ok", "backup", backup_id, self.backup_pin, self.backup_data, 1)
            cls.backup_count += 1

        backup_count  = 0
        start_time    = time.time()
        elapsed_time  = 0
        request_count = 50000
        cmd = ["client", "--enclave-name", self.enclave_name, "create",
               "--request-count", str(request_count), "--max-parallel", "5000"]
        while backup_count < num_keys:
            kbupctls = []
            for frontend in self.frontends:
                self.client.log.write("CMD: " + " ".join(cmd) + "\n")
                self.client.log.flush()
                kbupctls.append(frontend.kbupctl_async(*cmd))
            for kbupctl in kbupctls:
                kbupctl_res = kbupctl.wait()
                if kbupctl_res != 0:
                    eprint()
                    eprint("TEST '%s' FAILED, returned %d" % (" ".join(cmd), kbupctl_res))
                    raise Exception("Test failed")
            elapsed_time = time.time() - start_time
            backup_count += request_count * len(self.frontends)
            gprint("created %7d backups in %6.03fs (%4d/s)" % (backup_count, elapsed_time, backup_count / elapsed_time))
        cls.backup_count += backup_count

        self.assertEqual(self.partition.get_backup_count(), cls.backup_count)

        for frontend in cls.frontends:
            frontend.kill()

        self.new_partition = self.partition.move_partition()

        gprint("Started service %s" % self.new_partition.service_id)
        gprint("Started 2nd partition %s" % self.new_partition.get_spec())
        gprint()

        self.new_partition.start_partition()
        self.partition.wait_partition_started_source()
        self.partition.resume_partition()
        self._about_to_xfer()
        start_time = time.time()

        self.partition.wait_partition_source()
        self.new_partition.wait_partition_destination()
        elapsed_time = time.time() - start_time

        gprint("transferred %d backups in %.03fs (%4d/s)" % (self.backup_count, elapsed_time, self.backup_count / elapsed_time))
        gprint()

        self.new_partition.finish_partition()
        self.partition.finish_partition()
        self.partition.kill()
        cls.partition = self.new_partition
        del(self.new_partition)

        new_frontends = []
        for frontend in cls.frontends:
            new_frontends.append(self.start_frontend(frontend.control_port))
        cls.frontends = new_frontends

        for backup_id in self.backup_ids:
            result = self.client.request(r"status=Ok", "restore", backup_id, self.backup_pin)
            self.assertEqual(result.get("data"), self.backup_data)

        self.assertEqual(self.partition.get_backup_count(), cls.backup_count)

class KbupdXferFailureTestCase(KbupdBenchmarkTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass(num_replicas=5)

    def _cause_havoc(self):
        cls = self.__class__

        time.sleep(5)

        start = time.monotonic()
        while True:
            leader, followers = self.new_partition.get_replicas()
            if leader:
                break
            time.sleep(1)

        #Kill leader
        self.new_partition.kill(leader)
        gprint("Killed dest partition leader", flush=True)

        now = time.monotonic()
        if now < start + 5:
            time.sleep(5 - (now - start))

        leader, followers = cls.partition.get_replicas()

        #Kill follower
        cls.partition.kill(followers[0])
        gprint("Killed source partition follower", flush=True)

        if now < start + 10:
            time.sleep(10 - (now - start))

        while not leader:
            leader, followers = cls.partition.get_replicas()
            time.sleep(1)

        #Kill leader
        cls.partition.kill(leader)
        gprint("Killed source partition leader", flush=True)

    def _about_to_xfer(self):
        leader, followers = self.new_partition.get_replicas()
        #Kill follower
        self.new_partition.kill(followers[0])
        gprint("Killed dest partition follower", flush=True)

        self.thread = threading.Thread(target=self._cause_havoc, name='havoc')
        self.thread.start()

    def test_00_benchmark(self):
        super().test_00_benchmark(max_time=15)

    def test_10_partition_transfer(self):
        super().test_10_partition_transfer(num_keys=3*10**5)
        assert(not self.thread.is_alive())
        self.thread.join()

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
