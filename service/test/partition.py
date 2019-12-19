import time, re

from util import gprint, backup_id_to_str, str_to_backup_id, create_cgroup
from kbupd import Kbupd

NUM_RETRIES=90

class Partition():
    port = 31337
    partitions = []

    def __init__(self,
                 ca,
                 first_id         = backup_id_to_str(0),
                 last_id          = backup_id_to_str(2**256-1),
                 source_partition = None,
                 replicas         = 3,
                 config_file      = None,
                 debug            = True,
                 storage_size     = None):
        self.ca = ca
        self.first_id = first_id
        self.last_id = last_id
        self.config_file = config_file
        self.debug = debug
        self.peers = []

        source_nodes_cmd = []
        if source_partition:
            source_nodes_cmd.append("--firstid")
            source_nodes_cmd.append(first_id)
            source_nodes_cmd.append("--lastid")
            source_nodes_cmd.append(last_id)
            source_nodes_cmd.append("--source-nodes")
            source_nodes_cmd.append(source_partition.peer_addrs)

        storage_size_cmd = []
        if storage_size:
            storage_size_cmd.append("--storage-size")
            storage_size_cmd.append(str(storage_size))

        replica_ip_ports = ','.join([ "127.0.0.1:%s" % (Partition.port + 1 + replica_num * 2) for replica_num in range(replicas)])

        for num in range(replicas):
            net_cls_group = 'kbupd-%s' % num
            net_cls_id = (num * 2) + 31337
            create_cgroup(net_cls_group, net_cls_id)
            replica = Kbupd(Partition.port, "replica", self.ca,
                            "--replicas", replica_ip_ports,
                            config_file = config_file,
                            debug = debug,
                            net_cls_group = net_cls_group,
                            net_cls_id = net_cls_id,
                            *source_nodes_cmd,
                            *storage_size_cmd)
            gprint("Started replica %s: %s (%s)" % (num, replica.node_id, replica.enclave_lib))
            self.peers.append(replica)
            Partition.port += 2

        self.peers = sorted(self.peers, key=lambda peer: peer.node_id, reverse=True)
        self.peer_addrs = ','.join([ "127.0.0.1:%s" % (p.peer_port) for p in self.peers])

        #Destination replicas don't have a service ID yet.
        for peer in self.peers:
            while True:
                peer.refresh_info()
                if hasattr(peer, "group_id"):
                    if hasattr(self, "group_id"):
                        assert(self.group_id == peer.group_id)
                    else:
                        self.group_id = peer.group_id
                        self.service_id = getattr(peer, "service_id", "<no_service_id>")
                    break
                time.sleep(0.1)

        while len(self.grep_logs(r"raft.*=== became leader at")) <= 0:
            time.sleep(0.1)

        Partition.partitions.append(self)

    def get_spec(self):
        return "%s-%s=%s" % (self.first_id, self.last_id, self.peer_addrs)

    def get_spec_no_range(self):
        return "=%s" % (self.peer_addrs)

    def log_replica_statuses(self, header):
        if not hasattr(self, 'status_log'):
            self.status_log = open('stat-' + self.group_id[0:10] + '.log', 'w')
        self.status_log.write(header + ' at ' + time.asctime() + '\n')
        for peer in self.peers:
            status = peer.kbupctl('status')
            self.status_log.write(status.stdout.decode())
        self.status_log.flush()

    def split_partition(self):
        last_id = str_to_backup_id(self.last_id)
        first_id = str_to_backup_id(self.first_id)
        split = first_id + (last_id - first_id)//2
        new_partition = Partition(self.ca, self.first_id, backup_id_to_str(split), source_partition = self,
                                  replicas = len(self.peers),
                                  config_file = self.config_file,
                                  debug = self.debug)
        self.first_id = backup_id_to_str(split + 1)

        return new_partition

    def move_partition(self):
        return Partition(self.ca, self.first_id, self.last_id, source_partition = self,
                         replicas = len(self.peers),
                         config_file = self.config_file,
                         debug = self.debug)

    def partition_command(self, command):
        for retry in range(0, NUM_RETRIES):
            ok_peers = 0
            for peer in self.peers:
                proc = peer.kbupctl("xfer", command)
                if proc.stdout.decode().startswith('ok'):
                    ok_peers += 1
            if ok_peers > 0:
                return
            time.sleep(2)
        raise Exception("partition_command timed out!")

    def start_partition(self):
        self.log_replica_statuses('start_partition')
        self.partition_command("start")

    def resume_partition(self):
        self.partition_command("resume")

    def pause_partition(self):
        self.partition_command("pause")

    def wait_partition_started_source(self):
        while len(self.grep_logs(r"=== starting xfer")) < 1:
            time.sleep(0.1)
        #We wait for only 1 replica, not all, so there is an improbable race
        # where a replica will get a resume before a "starting xfer" and log
        # an error.  Just here to reduce log noise:
        time.sleep(0.2)

    #Wait for the partitioning to be done.
    def wait_partition_source(self):
        #XXX Doesn't handle more than 1 partitioning!  Count start/completed?
        while len(self.grep_logs(r"=== All transfers sent")) < 1:
            time.sleep(0.1)
        self.log_replica_statuses('wait_partition_source')
    def wait_partition_destination(self):
        while len(self.grep_logs(r"=== All transfer chunks applied")) < 1:
            time.sleep(0.1)
        self.log_replica_statuses('wait_partition_destination')

    def finish_partition(self):
        self.partition_command("finish")

    def grep_logs(self, regex):
        results = []
        for peer in self.peers:
            results.extend(peer.grep_log(regex))
        return results

    def get_replicas(self):
        #XXX Sould make the leader the peer with the most other peers (including itself)
        #    who think it is the leader, as long as that is more than quorum.
        leader, max_term = None, -1
        for peer in self.peers:
            status = peer.kbupctl("status").stdout.decode()
            m = re.search(r'is_leader: ([a-z]+),\n[ ]+current_term: ([0-9]+),', status)
            if m:
                is_leader, term = m.groups()
                if is_leader == 'true' and int(term) > max_term:
                    leader = peer
                    max_term = int(term)
        followers = set(self.peers)
        followers.discard(leader)
        return (leader, list(followers))

    def kill(self, peer=None):
        if peer:
            peer.kill()
            self.peers.remove(peer)
        else:
            while len(self.peers) > 0:
                self.peers.pop().kill()
        self.peer_addrs = ','.join([ "127.0.0.1:%s" % (p.peer_port) for p in self.peers])

    def get_backup_count(self):
        for peer in self.peers:
            count = peer.get_backup_count()
            if count is not None:
                return count
        return None
