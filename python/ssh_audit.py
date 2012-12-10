#!/usr/bin/python -O

"""
Script which audits for open SSH instances and tries to connect using default
credentials.
"""

# Author: Johno Crawford ( johno@hellface.com )
# Hacked on by: Ian Oswald ( ozzie@hellface.com )
# Date: 09 Oct 2012

import paramiko
import threading
import Queue
import sys
import os
import time

if len(sys.argv) < 3:
    sys.exit('Usage: %s <password> <path to host list>' % sys.argv[0])

if not os.path.exists(sys.argv[2]):
    sys.exit('Host list %s not found' % sys.argv[2])


SSH_USER  = 'root'
SSH_PASS  = sys.argv[1]
TIMEOUT   = 5000
THREADS   = 16
QUEUE     = Queue.Queue()

class ThreadAudit(threading.Thread):
    """Threaded SSH Audit"""
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.queue = queue

    def run(self):
        while True:
            host = self.queue.get()

            ssh = paramiko.SSHClient()
            ssh.load_system_host_keys()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                ssh.connect(host, username=SSH_USER,
                    password=SSH_PASS, timeout=TIMEOUT)
                print host + ' default login credentials have not been updated!'
            except paramiko.AuthenticationException:
                pass
            except:
                print host + ' SSH connection failed'

            transport = ssh.get_transport()
            if transport is not None:
                print host + ' running ' + transport.remote_version

            ssh.close()

            self.queue.task_done()

def main(_file):
    """Main entry point"""

    lines = open(_file)
    hosts = [line.rstrip() for line in lines if line]
    lines.close()

    for _ in range(THREADS):
        thread = ThreadAudit(QUEUE)
        thread.setDaemon(True)
        thread.start()

    for host in hosts:
        QUEUE.put(host)

    QUEUE.join()

START = time.time()
main(sys.argv[2])
print 'Audit complete in: %s' % (time.time() - START)
