#!/usr/bin/env python3

import unittest
import multiprocessing
import logging
import btcp.server_socket
import btcp.client_socket
import queue
import contextlib
import threading
import select
import time
import queue
import sys
import os

DEFAULT_WINDOW = 10
DEFAULT_TIMEOUT = 100 # ms
DEFAULT_LOGLEVEL = 'WARNING'

logger = logging.getLogger(os.path.basename(__file__)) # we don't want __main__

class BasicTests(unittest.TestCase):
    def test_1_connect(self): 
        barrier = multiprocessing.Barrier(2)
        self.assertTrue(run_in_separate_processes((barrier,), 
                                                  BasicTests._1_connect_client, 
                                                  BasicTests._1_connect_server))
    @staticmethod
    def _1_connect_client(barrier):
        c = btcp.client_socket.BTCPClientSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        c.connect()
        barrier.wait()

    @staticmethod
    def _1_connect_server(barrier):
        s = btcp.server_socket.BTCPServerSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        s.accept()
        barrier.wait()

    def test_2_hello_world(self): 
        barrier = multiprocessing.Barrier(2)
        self.assertTrue(run_in_separate_processes((barrier,), 
                                                  BasicTests._2_hello_world_client, 
                                                  BasicTests._2_hello_world_server))
    @staticmethod
    def _2_hello_world_client(barrier):
        c = btcp.client_socket.BTCPClientSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        c.connect()
        c.send(b"Hello world!")
        barrier.wait()

    @staticmethod
    def _2_hello_world_server(barrier):
        s = btcp.server_socket.BTCPServerSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        s.accept()
        assert(s.recv() == b"Hello world!")
        barrier.wait()

    def test_3_also_close(self): 
        self.assertTrue(run_in_separate_processes((), 
                                                  BasicTests._3_also_close_client, 
                                                  BasicTests._3_also_close_server))
        # no barrier here -shutdown should make sure its final acks are sent

    @staticmethod
    def _3_also_close_client():
        c = btcp.client_socket.BTCPClientSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        c.connect()
        c.send(b"Hello world!")
        c.shutdown()

    @staticmethod
    def _3_also_close_server():
        s = btcp.server_socket.BTCPServerSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        s.accept()
        assert(s.recv() == b"Hello world!")
        s.close()

    def test_4_reconnect(self): 
        self.assertTrue(run_in_separate_processes((), 
                                                  BasicTests._4_reconnect_client, 
                                                  BasicTests._4_reconnect_server, timeout=10))
    @staticmethod
    def _4_reconnect_client():
        c = btcp.client_socket.BTCPClientSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        c.connect()
        c.send(b"Hello world!")
        c.shutdown()
        c.connect()
        c.send(b"Hello world, again!")
        c.shutdown()

    @staticmethod
    def _4_reconnect_server():
        s = btcp.server_socket.BTCPServerSocket(DEFAULT_WINDOW, DEFAULT_TIMEOUT)
        s.accept()
        assert(s.recv() == b"Hello world!")
        s.shutdown()
        s.accept()
        assert(s.recv() == b"Hello world, again!")
        s.shutdown()
    

def run_in_separate_processes(args, *targets, timeout=5):
    """ Run the given functions with args in separate processes and terminates them if they haven't finished within `timeout` seconds.  We use separate processes instead of threads, because threads cannot be aborted. Returns True if all the processes exited without exception or timeout. """

    # queue via which the processes signal their completion
    q = multiprocessing.Queue(len(targets))

    processes_left = len(targets)

    processes = list([ multiprocessing.Process(
        target=run_process, 
        args=(target, q, idx, logger.getEffectiveLevel())+args, 
        name=f"{repr(target.__name__)}"
    ) for (idx,target) in enumerate(targets)])

    for process in processes:
        process.start()

    deadline = time.time() + timeout

    while processes_left > 0:
        eta = deadline - time.time()
        if eta < 0:
            break # get didn't time out, but we ran out of time nonetheless
        logger.info(f"waiting for a process to finish for {eta:.3f} seconds")
        try:
            (idx, success) = q.get(True, eta)
        except queue.Empty:
            # timeout
            logger.error("""

        T I M E O U T

    Woops, it looks like your code hangs. 

    Check below whether the client, server, or both timed out.

""")
            for process in processes:
                if process.is_alive():
                    logger.error(f"Process {process.name} ({process.pid}) timed out")
            break

        process = processes[idx]
        process.join()
        processes_left -= 1
        if not success:
            logger.error(f"""

        C R A S H

    Woops, process {process.name} ({process.pid}) crashed.

    Check the traceback and error message above.

""")
            break
        logger.info(f"Process {process.name} ({process.pid}) completed gracefully")
    else:
        return True # while loop ended without break - all processes joined before deadline

    for process in processes:
        if process.is_alive():
            logger.warning(f"  terminating process {process.name} ({process.pid})...")
            process.terminate()
    for process in processes:
        if process.is_alive():
            logger.warning(f"  waiting for process {process.name} ({process.pid}) exitcode={process.exitcode} to join...")
            process.join()
            logger.warning(f"    process {process.name} ({process.pid}) exited with code {process.exitcode}")
        else:
            logger.warning(f"  process {process.name} ({process.pid}) has already exited wih code {process.exitcode}")
    return False

def run_process(func, queue, idx, loglevel, *args):
    configure_logger(loglevel) # logger configuration is not shared between processes
    success = False
    try:
        func(*args)
        success = True
    finally:
        queue.put_nowait((idx, success))

def configure_logger(loglevel):
    # must be run for each process separately
    logging.basicConfig(level=loglevel,
            format="%(asctime)s:%(name)s:%(levelname)s:%(message)s")

if __name__ == "__main__":
    # Parse command line arguments
    import argparse
    parser = argparse.ArgumentParser(description="bTCP unit tests")
    parser.add_argument("-l", "--loglevel",
                        choices=["DEBUG", "INFO", "WARNING",
                                 "ERROR", "CRITICAL"],
                        help="Log level "
                             "for the python built-in logging module. ",
                        default=DEFAULT_LOGLEVEL)
    args, extra = parser.parse_known_args()

    if args.loglevel == DEFAULT_LOGLEVEL:
        print(f"""NB:  Using default {DEFAULT_LOGLEVEL} loglevel; if you need more details, use:

  python3 {os.path.basename(__file__)} -l DEBUG

""")

    configure_logger(getattr(logging, args.loglevel.upper()))
    # Pass the extra arguments to unittest
    sys.argv[1:] = extra

    # Start test suite
    unittest.main()
