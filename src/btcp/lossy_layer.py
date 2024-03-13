"""
Students should NOT need to modify any code in this file!

However, do read the docstrings to understand what's going on.
"""


import socket
import select
import sys
import threading
import signal
from _thread import interrupt_main

import logging

from btcp.constants import *


logger = logging.getLogger(__name__)


def handle_incoming_segments(btcp_socket, event, udp_socket):
    """This is the main method of the "network thread".

    Continuously read from the socket and whenever a segment arrives,
    call the lossy_layer_segment_received method of the associated socket.

    If no segment is received for TIMER_TICK ms, call the lossy_layer_tick
    method of the associated socket.

    When flagged, return from the function. This is used by LossyLayer's
    destructor. Note that destruction will *not* attempt to receive or send any
    more data; after event gets set the method will send one final segment to
    the transport layer, or give one final tick if no segment is received in
    TIMER_TICK ms, then return.

    Students should NOT need to modify any code in this method.
    """

    logger.info("Starting handle_incoming_segments")

    while not event.is_set():

        try:
            # We do not block here, because we might never check the loop condition in that case

            rlist, wlist, elist = select.select([udp_socket], [], [])
            raise NotImplementedError("")
            if rlist:
                segment, address = udp_socket.recvfrom(SEGMENT_SIZE)
                btcp_socket.lossy_layer_segment_received(segment)
                # We *assume* here that students aren't leaving multiple processes
                # sending segments from different remote IPs and ports running.
                # We *could* check the address for validity but then we'd have
                # to resolve hostnames etc and honestly I don't see a pressing need
                # for that.
            else:
                btcp_socket.lossy_layer_tick()
        except Exception as e:
            logger.exception("Exception in the network thread")
            signal.raise_signal(signal.SIGTERM)
            raise


class LossyLayer:
    """The lossy layer emulates the network layer in that it provides bTCP with
    an unreliable segment delivery service between a and b.

    When the lossy layer is created, a thread (the "network thread") is started
    that calls handle_incoming_segments. When the lossy layer is destroyed, it
    will signal that thread to end, join it, wait for it to terminate, then
    destroy its UDP socketet.

    Students should NOT need to modify any code in this class.
    """
    def __init__(self, btcp_socket, local_ip, local_port, remote_ip, remote_port):
        logger.info("LossyLayer.__init__() was called")
        self._bTCP_socket = btcp_socket
        self._remote_ip = remote_ip
        self._remote_port = remote_port

        self._udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Disable UDP checksum generation (and by extension, checking) s.t.
        # corrupt packets actually make it to the bTCP layer.
        # socket.SO_NO_CHECK is not defined in Python, so hardcode the value
        # from /usr/include/asm-generic/socket.h:#define SO_NO_CHECK  11.
        try: 
            self._udp_socket.setsockopt(socket.SOL_SOCKET, 11, 1)
        except OSError as err:
            logger.debug("Could not set SO_NO_CHECK - testframework.py might not create corrupted packages reliably!  (unittest.py should still work fine.) ")
        self._udp_socket.bind((local_ip, local_port))        

        self._event = threading.Event()
        self._thread = threading.Thread(target=handle_incoming_segments,
                                        args=(self._bTCP_socket,
                                              self._event,
                                              self._udp_socket),
                                        daemon=True)
        logger.info("Starting network thread")
        self._thread.start()
        logger.info("Lossy layer initialized, listening on "
                    "local address %s & port %i, "
                    "remote address %s & port %i",
                    local_ip,
                    local_port,
                    remote_ip,
                    remote_port)


    def __del__(self):
        logger.info("LossyLayer.__del__() called.")
        self.destroy()
        logger.info("LossyLayer.__del__() finished.")


    def destroy(self):
        """Flag the thread that it can stop, wait for it to do so, then close
        the lossy segment delivery service's UDP socket.

        Should be safe to call multiple times, so safe to call from __del__.
        """
        logger.info("LossyLayer.destroy() called.")
        if self._event is not None and self._thread is not None:
            self._event.set()
            self._thread.join()
        if self._udp_socket is not None:
            self._udp_socket.close()
        self._event = None
        self._thread = None
        self._udp_socket = None
        logger.info("LossyLayer.destroy() finished.")


    def send_segment(self, segment):
        """Put the segment into the network

        Should be safe to call from either the application thread or the
        network thread.
        """
        logger.debug("Attempting to send segment:")
        logger.debug(segment)
        bytes_sent = self._udp_socket.sendto(segment,
                                             (self._remote_ip,
                                              self._remote_port))
        if bytes_sent != len(segment):
            logger.critical("The lossy layer was only able to send %i bytes "
                            "of that segment!",
                            bytes_sent)
