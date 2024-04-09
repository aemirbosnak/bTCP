from btcp.btcp_socket import BTCPSocket, BTCPStates, BTCPSignals
from btcp.lossy_layer import LossyLayer
from btcp.constants import *

import queue
import time
import random
import logging


logger = logging.getLogger(__name__)


class BTCPServerSocket(BTCPSocket):
    """bTCP server socket
    """

    def __init__(self, window, timeout):
        logger.debug("__init__() called.")
        super().__init__(window, timeout)
        self._lossy_layer = LossyLayer(self, SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT)

        self._ack = 0
        self._seq = 0
        self._state = BTCPStates.CLOSED

        self._recvbuf = queue.Queue(maxsize=1000)
        logger.info("Socket initialized with recvbuf size 1000")

        # Make sure the example timer exists from the start.
        self._timer = None

    def lossy_layer_segment_received(self, segment):
        """Called by the lossy layer whenever a segment arrives."""
        logger.debug("lossy_layer_segment_received called")

        # Check for internet checksum

        # Unpack segment header
        seqnum, acknum, syn_set, ack_set, fin_set, window, length, checksum = self.unpack_segment_header(segment[:10])
        # Log the extracted values
        logger.info(
            "Received segment: seqnum={}, acknum={}, syn_set={}, ack_set={}, fin_set={}, window={}, length={}, checksum={}"
            .format(seqnum, acknum, syn_set, ack_set, fin_set, window, length, checksum))

        if not syn_set and not ack_set and not fin_set:  # data segment
            self._data_segment_received(segment, seqnum)
        elif not syn_set and not ack_set and fin_set:   # FIN segment
            self._fin_segment_received(seqnum)

        return

    def _fin_segment_received(self, seqnum):
        logger.debug("_fin_segment_received called")
        logger.info("Received data segment with sequence number: {}".format(seqnum))

        logger.debug("FIN received with seq: {}".format(seqnum))

        # Send FIN/ACK segment
        finack_segment = self.build_segment_header(self._seq, seqnum + 1, ack_set=True, fin_set=True)
        self._lossy_layer.send_segment(finack_segment)
        logger.debug("FIN/ACK sent with seq: {} ack: {}".format(self._seq, seqnum + 1))

        self.close()

    def _data_segment_received(self, segment, seqnum):
        logger.debug("_data_segment_received called")
        logger.info("Received data segment with sequence number: {}".format(seqnum))

        # Put the received data into the receive buffer
        try:
            data_start = HEADER_SIZE  # Assuming the header size is known
            data = segment[data_start:]
            logger.info("Data part of segment: {}".format(data))
            self._recvbuf.put(data, block=True, timeout=None)
        except queue.Full:
            logger.error("Receive buffer is full. Dropping data segment.")
            return

        # Send ACK
        self._ack = seqnum + 1
        ack_segment = self.build_segment_header(self._seq, self._ack, ack_set=True)
        self._lossy_layer.send_segment(ack_segment)
        logger.debug("ACK sent with seq: {}, ack: {}".format(self._seq, self._ack))

    def lossy_layer_tick(self):
        """Called by the lossy layer whenever no segment has arrived for
        TIMER_TICK milliseconds. Defaults to 100ms, can be set in constants.py.
        """
        logger.debug("lossy_layer_tick called")

    def _start_timer(self):
        if not self._timer:
            logger.debug("Starting timer.")
            self._timer = time.monotonic_ns()
        else:
            logger.debug("Timer already running.")

    def _expire_timers(self):
        curtime = time.monotonic_ns()
        if not self._timer:
            logger.debug("Timer not running.")
        elif curtime - self._timer > self._timeout * 1_000_000:
            logger.debug("Timer elapsed. Connection or transmission timed out.")
            # Take appropriate action here, such as closing the connection or retransmitting data
            # self.close()  # For example, close the connection
            # Or trigger retransmission
        else:
            logger.debug("Timer not yet elapsed.")
            self._timer = time.monotonic_ns()

    def accept(self):
        """Accept and perform the bTCP three-way handshake to establish a
        connection."""
        logger.debug("accept called")
        self._state = BTCPStates.ESTABLISHED

    def recv(self):
        """Return data that was received from the client to the application in
        a reliable way."""
        logger.debug("recv called")

        data = bytearray()
        logger.info("Retrieving data from receive queue")
        try:
            # Wait until one segment becomes available in the buffer, or
            # timeout signalling disconnect.
            logger.info("Blocking get for first chunk of data.")
            data.extend(self._recvbuf.get(block=True, timeout=30))
            logger.debug("First chunk of data retrieved.")
            logger.debug("Looping over rest of queue.")
            while True:
                # Empty the rest of the buffer, until queue.Empty exception
                # exits the loop. If that happens, data contains received
                # segments so that will *not* signal disconnect.
                data.extend(self._recvbuf.get_nowait())
                logger.debug("Additional chunk of data retrieved.")
        except queue.Empty:
            logger.debug("Queue emptied or timeout reached")
            pass
        if not data:
            logger.info("No data received for 30 seconds.")
            logger.info("Returning empty bytes to caller, signalling disconnect.")
        return bytes(data)

    def close(self):
        """Cleans up any internal state by at least destroying the instance of
        the lossy layer in use. Also called by the destructor of this socket."""
        logger.debug("close called")
        if self._lossy_layer is not None:
            self._lossy_layer.destroy()
        self._lossy_layer = None

    def __del__(self):
        """Destructor. Do not modify."""
        logger.debug("__del__ called")
        self.close()
