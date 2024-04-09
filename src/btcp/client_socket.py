from btcp.btcp_socket import BTCPSocket, BTCPStates
from btcp.lossy_layer import LossyLayer
from btcp.constants import *

import queue
import logging
import time
import random

logger = logging.getLogger(__name__)


class BTCPClientSocket(BTCPSocket):
    """bTCP client socket"""

    def __init__(self, window, timeout):
        """Constructor for the bTCP client socket. Allocates local resources
        and starts an instance of the Lossy Layer.
        """
        logger.debug("__init__ called")
        super().__init__(window, timeout)
        self._lossy_layer = LossyLayer(self, CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT)

        self._state = BTCPStates.CLOSED

        # Initialize the seq and ack number
        self._next_seqnum = 0
        self._ack_received = 0

        self._max_retries = MAX_RETRIES
        self._retry_count = 0
        self._timeout = timeout

        # The data buffer used by send() to send data from the application
        # thread into the network thread. Bounded in size.
        self._sendbuf = queue.Queue(maxsize=1000)
        logger.info("Socket initialized with sendbuf size 1000")

    def lossy_layer_segment_received(self, segment):
        """Called by the lossy layer whenever a segment arrives."""
        logger.debug("lossy_layer_segment_received called")
        seqnum, acknum, syn_set, ack_set, fin_set, window, length, checksum = self.unpack_segment_header(segment[:10])

        # Log the extracted values
        logger.info("Received segment: seqnum={}, acknum={}, syn_set={}, ack_set={}, fin_set={}, window={}, length={}, checksum={}"
            .format(seqnum, acknum, syn_set, ack_set, fin_set, window, length, checksum))

        if self._state == BTCPStates.CLOSED:
            logger.error("Connection is closed")
            pass

        elif self._state == BTCPStates.SYN_SENT:
            if syn_set and ack_set:
                logger.debug("Received SYN/ACK segment")

                # Send ACK segment
                ack_segment = self.build_segment_header(acknum, seqnum + 1, ack_set=True)
                self._lossy_layer.send_segment(ack_segment)
                logger.debug("ACK sent with seq: {} ack: {}".format(acknum, seqnum + 1))

                self._next_seqnum = acknum
                self._state = BTCPStates.ESTABLISHED

        elif self._state == BTCPStates.ESTABLISHED:
            if ack_set:
                logger.debug("ACK received with seq: {} ack: {}".format(seqnum, acknum))
                self._ack_received = acknum

        elif self._state == BTCPStates.FIN_SENT:
            if ack_set and fin_set:
                logger.debug("FIN/ACK received with seq: {} ack: {}".format(seqnum, acknum))

                # Send ACK segment
                ack_segment = self.build_segment_header(acknum, seqnum + 1, ack_set=True)
                self._lossy_layer.send_segment(ack_segment)
                logger.debug("ACK sent with seq: {} ack: {}".format(acknum, seqnum + 1))

                self._state = BTCPStates.CLOSED
                self.close()

    def lossy_layer_tick(self):
        """Called by the lossy layer whenever no segment has arrived for
        TIMER_TICK milliseconds. Defaults to 100ms, can be set in constants.py."""
        logger.debug("lossy_layer_tick called")

        try:
            while True:
                logger.debug("Getting segment from buffer.")
                segment = self._sendbuf.get_nowait()
                logger.debug(segment)
                logger.debug("Sending segment with seq: {}".format(self._next_seqnum))
                self._lossy_layer.send_segment(segment)

        except queue.Empty:
            logger.info("No (more) data was available for sending right now.")

    def connect(self):
        """Perform the bTCP three-way handshake to establish a connection."""
        logger.debug("connect called")

        # Send SYN segment
        initial_seqnum = random.randint(0, 65535)
        logger.debug("Initial sequence number: {} ".format(initial_seqnum))
        syn_segment = self.build_segment_header(initial_seqnum, 0, syn_set=True)
        self._lossy_layer.send_segment(syn_segment)
        self._state = BTCPStates.SYN_SENT
        logger.debug("SYN sent with seq: {}".format(initial_seqnum))

        while self._retry_count < self._max_retries:
            # Wait for SYN/ACK
            start_time = time.time()
            while time.time() - start_time < self._timeout:
                logger.debug("Waiting for SYN/ACK")
                logger.warning(self._state)
                if self._state == BTCPStates.ESTABLISHED:
                    logger.debug("Connection established")
                    return True  # Connection established
                time.sleep(0.1)

            logger.debug("Retrying with duplicate SYN segment")
            self._lossy_layer.send_segment(syn_segment)
            self._state = BTCPStates.SYN_SENT
            logger.debug("Retry: {}".format(self._retry_count))

            self._retry_count += 1

        logger.error("Failed to establish connection. Aborting connect.")
        self.close()
        return False

    def send(self, data):
        """Send data originating from the application in a reliable way to the server."""
        logger.debug("send called")

        if self._state != BTCPStates.ESTABLISHED:
            logger.error("Cannot send data: connection not established.")
            return 0

        datalen = len(data)
        logger.debug("%i bytes passed to send", datalen)
        sent_bytes = 0
        logger.debug("Queueing data for transmission")
        try:
            while sent_bytes < datalen:
                logger.debug("Cumulative data queued: %i bytes", sent_bytes)
                chunk = data[sent_bytes:sent_bytes + PAYLOAD_SIZE]

                # Build the data segment
                logger.debug("Building segment from chunk")
                segment = self.build_segment_header(self._next_seqnum, 0, length=len(chunk)) + chunk
                logger.debug("Putting segment in send queue.")
                self._sendbuf.put_nowait(segment)
                sent_bytes += len(chunk)
                self._next_seqnum += 1

                # Wait for ack segment before sending the next segment
                while not self._ack_received == self._next_seqnum:
                    time.sleep(0.1)

        except queue.Full:
            logger.info("Send queue full.")
        logger.info("Managed to queue %i out of %i bytes for transmission",
                    sent_bytes,
                    datalen)
        return sent_bytes

    def shutdown(self):
        """Perform the bTCP three-way finish to shutdown the connection."""
        logger.debug("shutdown called")
        self._retry_count = 0

        while self._retry_count < self._max_retries:
            # Send FIN segment
            fin_segment = self.build_segment_header(self._next_seqnum, 0, fin_set=True)
            self._lossy_layer.send_segment(fin_segment)
            self._state = BTCPStates.FIN_SENT
            logger.debug("FIN sent with seq: {}".format(self._next_seqnum))

            # Wait for FIN/ACK segment or timeout
            start_time = time.time()
            while time.time() - start_time < self._timeout:
                if self._state == BTCPStates.CLOSED:
                    return  # Connection successfully closed
                time.sleep(0.1)

            self._retry_count += 1

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
