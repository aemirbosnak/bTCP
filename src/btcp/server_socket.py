from btcp.btcp_socket import BTCPSocket, BTCPStates, BTCPSignals
from btcp.lossy_layer import LossyLayer
from btcp.constants import *

import queue
import time
import logging
import random


logger = logging.getLogger(__name__)


class BTCPServerSocket(BTCPSocket):
    def __init__(self, window, timeout):
        """Constructor for the bTCP server socket. Allocates local resources
        and starts an instance of the Lossy Layer.
        """
        logger.debug("__init__() called.")
        super().__init__(window, timeout)
        self._lossy_layer = LossyLayer(self, SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT)

        self._state = BTCPStates.CLOSED

        self._ack = 0
        self._seq = 0

        self._max_retries = MAX_RETRIES
        self._retry_count = 0
        self._timeout = timeout
        self._timer = None

        self._recvbuf = queue.Queue(maxsize=1000)
        logger.info("Socket initialized with recvbuf size 1000")

    def _start_timer(self):
        logger.debug("Starting timer.")
        self._timer = time.monotonic_ns()

    def _timer_expired(self):
        curtime = time.monotonic_ns()
        if not self._timer:
            logger.debug("Timer not running.")
            return False
        elif curtime - self._timer > self._timeout * 1_000_000:
            logger.debug("Timer elapsed. Connection or transmission timed out.")
            self._timer = time.monotonic_ns()
            return True
        else:
            logger.debug("Timer not yet elapsed.")
            return False

    def lossy_layer_segment_received(self, segment):
        """Called by the lossy layer whenever a segment arrives."""
        logger.debug("lossy_layer_segment_received called")

        # Check for internet checksum

        # Unpack segment header
        seqnum, acknum, syn_set, ack_set, fin_set, window, length, checksum = self.unpack_segment_header(segment[:10])
        # Log the extracted values
        logger.debug(
            "Received segment: seqnum={}, acknum={}, syn_set={}, ack_set={}, fin_set={}, window={}, length={}, checksum={}"
            .format(seqnum, acknum, syn_set, ack_set, fin_set, window, length, checksum))

        if self._state == BTCPStates.CLOSED:
            logger.error("Connection is closed")
            pass

        elif self._state == BTCPStates.ACCEPTING:
            if syn_set:  # SYN segment
                logger.debug("SYN received with seq: {}, ack: {}".format(seqnum, acknum))
                self._syn_segment_received(seqnum)

        elif self._state == BTCPStates.SYN_RCVD:
            if ack_set:
                logger.info("Connection established")
                logger.debug("ACK received with seq: {}, ack: {}, connection established".format(seqnum, acknum))
                self._seq = acknum
                self._state = BTCPStates.ESTABLISHED

            elif syn_set:
                logger.info("Received duplicate SYN segment, resending SYN/ACK")
                synack_segment = self.build_segment_header(self._seq, seqnum + 1, syn_set=True, ack_set=True)
                self._lossy_layer.send_segment(synack_segment)

            elif time.time() - self._timer > self._timeout:
                if self._retry_count < self._max_retries:
                    logger.info("Timeout: Retrying SYN/ACK")
                    synack_segment = self.build_segment_header(self._seq, seqnum + 1, syn_set=True, ack_set=True)
                    self._lossy_layer.send_segment(synack_segment)
                    self._timer = time.time()
                    self._retry_count += 1
                else:
                    logger.error("Timeout and retries exceeded, back to ACCEPTING state")
                    self._state = BTCPStates.ACCEPTING

        elif self._state == BTCPStates.ESTABLISHED:
            if not syn_set and not ack_set and not fin_set:  # data segment
                self._data_segment_received(segment, seqnum)
            elif not syn_set and not ack_set and fin_set:  # FIN segment
                self._fin_segment_received(seqnum)

        elif self._state == BTCPStates.CLOSING:
            if ack_set:
                logger.debug("Final ACK received with seq: {}, ack: {}".format(seqnum, acknum))
                self.close()

        return

    def _syn_segment_received(self, seqnum):
        logger.debug("Received SYN segment")

        initial_seqnum = random.randint(0, 65535)
        self._seq = initial_seqnum
        logging.warning("Initial sequence number: {}".format(self._seq))

        # Send SYN/ACK
        synack_segment = self.build_segment_header(self._seq, seqnum + 1, syn_set=True, ack_set=True)
        self._lossy_layer.send_segment(synack_segment)
        self._state = BTCPStates.SYN_RCVD
        self._start_timer()
        logger.debug("SYN/ACK sent with seq: {} ack: {}".format(self._seq, seqnum + 1))

        while self._retry_count < self._max_retries:
            # Wait for ACK segment or timeout
            while not self._timer_expired():
                if self._state == BTCPStates.ESTABLISHED:
                    return  # ACK received and connection established
                time.sleep(0.1)

            logger.debug("Retrying with duplicate SYN/ACK segment")
            self._lossy_layer.send_segment(synack_segment)
            self._state = BTCPStates.SYN_RCVD
            logger.debug("Retry: {}".format(self._retry_count))

            self._retry_count += 1

        logger.error("Failed to receive ACK. Back to ACCEPTING state")
        self._state = BTCPStates.ACCEPTING

    def _fin_segment_received(self, seqnum):
        logger.debug("_fin_segment_received called")
        logger.info("Received data segment with sequence number: {}".format(seqnum))

        logger.debug("FIN received with seq: {}".format(seqnum))

        # Send FIN/ACK segment
        finack_segment = self.build_segment_header(self._seq, seqnum + 1, ack_set=True, fin_set=True)
        self._lossy_layer.send_segment(finack_segment)
        self._state = BTCPStates.CLOSING
        self._start_timer()
        logger.debug("FIN/ACK sent with seq: {} ack: {}".format(self._seq, seqnum + 1))

        while not self._timer_expired():
            logger.debug("Waiting for ACK")
            if self._state == BTCPStates.CLOSED:
                return  # Connection closed
            time.sleep(0.1)

        logger.error("Failed to receive ACK. Closing connection")
        self.close()

    def _data_segment_received(self, segment, seqnum):
        logger.debug("_data_segment_received called")
        logger.debug("Data received with seq: {}".format(seqnum))

        # Put the received data into the receive buffer
        try:
            data_start = HEADER_SIZE  # Assuming the header size is known
            data = segment[data_start:]
            logger.info("Data part of segment: {}".format(data))
            self._recvbuf.put(data, block=True, timeout=None)
        except queue.Full:
            logger.error("Receive buffer is full. Dropping data segment.")
            return

        # Send ACK segment
        self._ack = seqnum + 1
        ack_segment = self.build_segment_header(self._seq, self._ack, ack_set=True)
        self._lossy_layer.send_segment(ack_segment)
        logger.debug("ACK sent with seq: {}, ack: {}".format(self._seq, self._ack))

    def lossy_layer_tick(self):
        """Called by the lossy layer whenever no segment has arrived for
        TIMER_TICK milliseconds. Defaults to 100ms, can be set in constants.py.
        """
        logger.debug("lossy_layer_tick called")

    def accept(self):
        """Accept and perform the bTCP three-way handshake to establish a
        connection.
        """
        logger.debug("accept called")
        self._state = BTCPStates.ACCEPTING
        self._start_timer()

        while self._retry_count < self._max_retries:
            while not self._timer_expired():
                logger.debug("Waiting for connection")
                if self._state == BTCPStates.SYN_RCVD:
                    return True     # Connection established
                time.sleep(0.1)
            self._retry_count += 1

        logger.error("Failed to establish connection. Aborting connect.")
        self.close()
        return False

    def recv(self):
        """Return data that was received from the client to the application in
        a reliable way.
        """
        logger.debug("recv called")

        data = bytearray()
        logger.info("Retrieving data from receive queue")
        try:
            # Wait until one segment becomes available in the buffer, or
            # timeout signalling disconnect.
            logger.info("Blocking get for first chunk of data.")
            data.extend(self._recvbuf.get(block=True, timeout=5))
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
            logger.info("No data received for 5 seconds.")
            logger.info("Returning empty bytes to caller, signalling disconnect.")
        return bytes(data)

    def close(self):
        """Cleans up any internal state by at least destroying the instance of
        the lossy layer in use. Also called by the destructor of this socket.
        """
        logger.debug("close called")
        self._state = BTCPStates.CLOSED
        if self._lossy_layer is not None:
            self._lossy_layer.destroy()
        self._lossy_layer = None

    def __del__(self):
        """Destructor. Do not modify."""
        logger.debug("__del__ called")
        self.close()
