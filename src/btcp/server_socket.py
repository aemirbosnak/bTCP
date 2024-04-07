from btcp.btcp_socket import BTCPSocket, BTCPStates, BTCPSignals
from btcp.lossy_layer import LossyLayer
from btcp.constants import *

import queue
import time
import logging


logger = logging.getLogger(__name__)


class BTCPServerSocket(BTCPSocket):
    def __init__(self, window, timeout):
        """Constructor for the bTCP server socket. Allocates local resources
        and starts an instance of the Lossy Layer.

        You can extend this method if you need additional attributes to be
        initialized, but do *not* call accept from here.
        """
        logger.debug("__init__() called.")
        super().__init__(window, timeout)
        self._lossy_layer = LossyLayer(self, SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT)

        self._next_seqnum = 0
        self._state = BTCPStates.CLOSED

        self._max_retries = MAX_RETRIES
        self._retry_count = 0
        self._timeout = timeout
        self._timer = None

        # The data buffer used by lossy_layer_segment_received to move data
        # from the network thread into the application thread. Bounded in size.
        # If data overflows the buffer it will get lost -- that's what window
        # size negotiation should solve.
        # For this rudimentary implementation, we simply hope receive manages
        # to be faster than send.
        self._recvbuf = queue.Queue(maxsize=1000)
        logger.info("Socket initialized with recvbuf size 1000")

        # Make sure the example timer exists from the start.
        self._example_timer = None

    ###########################################################################
    ### The following section is the interface between the transport layer  ###
    ### and the lossy (network) layer. When a segment arrives, the lossy    ###
    ### layer will call the lossy_layer_segment_received method "from the   ###
    ### network thread". In that method you should handle the checking of   ###
    ### the segment, and take other actions that should be taken upon its   ###
    ### arrival, like acknowledging the segment and making the data         ###
    ### available for the application thread that calls to recv can return  ###
    ### the data.                                                           ###
    ###                                                                     ###
    ### Of course you can implement this using any helper methods you want  ###
    ### to add.                                                             ###
    ###                                                                     ###
    ### Since the implementation is inherently multi-threaded, you should   ###
    ### use a Queue, not a List, to transfer the data to the application    ###
    ### layer thread: Queues are inherently threadsafe, Lists are not.      ###
    ###########################################################################

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

        if self._state == BTCPStates.CLOSED:
            logger.error("Connection is closed")
            pass

        elif self._state == BTCPStates.ACCEPTING:
            if syn_set:  # SYN segment
                self._syn_segment_received(segment, seqnum)

        elif self._state == BTCPStates.SYN_RCVD:
            if ack_set:
                logger.info("Connection established")
                self._state = BTCPStates.ESTABLISHED

            elif syn_set:
                logger.info("Received duplicate SYN segment, resending SYN/ACK")
                synack_segment = self.build_segment_header(self._next_seqnum, seqnum + 1, syn_set=True, ack_set=True)
                self._lossy_layer.send_segment(synack_segment)

            elif time.time() - self._timer > self._timeout:
                if self._retry_count < self._max_retries:
                    logger.info("Timeout: Retrying SYN/ACK")
                    synack_segment = self.build_segment_header(self._next_seqnum, seqnum + 1, syn_set=True, ack_set=True)
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

        return

    def _syn_segment_received(self, segment, seqnum):
        logger.info("Received SYN segment")

        # Send SYN/ACK
        synack_segment = self.build_segment_header(self._next_seqnum, seqnum + 1, syn_set=True, ack_set=True)
        self._lossy_layer.send_segment(synack_segment)
        self._state = BTCPStates.SYN_RCVD
        self._timer = time.time()

    def _fin_segment_received(self, seqnum):
        logger.debug("_fin_segment_received called")
        logger.info("Received data segment with sequence number: {}".format(seqnum))

        # Send FIN/ACK segment
        finack_segment = self.build_segment_header(seqnum, self._next_seqnum, ack_set=True, fin_set=True)
        self._lossy_layer.send_segment(finack_segment)

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

        # Send acknowledgment for the received data segment
        ack_segment = self.build_segment_header(seqnum, self._next_seqnum, ack_set=True)
        self._lossy_layer.send_segment(ack_segment)
        logger.info("Sent acknowledgment for sequence number: {}".format(seqnum))

        # Update the expected sequence number
        self._next_seqnum += 1

    def lossy_layer_tick(self):
        """Called by the lossy layer whenever no segment has arrived for
        TIMER_TICK milliseconds. Defaults to 100ms, can be set in constants.py.

        NOTE: Will NOT be called if segments are arriving; do not rely on
        simply counting calls to this method for an accurate timeout. If 10
        segments arrive, each 99 ms apart, this method will NOT be called for
        over a second!

        The primary use for this method is to be able to do things in the
        "network thread" even while no segments are arriving -- which would
        otherwise trigger a call to lossy_layer_segment_received. On the server
        side, you may find you have no actual need for this method. Or maybe
        you do. See if it suits your implementation.

        You will probably see some code duplication of code that doesn't handle
        the incoming segment among lossy_layer_segment_received and
        lossy_layer_tick. That kind of duplicated code would be a good
        candidate to put in a helper method which can be called from either
        lossy_layer_segment_received or lossy_layer_tick.
        """
        logger.debug("lossy_layer_tick called")
        self._expire_timers()

    # The following two functions show you how you could implement a (fairly
    # inaccurate) but easy-to-use timer.
    # You *do* have to call _expire_timers() from *both* lossy_layer_tick
    # and lossy_layer_segment_received, for reasons explained in
    # lossy_layer_tick.
    def _start_timer(self):
        if not self._example_timer:
            logger.debug("Starting timer.")
            self._example_timer = time.monotonic_ns()
        else:
            logger.debug("Timer already running.")

    def _expire_timers(self):
        curtime = time.monotonic_ns()
        if not self._example_timer:
            logger.debug("Timer not running.")
        elif curtime - self._example_timer > self._timeout * 1_000_000:
            logger.debug("Timer elapsed. Connection or transmission timed out.")
            # Take appropriate action here, such as closing the connection or retransmitting data
            # self.close()  # For example, close the connection
            # Or trigger retransmission
        else:
            logger.debug("Timer not yet elapsed.")
            self._example_timer = time.monotonic_ns()

    ###########################################################################
    ### You're also building the socket API for the applications to use.    ###
    ### The following section is the interface between the application      ###
    ### layer and the transport layer. Applications call these methods to   ###
    ### accept connections, receive data, etc. Conceptually, this happens   ###
    ### in "the application thread".                                        ###
    ###                                                                     ###
    ### You *can*, from this application thread, send segments into the     ###
    ### lossy layer, i.e. you can call LossyLayer.send_segment(segment)     ###
    ### from these methods without ensuring that happens in the network     ###
    ### thread. However, if you do want to do this from the network thread, ###
    ### you should use the lossy_layer_tick() method above to ensure that   ###
    ### segments can be sent out even if no segments arrive to trigger the  ###
    ### call to lossy_layer_segment_received. When passing segments between ###
    ### the application thread and the network thread, remember to use a    ###
    ### Queue for its inherent thread safety. Whether you need to send      ###
    ### segments from the application thread into the lossy layer is up to  ###
    ### you; you may find you can handle all receiving *and* sending of     ###
    ### segments in the lossy_layer_segment_received and lossy_layer_tick   ###
    ### methods.                                                            ###
    ###                                                                     ###
    ### Note that because this is the server socket, and our (initial)      ###
    ### implementation of bTCP is one-way reliable data transfer, there is  ###
    ### no send() method available to the applications. You should still    ###
    ### be able to send segments on the lossy layer, however, because       ###
    ### of acknowledgements and synchronization. You should implement that  ###
    ### above.                                                              ###
    ###########################################################################

    def accept(self):
        """Accept and perform the bTCP three-way handshake to establish a
        connection.

        accept should *block* (i.e. not return) until a connection has been
        successfully established (or some timeout is reached, if you want. Feel
        free to add a timeout to the arguments). You will need some
        coordination between the application thread and the network thread for
        this, because the syn and final ack from the client will be received in
        the network thread.

        Hint: assigning to a boolean or enum attribute in thread A and reading
        it in a loop in thread B (preferably with a short sleep to avoid
        wasting a lot of CPU time) ensures that thread B will wait until the
        boolean or enum has the expected value. You can also put some kind of
        "signal" (e.g. BTCPSignals.CONNECT, or BTCPStates.FIN_SENT) in a Queue,
        and use a blocking get() on the other side to receive that signal.

        We do not think you will need more advanced thread synchronization in
        this project.
        """
        logger.debug("accept called")
        self._state = BTCPStates.ACCEPTING
        self._start_timer()

    def recv(self):
        """Return data that was received from the client to the application in
        a reliable way.

        If no data is available to return to the application, this method
        should block waiting for more data to arrive. If the connection has
        been terminated, this method should return with no data (e.g. an empty
        bytes b'').

        If you want, you can add an argument to this method stating how many
        bytes you want to receive in one go at the most (but this is not
        required for this project).

        You are free to implement this however you like, but the following
        explanation may help to understand how sockets *usually* behave and you
        may choose to follow this concept as well:

        The way this usually works is that "recv" operates on a "receive
        buffer". Once data has been successfully received and acknowledged by
        the transport layer, it is put "in the receive buffer". A call to recv
        will simply return data already in the receive buffer to the
        application.  If no data is available at all, the method will block
        until at least *some* data can be returned.
        The actual receiving of the data, i.e. reading the segments, sending
        acknowledgements for them, reordering them, etc., happens *outside* of
        the recv method (e.g. in the network thread).
        Because of this blocking behaviour, an *empty* result from recv signals
        that the connection has been terminated.

        Again, you should feel free to deviate from how this usually works.
        """
        logger.debug("recv called")

        # Simply return whatever data is available in the receive buffer
        # If no data is available, this method should block until data arrives

        # Rudimentary example implementation:
        # Empty the queue in a loop, reading into a larger bytearray object.
        # Once empty, return the data as bytes.
        # If no data is received for 30 seconds, a disconnect is assumed.
        # At that point recv returns no data and thereby signals disconnect
        # to the server application.
        # Proper handling should use the bTCP state machine to check that the
        # client has disconnected when a timeout happens, and keep blocking
        # until data has actually been received if it's still possible for
        # data to appear.
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
        the lossy layer in use. Also called by the destructor of this socket.

        Do not confuse with shutdown, which disconnects the connection.
        close destroys *local* resources, and should only be called *after*
        shutdown.

        Probably does not need to be modified, but if you do, be careful to
        gate all calls to destroy resources with checks that destruction is
        valid at this point -- this method will also be called by the
        destructor itself. The easiest way of doing this is shown by the
        existing code:
            1. check whether the reference to the resource is not None.
                2. if so, destroy the resource.
            3. set the reference to None.
        """
        logger.debug("close called")
        if self._lossy_layer is not None:
            self._lossy_layer.destroy()
        self._lossy_layer = None

    def __del__(self):
        """Destructor. Do not modify."""
        logger.debug("__del__ called")
        self.close()
