from btcp.btcp_socket import BTCPSocket, BTCPStates
from btcp.lossy_layer import LossyLayer
from btcp.constants import *

import queue
import logging
import time

logger = logging.getLogger(__name__)


class BTCPClientSocket(BTCPSocket):
    """bTCP client socket
    A client application makes use of the services provided by bTCP by calling
    connect, send, shutdown, and close.

    You're implementing the transport layer, exposing it to the application
    layer as a (variation on) socket API.

    To implement the transport layer, you also need to interface with the
    network (lossy) layer. This happens by both calling into it
    (LossyLayer.send_segment) and providing callbacks for it
    (BTCPClientSocket.lossy_layer_segment_received, lossy_layer_tick).

    Your implementation will operate in two threads, the network thread,
    where the lossy layer "lives" and where your callbacks will be called from,
    and the application thread, where the application calls connect, send, etc.
    This means you will need some thread-safe information passing between
    network thread and application thread.
    Writing a boolean or enum attribute in one thread and reading it in a loop
    in another thread should be sufficient to signal state changes.
    Lists, however, are not thread safe, so to pass data and segments around
    you probably want to use Queues, or a similar thread safe collection.
    """

    def __init__(self, window, timeout):
        """Constructor for the bTCP client socket. Allocates local resources
        and starts an instance of the Lossy Layer.

        You can extend this method if you need additional attributes to be
        initialized, but do *not* call connect from here.
        """
        logger.debug("__init__ called")
        super().__init__(window, timeout)
        self._lossy_layer = LossyLayer(self, CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT)

        self._state = BTCPStates.CLOSED

        # Initialize the seq and ack number
        self._next_seqnum = 0
        self._expected_ack = 0
        self._ack_received = False

        self._max_retries = MAX_RETRIES
        self._retry_count = 0
        self._timeout = timeout

        # The data buffer used by send() to send data from the application
        # thread into the network thread. Bounded in size.
        self._sendbuf = queue.Queue(maxsize=1000)
        logger.info("Socket initialized with sendbuf size 1000")

    ###########################################################################
    ### The following section is the interface between the transport layer  ###
    ### and the lossy (network) layer. When a segment arrives, the lossy    ###
    ### layer will call the lossy_layer_segment_received method "from the   ###
    ### network thread". In that method you should handle the checking of   ###
    ### the segment, and take other actions that should be taken upon its   ###
    ### arrival.                                                            ###
    ###                                                                     ###
    ### Of course you can implement this using any helper methods you want  ###
    ### to add.                                                             ###
    ###########################################################################

    def lossy_layer_segment_received(self, segment):
        """Called by the lossy layer whenever a segment arrives.

        Things you should expect to handle here (or in helper methods called
        from here):
            - checksum verification (and deciding what to do if it fails)
            - receiving syn/ack during handshake
            - receiving ack and registering the corresponding segment as being
              acknowledged
            - receiving fin/ack during termination
            - any other handling of the header received from the server

        Remember, we expect you to implement this *as a state machine!*
        You have quite a bit of freedom in how you do this, but we at least
        expect you to *keep track of the state the protocol is in*,
        *perform the appropriate state transitions based on events*, and
        *alter behaviour based on that state*.

        So when you receive the segment, do the processing that is common
        for all states (verifying the checksum, parsing it into header values
        and data...).
        Then check the protocol state, do appropriate state-based processing
        (e.g. a FIN is not an acceptable segment in ACCEPTING state, whereas a
        SYN is).
        Finally, do post-processing that is common to all states.

        You could e.g. implement the state-specific processing in a helper
        function per state, and simply call the appropriate helper function
        based on which state you are in.
        In that case, it will be very helpful to split your processing into
        smaller helper functions, that you can combine as needed into a larger
        function for each state.

        If you are on Python 3.10, feel free to use the match ... case
        statement.
        If you are on an earlier Python version, an if ... elif ...  elif
        construction can be used; just make sure to check the same variable in
        each elif.
        """
        logger.debug("lossy_layer_segment_received called")
        seqnum, acknum, syn_set, ack_set, fin_set, window, length, checksum = self.unpack_segment_header(segment[:10])

        # Log the extracted values
        logger.info("Received segment: seqnum={}, acknum={}, syn_set={}, ack_set={}, fin_set={}, window={}, length={}, checksum={}"
            .format(seqnum, acknum, syn_set, ack_set, fin_set, window, length, checksum))

        #if not BTCPSocket.verify_checksum(segment):
        #    logger.error("Checksum verification failed. Dropping segment")
        #    return

        if self._state == BTCPStates.CLOSED:
            logger.error("Connection is closed")
            pass

        elif self._state == BTCPStates.SYN_SENT:
            if syn_set and ack_set:
                logger.info("Received SYN/ACK segment")

                # Send ACK segment
                ack_segment = self.build_segment_header(acknum, seqnum+1, ack_set=True)
                self._lossy_layer.send_segment(ack_segment)
                self._state = BTCPStates.ESTABLISHED

        elif self._state == BTCPStates.ESTABLISHED:
            if ack_set and acknum == self._expected_ack:
                self._expected_ack += 1  # Update the expected acknowledgment number
                self._ack_received = True
            else:
                self._ack_received = False

        elif self._state == BTCPStates.FIN_SENT:
            if ack_set and fin_set:
                logger.info("Received FIN/ACK segment")
                self._state = BTCPStates.CLOSED
                self.close()

    def lossy_layer_tick(self):
        """Called by the lossy layer whenever no segment has arrived for
        TIMER_TICK milliseconds. Defaults to 100ms, can be set in constants.py.

        NOTE: Will NOT be called if segments are arriving; do not rely on
        simply counting calls to this method for an accurate timeout. If 10
        segments arrive, each 99 ms apart, this method will NOT be called for
        over a second!

        The primary use for this method is to be able to do things in the
        "network thread" even while no segments are arriving -- which would
        otherwise trigger a call to lossy_layer_segment_received.

        For example, checking for timeouts on acknowledgement of previously
        sent segments -- to trigger retransmission -- should work even if no
        segments are being received. Although you can't count these ticks
        themselves for the timeout, you can trigger the check from here.

        You will probably see some code duplication of code that doesn't handle
        the incoming segment among lossy_layer_segment_received and
        lossy_layer_tick. That kind of duplicated code would be a good
        candidate to put in a helper method which can be called from either
        lossy_layer_segment_received or lossy_layer_tick.
        """
        logger.debug("lossy_layer_tick called")

        # Actually send all chunks available for sending.
        # Relies on an eventual exception to break from the loop when no data
        # is available.
        # You should be checking whether there's space in the window as well,
        # and storing the segments for retransmission somewhere.
        try:
            while True:
                logger.debug("Getting chunk from buffer.")
                chunk = self._sendbuf.get_nowait()
                datalen = len(chunk)
                logger.debug("Got chunk with lenght %i:",
                             datalen)
                logger.debug(chunk)
                logger.debug("Building segment from chunk.")
                segment = self.build_segment_header(self._next_seqnum, 0, length=len(chunk)) + chunk
                logger.info("Sending segment.")
                self._lossy_layer.send_segment(segment)
        except queue.Empty:
            logger.info("No (more) data was available for sending right now.")

    ###########################################################################
    ### You're also building the socket API for the applications to use.    ###
    ### The following section is the interface between the application      ###
    ### layer and the transport layer. Applications call these methods to   ###
    ### connect, shutdown (disconnect), send data, etc. Conceptually, this  ###
    ### happens in "the application thread".                                ###
    ###                                                                     ###
    ### You *can*, from this application thread, send segments into the     ###
    ### lossy layer, i.e. you can call LossyLayer.send_segment(segment)     ###
    ### from these methods without ensuring that happens in the network     ###
    ### thread. However, if you do want to do this from the network thread, ###
    ### you should use the lossy_layer_tick() method above to ensure that   ###
    ### segments can be sent out even if no segments arrive to trigger the  ###
    ### call to lossy_layer_segment_received. When passing segments between ###
    ### the application thread and the network thread, remember to use a    ###
    ### Queue for its inherent thread safety.                               ###
    ###                                                                     ###
    ### Note that because this is the client socket, and our (initial)      ###
    ### implementation of bTCP is one-way reliable data transfer, there is  ###
    ### no recv() method available to the applications. You should still    ###
    ### be able to receive segments on the lossy layer, however, because    ###
    ### of acknowledgements and synchronization. You should implement that  ###
    ### above.                                                              ###
    ###########################################################################

    def connect(self):
        """Perform the bTCP three-way handshake to establish a connection."""
        logger.debug("connect called")

        while self._retry_count < self._max_retries:
            # Send SYN segment
            initial_seqnum = self._next_seqnum  # starting sequence number from 0
            syn_segment = self.build_segment_header(initial_seqnum, 0, syn_set=True)
            self._lossy_layer.send_segment(syn_segment)
            self._state = BTCPStates.SYN_SENT
            self._expected_ack = self._next_seqnum + 1
            logger.info("SYN sent")

            # Wait for SYN/ACK
            start_time = time.time()
            while time.time() - start_time < self._timeout:
                logger.debug("Waiting for SYN/ACK (State: {})".format(self._state))
                if self._state == BTCPStates.ESTABLISHED:
                    logger.debug("Connection established")
                    return  # Connection established
                time.sleep(0.1)

            self._retry_count += 1

        logger.error("Failed to establish connection. Aborting connect.")
        self.close()

    def send(self, data):
        """Send data originating from the application in a reliable way to the server."""
        logger.debug("send called")

        if self._state != BTCPStates.ESTABLISHED:
            logger.error("Cannot send data: connection not established.")
            return 0

        datalen = len(data)
        logger.debug("%i bytes passed to send", datalen)
        sent_bytes = 0
        logger.info("Queueing data for transmission")
        try:
            while sent_bytes < datalen:
                logger.debug("Cumulative data queued: %i bytes", sent_bytes)
                chunk = data[sent_bytes:sent_bytes+PAYLOAD_SIZE]
                logger.debug("Putting chunk in send queue.")
                self._sendbuf.put_nowait(chunk)
                sent_bytes += len(chunk)
                # Increment the sequence number for the next segment
                self._next_seqnum += 1

                # Wait for ack segment before sending the next segment
                while not self._ack_received:
                    logger.debug(self._ack_received)
                    time.sleep(0.1)

                # Reset ack
                self._ack_received = False

        except queue.Full:
            logger.info("Send queue full.")
        logger.info("Managed to queue %i out of %i bytes for transmission",
                    sent_bytes,
                    datalen)
        return sent_bytes

    def shutdown(self):
        """Perform the bTCP three-way finish to shutdown the connection.

        shutdown should *block* (i.e. not return) until the connection has been
        successfully terminated or the disconnect attempt is aborted. You will
        need some coordination between the application thread and the network
        thread for this, because the fin/ack from the server will be received
        in the network thread.

        Hint: assigning to a boolean or enum attribute in thread A and reading
        it in a loop in thread B (preferably with a short sleep to avoid
        wasting a lot of CPU time) ensures that thread B will wait until the
        boolean or enum has the expected value. We do not think you will need
        more advanced thread synchronization in this project.
        """
        logger.debug("shutdown called")
        self._retry_count = 0

        while self._retry_count < self._max_retries:
            # Send FIN segment
            fin_segment = self.build_segment_header(self._next_seqnum, 0, fin_set=True)
            self._lossy_layer.send_segment(fin_segment)
            self._state = BTCPStates.FIN_SENT

            # Wait for FIN/ACK segment or timeout
            start_time = time.time()
            while time.time() - start_time < self._timeout:
                if self._state == BTCPStates.CLOSED:
                    return  # Connection successfully closed
                time.sleep(0.1)

            self._retry_count += 1

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
