import struct
import logging
from enum import IntEnum


logger = logging.getLogger(__name__)


class BTCPStates(IntEnum):
    """Enum class that helps you implement the bTCP state machine.

    Don't use the integer values of this enum directly. Always refer to them as
    BTCPStates.CLOSED etc.

    These states are NOT exhaustive! We left out at least one state that you
    will need to implement the bTCP state machine correctly. The intention of
    this enum is to give you some idea for states and how simple the
    transitions between them are.

    Feel free to implement your state machine in a different way, without
    using such an enum.
    """
    CLOSED      = 0
    ACCEPTING   = 1
    SYN_SENT    = 2
    SYN_RCVD    = 3
    ESTABLISHED = 4 # There's an obvious state that goes here. Give it a name.
    FIN_SENT    = 5
    CLOSING     = 6
    __          = 7 # If you need more states, extend the Enum like this.


class BTCPSignals(IntEnum):
    """Enum class that you can use to signal from the Application thread
    to the Network thread.

    For example, rather than explicitly change state in the Application thread,
    you could put one of these in a variable that the network thread reads the
    next time it ticks, and handles the state change in the network thread.
    """
    ACCEPT = 1
    CONNECT = 2
    SHUTDOWN = 3


class BTCPSocket:
    """Base class for bTCP client and server sockets. Contains static helper
    methods that will definitely be useful for both sending and receiving side.
    """
    def __init__(self, window, timeout):
        logger.debug("__init__ called")
        self._window = window
        self._timeout = timeout
        self._state = BTCPStates.CLOSED
        logger.debug("Socket initialized with window %i and timeout %i",
                     self._window, self._timeout)

    @staticmethod
    def carry_add(a, b):
        overflow = (a + b) >> 16

        return (((a + b) << 16) >> 16) + overflow

    @staticmethod
    def in_cksum(segment):
        """Compute the internet checksum of the segment given as argument.
        Consult lecture 3 for details.

        Our bTCP implementation always has an even number of bytes in a segment.

        Remember that, when computing the checksum value before *sending* the
        segment, the checksum field in the header should be set to 0x0000, and
        then the resulting checksum should be put in its place.
        """
        logger.debug("in_cksum() called")

        pseudo_header = segment[:8] + b'\x00\x00' + segment[10:]

        # makes sure the pseudo header can be split into 16 bit words
        if len(pseudo_header) % 2 == 1:
            pseudo_header += b'\x00'

        num_words = len(pseudo_header) / 2

        words = struct.unpack(f"!{num_words}H", pseudo_header)

        current_sum = 0

        for word in words:
            current_sum = self.carry_add(current_sum, word)

        return ~current_sum

    @staticmethod
    def verify_checksum(segment):
        """Verify that the checksum indicates is an uncorrupted segment.

        Mind that you change *what* signals that to the correct value(s).
        """
        logger.debug("verify_cksum() called")
        raise NotImplementedError("No implementation of in_cksum present. Read the comments & code of btcp_socket.py.")
        return BTCPSocket.in_cksum(segment) == 0xABCD


    @staticmethod
    def build_segment_header(seqnum, acknum,
                             syn_set=False, ack_set=False, fin_set=False,
                             window=0x01, length=0, checksum=0):
        """Pack the method arguments into a valid bTCP header using struct.pack"""

        logger.debug("build_segment_header() called")
        flag_byte = syn_set << 2 | ack_set << 1 | fin_set
        logger.debug("build_segment_header() done")
        return struct.pack("!HHBBHH", seqnum, acknum, flag_byte, window, length, checksum)


    @staticmethod
    def unpack_segment_header(header):
        """Unpack the individual bTCP header field values from the header."""

        logger.debug("unpack_segment_header() called")

        seqnum, acknum, flags, window, data_length, checksum = struct.unpack("!HHBBHH", header)

        fin_set = bool(flags & 1)
        ack_set = bool((flags >> 1) & 1)
        syn_set = bool(flags >> 2)

        data = header[10:10 + data_length]

        logger.debug("unpack_segment_header() done")
        return seqnum, acknum, syn_set, ack_set, fin_set, window, data_length, checksum

