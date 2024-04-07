import struct
import logging
from enum import IntEnum


logger = logging.getLogger(__name__)


class BTCPStates(IntEnum):
    CLOSED      = 0
    ACCEPTING   = 1
    SYN_SENT    = 2
    SYN_RCVD    = 3
    ESTABLISHED = 4
    FIN_SENT    = 5
    CLOSING     = 6


class BTCPSignals(IntEnum):
    ACCEPT = 1
    CONNECT = 2
    SHUTDOWN = 3


class BTCPSocket:
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

        logger.debug("unpack_segment_header() done")
        return seqnum, acknum, syn_set, ack_set, fin_set, window, data_length, checksum

