"""UDP echo checks for NetVerify."""

import socket

# Receive buffer capacity for recvfrom(): the most bytes read from one reply.
# This is not the maximum UDP payload, but it can hold any IPv4 UDP payload
# (at most 65,507 bytes), so replies are not truncated.
BUFFER_SIZE = 65535


def check_udp_echo(
    host: str,
    port: int,
    payload: bytes = b"netverify-ping",
    timeout: float = 2.0,
) -> bool:
    """Check whether a UDP echo service returns the payload it was sent.

    Sends one datagram and waits for one reply. Only the first reply
    received is checked.

    Args:
        host: Hostname or IPv4 address of the echo service.
        port: UDP port number of the echo service.
        payload: Bytes to send. The reply must contain exactly these bytes.
        timeout: Socket timeout in seconds for each send and receive;
            not a strict deadline for the entire function.

    Returns:
        True if the reply matches the payload and comes from the host's
        IP address and the same port. False if the reply is different,
        comes from another address, or the check fails with an OSError
        such as a timeout or an unresolvable hostname.
    """
    try:
        # Resolve the host once, because replies always report an IP address.
        ip = socket.gethostbyname(host)

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(payload, (ip, port))
            response, sender = sock.recvfrom(BUFFER_SIZE)
    except OSError:  # Also covers TimeoutError.
        return False

    return response == payload and sender == (ip, port)
