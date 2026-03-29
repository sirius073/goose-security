# File: crypto_algos/security_utils.py

def _read_tlv_length(data: bytes, index: int) -> tuple[int, int]:
    first = data[index]
    index += 1

    if first < 0x80:
        return first, index
    if first == 0x81:
        return data[index], index + 1
    if first == 0x82:
        return int.from_bytes(data[index:index + 2], "big"), index + 2
    if first == 0x83:
        return int.from_bytes(data[index:index + 3], "big"), index + 3
    raise ValueError("Unsupported TLV length encoding in GOOSE payload")


def extract_goose_state_numbers(goose_payload: bytes) -> tuple[int, int]:
    """
    Extracts (stNum, sqNum) from GOOSE payload bytes.
    Expected payload starts at APPID and includes the GOOSE PDU.
    """
    if len(goose_payload) < 10:
        raise ValueError("Invalid GOOSE payload: too short")

    pdu_start = 8
    if goose_payload[pdu_start] != 0x61:
        raise ValueError("Invalid GOOSE payload: missing PDU tag 0x61")

    pdu_length, value_index = _read_tlv_length(goose_payload, pdu_start + 1)
    pdu_end = value_index + pdu_length

    if pdu_end > len(goose_payload):
        raise ValueError("Invalid GOOSE payload: truncated PDU")

    st_num = None
    sq_num = None
    index = value_index

    while index < pdu_end:
        tag = goose_payload[index]
        length, value_start = _read_tlv_length(goose_payload, index + 1)
        value_end = value_start + length

        if value_end > pdu_end:
            raise ValueError("Invalid GOOSE payload: malformed TLV")

        value = goose_payload[value_start:value_end]
        if tag == 0x85:
            st_num = int.from_bytes(value, "big")
        elif tag == 0x86:
            sq_num = int.from_bytes(value, "big")
            if st_num is not None:
                break

        index = value_end

    if st_num is None or sq_num is None:
        raise ValueError("Invalid GOOSE payload: missing stNum or sqNum")

    return st_num, sq_num


class GooseReplayTracker:
    """
    Replay protection using Boot ID + stNum + sqNum semantics.
    - boot_id change is treated as a new publisher session.
    - stNum must not decrease.
    - sqNum must strictly increase for the same stNum.
    """
    def __init__(self):
        self.last_boot_id: bytes | None = None
        self.last_st_num = -1
        self.last_sq_num = -1

    def is_acceptable(self, boot_id: bytes, st_num: int, sq_num: int) -> bool:
        if len(boot_id) != 4:
            return False

        if self.last_boot_id is None or boot_id != self.last_boot_id:
            return True

        if st_num < self.last_st_num:
            return False

        if st_num > self.last_st_num:
            return True

        if sq_num <= self.last_sq_num:
            return False

        return True

    def commit(self, boot_id: bytes, st_num: int, sq_num: int) -> None:
        self.last_boot_id = boot_id
        self.last_st_num = st_num
        self.last_sq_num = sq_num

