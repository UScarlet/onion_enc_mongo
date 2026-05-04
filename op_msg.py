import struct
from typing import Optional

from bson import decode

from wire import (
    MSG_HEADER_SIZE,
    OP_MSG,
    FLAG_CHECKSUM_PRESENT,
    ProtocolError,
    read_int32,
    read_uint32,
    write_int32,
    write_uint32,
    read_cstring,
)

# TODO найди в прошлом фацле описание формата этого - какие тамм поля, как этим пользоваться
def parse_op_msg(message: bytes) -> dict:
    """
    Разобрать сообщение формата OP_MSG.
    """
    if len(message) < 20:
        raise ProtocolError("OP_MSG too short")

    header = message[:MSG_HEADER_SIZE]
    request_id, response_to, opcode = struct.unpack('<iii', header[4:16])

    if opcode != OP_MSG:
        raise ProtocolError(f"Expected OP_MSG, got {opcode}")

    flags = read_uint32(message, 16)
    offset = 20

    sections = []
    has_checksum = (flags & FLAG_CHECKSUM_PRESENT) != 0
    data_end = len(message) - (4 if has_checksum else 0)

    while offset < data_end:
        payload_type = message[offset]
        offset += 1

        if payload_type == 0:
            if offset + 4 > data_end:
                raise ProtocolError("Truncated BSON in section type 0")

            doc_len = read_int32(message, offset)
            if doc_len < 5 or offset + doc_len > data_end:
                raise ProtocolError(
                    f"BSON document exceeds message: doc_len={doc_len}, "
                    f"offset={offset}, data_end={data_end}"
                )

            sections.append({
                'type': 0,
                'document': message[offset:offset + doc_len]
            })
            offset += doc_len

        elif payload_type == 1:
            if offset + 4 > data_end:
                raise ProtocolError("Truncated section type 1 size")

            section_size = read_int32(message, offset)
            if section_size < 5:
                raise ProtocolError(f"Invalid section size: {section_size}")

            section_end = offset + section_size
            if section_end > data_end:
                raise ProtocolError(
                    f"Section type 1 exceeds message: "
                    f"section_end={section_end}, data_end={data_end}"
                )

            offset += 4
            ident, offset = read_cstring(message, offset)

            docs = []
            while offset < section_end:
                if offset + 4 > section_end:
                    raise ProtocolError("Truncated BSON in section type 1")

                doc_len = read_int32(message, offset)
                if doc_len < 5 or offset + doc_len > section_end:
                    raise ProtocolError(
                        f"BSON document exceeds section: doc_len={doc_len}, "
                        f"offset={offset}, section_end={section_end}"
                    )

                docs.append(message[offset:offset + doc_len])
                offset += doc_len

            sections.append({
                'type': 1,
                'identifier': ident,
                'documents': docs
            })

            if offset != section_end:
                raise ProtocolError("Section type 1 parsing mismatch")

        else:
            raise ProtocolError(f"Unknown payload type: {payload_type}")

    checksum = None
    if has_checksum:
        if len(message) - offset != 4:
            raise ProtocolError("Checksum present flag set, but checksum bytes missing")
        checksum = read_uint32(message, offset)

    return {
        'header': (request_id, response_to, opcode),
        'flags': flags,
        'sections': sections,
        'checksum': checksum,
        'raw_message': message
    }


def build_op_msg(
    request_id: int,
    response_to: int,
    flags: int,
    sections: list,
    checksum: Optional[int] = None
) -> bytes:
    """
    Собрать OP_MSG обратно.
    """
    body = bytearray()
    body += write_uint32(flags)

    for sec in sections:
        if sec['type'] == 0:
            body.append(0)
            body += sec['document']

        elif sec['type'] == 1:
            identifier_bytes = sec['identifier'].encode('utf-8') + b'\x00'
            docs_blob = b''.join(sec['documents'])

            section_size = 4 + len(identifier_bytes) + len(docs_blob)

            body.append(1)
            body += write_int32(section_size)
            body += identifier_bytes
            body += docs_blob

        else:
            raise ProtocolError(f"Unsupported section type for build_op_msg: {sec['type']}")

    if flags & FLAG_CHECKSUM_PRESENT:
        if checksum is None:
            raise NotImplementedError(
                "Building OP_MSG with checksumPresent requires explicit checksum value"
            )
        body += write_uint32(checksum)

    total_len = MSG_HEADER_SIZE + len(body)
    header = struct.pack('<iiii', total_len, request_id, response_to, OP_MSG)
    return header + body


def roundtrip_op_msg(raw_msg: bytes) -> bool:
    """
    Проверка parse -> build -> compare.
    """
    parsed = parse_op_msg(raw_msg)
    rebuilt = build_op_msg(
        request_id=parsed['header'][0],
        response_to=parsed['header'][1],
        flags=parsed['flags'],
        sections=parsed['sections'],
        checksum=parsed['checksum'],
    )
    return rebuilt == raw_msg


def get_first_document(sections: list) -> Optional[dict]:
    """
    Извлечь первый BSON-документ из секций OP_MSG.
    """
    for sec in sections:
        if sec['type'] == 0:
            return decode(sec['document'])
        if sec['type'] == 1 and sec['documents']:
            return decode(sec['documents'][0])
    return None


def get_command_name(doc: Optional[dict]) -> Optional[str]:
    """
    Вернуть имя MongoDB-команды: первый ключ первого BSON-документа.
    """
    if not doc:
        return None
    return next(iter(doc.keys()), None)