import struct
import zlib
import snappy
import zstd

from protocol.wire import (
    MSG_HEADER_SIZE,
    OP_COMPRESSED,
    ProtocolError,
    read_int32,
    write_int32,
)



def parse_op_compressed_wrapper(message: bytes) -> dict:
    """
    Разобрать внешнюю обёртку OP_COMPRESSED.
    """
    if len(message) < 25:
        raise ProtocolError("OP_COMPRESSED too short")

    wrapper_header = message[:MSG_HEADER_SIZE]
    request_id, response_to, wrapper_opcode = struct.unpack('<iii', wrapper_header[4:16])

    if wrapper_opcode != OP_COMPRESSED:
        raise ProtocolError(f"Expected OP_COMPRESSED, got {wrapper_opcode}")

    body = message[MSG_HEADER_SIZE:]
    if len(body) < 9:
        raise ProtocolError("OP_COMPRESSED body too short")

    original_opcode = read_int32(body, 0)
    uncompressed_size = read_int32(body, 4)
    compressor_id = body[8]
    compressed_payload = body[9:]

    return {
        'request_id': request_id,
        'response_to': response_to,
        'wrapper_opcode': wrapper_opcode,
        'original_opcode': original_opcode,
        'uncompressed_size': uncompressed_size,
        'compressor_id': compressor_id,
        'compressed_payload': compressed_payload,
        'raw_message': message,
    }


def decompress_mongo_payload(
    compressor_id: int,
    compressed_payload: bytes,
    uncompressed_size: int
) -> bytes:
    """
    Распаковать payload из OP_COMPRESSED.

    0 = noop
    1 = snappy
    2 = zlib
    3 = zstd
    """
    if compressor_id == 0:
        return compressed_payload

    if compressor_id == 1:
        if snappy is None:
            raise NotImplementedError(
                "Snappy compression is not available: install python-snappy"
            )
        return snappy.uncompress(compressed_payload)

    if compressor_id == 2:
        return zlib.decompress(compressed_payload)

    if compressor_id == 3:
        if zstd is None:
            raise NotImplementedError(
                "Zstd compression is not available: install zstandard"
            )
        dctx = zstd.ZstdDecompressor()
        return dctx.decompress(
            compressed_payload,
            max_output_size=uncompressed_size
        )

    raise NotImplementedError(f"Compression {compressor_id} not supported")


def compress_mongo_payload(compressor_id: int, payload: bytes) -> bytes:
    """
    Сжать payload для OP_COMPRESSED.

    0 = noop
    1 = snappy
    2 = zlib
    3 = zstd
    """
    if compressor_id == 0:
        return payload

    if compressor_id == 1:
        if snappy is None:
            raise NotImplementedError(
                "Snappy compression is not available: install python-snappy"
            )
        return snappy.compress(payload)

    if compressor_id == 2:
        return zlib.compress(payload)

    if compressor_id == 3:
        if zstd is None:
            raise NotImplementedError(
                "Zstd compression is not available: install zstandard"
            )
        cctx = zstd.ZstdCompressor()
        return cctx.compress(payload)

    raise NotImplementedError(f"Compression {compressor_id} not supported")


def unpack_op_compressed(message: bytes) -> bytes:
    """
    Распаковать OP_COMPRESSED в синтетическое обычное MongoDB-сообщение.
    """
    wrapper = parse_op_compressed_wrapper(message)

    decompressed = decompress_mongo_payload(
        wrapper['compressor_id'],
        wrapper['compressed_payload'],
        wrapper['uncompressed_size']
    )

    synthetic_header = struct.pack(
        '<iiii',
        MSG_HEADER_SIZE + len(decompressed),
        wrapper['request_id'],
        wrapper['response_to'],
        wrapper['original_opcode']
    )
    return synthetic_header + decompressed


def pack_op_compressed(inner_message: bytes, compressor_id: int) -> bytes:
    """
    Упаковать обычное MongoDB-сообщение обратно в OP_COMPRESSED.
    """
    if len(inner_message) < MSG_HEADER_SIZE:
        raise ProtocolError("Inner message too short for OP_COMPRESSED packing")

    request_id, response_to, original_opcode = struct.unpack('<iii', inner_message[4:16])
    inner_body = inner_message[MSG_HEADER_SIZE:]

    compressed_payload = compress_mongo_payload(compressor_id, inner_body)

    wrapper_body = (
        write_int32(original_opcode) +
        write_int32(len(inner_body)) +
        bytes([compressor_id]) +
        compressed_payload
    )

    wrapper_header = struct.pack(
        '<iiii',
        MSG_HEADER_SIZE + len(wrapper_body),
        request_id,
        response_to,
        OP_COMPRESSED
    )
    return wrapper_header + wrapper_body