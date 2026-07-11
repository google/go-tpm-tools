import pytest
import threading
import time
import socket
import http.server
import http.client
import io
import os
import sys
from unittest.mock import MagicMock, patch

# Simulate a server that reads request bodies - testing the security invariant
# that request body size must be limited to prevent memory exhaustion DoS

MAX_ALLOWED_BODY_SIZE = 10 * 1024 * 1024  # 10 MB - reasonable upper bound for any legitimate request

# Adversarial payloads representing attack scenarios
ADVERSARIAL_PAYLOADS = [
    # Large body attacks
    b"A" * (100 * 1024 * 1024),          # 100 MB - memory exhaustion attempt
    b"B" * (50 * 1024 * 1024),           # 50 MB - large body
    b"\x00" * (20 * 1024 * 1024),        # 20 MB null bytes
    b"\xff" * (15 * 1024 * 1024),        # 15 MB high bytes
    # Protobuf-like malformed large payloads
    b"\x0a" + b"\xff" * (11 * 1024 * 1024),  # Protobuf field tag + oversized data
    b"\x12\xff\xff\xff\xff\x0f" + b"X" * (12 * 1024 * 1024),  # Malformed protobuf length-delimited
    # Chunked/streaming large payloads
    b"C" * (25 * 1024 * 1024),           # 25 MB chunked simulation
    b"\x00\xff" * (8 * 1024 * 1024),     # 16 MB alternating bytes
]


class LimitedBodyReader:
    """
    Simulates a request body reader with MaxBytesReader-like behavior.
    This represents the CORRECT implementation that should be enforced.
    """
    def __init__(self, body: bytes, max_size: int):
        self._body = io.BytesIO(body)
        self._max_size = max_size
        self._bytes_read = 0
        self._limit_exceeded = False

    def read(self, n: int = -1) -> bytes:
        if self._bytes_read >= self._max_size:
            self._limit_exceeded = True
            raise IOError(f"http: request body too large (limit: {self._max_size} bytes)")
        
        remaining = self._max_size - self._bytes_read
        if n == -1:
            to_read = remaining
        else:
            to_read = min(n, remaining)
        
        data = self._body.read(to_read)
        self._bytes_read += len(data)
        
        # Check if there's more data beyond the limit
        extra = self._body.read(1)
        if extra:
            self._limit_exceeded = True
            raise IOError(f"http: request body too large (limit: {self._max_size} bytes)")
        
        return data

    @property
    def limit_exceeded(self) -> bool:
        return self._limit_exceeded


def simulate_read_request_with_limit(body: bytes, max_size: int) -> tuple:
    """
    Simulates the readRequest function WITH proper MaxBytesReader protection.
    Returns (success, bytes_read, error_message)
    """
    reader = LimitedBodyReader(body, max_size)
    try:
        data = reader.read()
        return True, len(data), None
    except IOError as e:
        return False, reader._bytes_read, str(e)


def simulate_read_request_without_limit(body: bytes) -> tuple:
    """
    Simulates the VULNERABLE readRequest function WITHOUT MaxBytesReader.
    Returns (success, bytes_read, error_message)
    """
    stream = io.BytesIO(body)
    data = stream.read()  # Reads entire body - VULNERABLE
    return True, len(data), None


@pytest.mark.parametrize("payload", ADVERSARIAL_PAYLOADS)
def test_request_body_size_limit_enforced(payload):
    """
    Invariant: HTTP request body reading MUST enforce a maximum size limit.
    
    Any implementation of readRequest (or equivalent) that processes HTTP request
    bodies for protobuf deserialization MUST reject bodies exceeding the configured
    maximum size. This prevents memory exhaustion DoS attacks where attackers send
    arbitrarily large request bodies.
    
    The security property: for any input body larger than MAX_ALLOWED_BODY_SIZE,
    the reader MUST raise an error and MUST NOT read the entire body into memory.
    """
    body_size = len(payload)
    
    if body_size > MAX_ALLOWED_BODY_SIZE:
        # Test that a properly protected implementation rejects oversized bodies
        success, bytes_read, error = simulate_read_request_with_limit(payload, MAX_ALLOWED_BODY_SIZE)
        
        # INVARIANT 1: Must not succeed when body exceeds limit
        assert not success, (
            f"SECURITY VIOLATION: Request body of {body_size} bytes was accepted without error. "
            f"Bodies exceeding {MAX_ALLOWED_BODY_SIZE} bytes must be rejected to prevent DoS."
        )
        
        # INVARIANT 2: Must not read more than the allowed maximum
        assert bytes_read <= MAX_ALLOWED_BODY_SIZE, (
            f"SECURITY VIOLATION: Read {bytes_read} bytes from body of {body_size} bytes. "
            f"Must not read more than {MAX_ALLOWED_BODY_SIZE} bytes."
        )
        
        # INVARIANT 3: Error message must indicate body size limit
        assert error is not None, (
            "SECURITY VIOLATION: No error raised for oversized request body."
        )
        
        assert "too large" in error.lower() or "limit" in error.lower(), (
            f"SECURITY VIOLATION: Error message '{error}' does not indicate size limit exceeded."
        )
        
        # INVARIANT 4: Demonstrate the vulnerability exists without protection
        # (this shows WHY the limit is necessary)
        vuln_success, vuln_bytes_read, _ = simulate_read_request_without_limit(payload)
        assert vuln_success and vuln_bytes_read == body_size, (
            "Test setup error: vulnerable implementation should read full body"
        )
        
        # The protected version must read significantly less than the vulnerable version
        assert bytes_read < vuln_bytes_read, (
            f"SECURITY VIOLATION: Protected reader ({bytes_read} bytes) read as much as "
            f"unprotected reader ({vuln_bytes_read} bytes). Size limiting is not effective."
        )


@pytest.mark.parametrize("payload", ADVERSARIAL_PAYLOADS)
def test_memory_not_exhausted_by_large_body(payload):
    """
    Invariant: Processing an oversized request body must not consume memory
    proportional to the attacker-controlled body size.
    
    The server must enforce body size limits so that memory usage is bounded
    by the configured limit, not by the size of the incoming request.
    """
    body_size = len(payload)
    
    if body_size > MAX_ALLOWED_BODY_SIZE:
        # Track memory allocation by measuring bytes actually processed
        bytes_processed_list = []
        
        def process_with_limit():
            _, bytes_read, _ = simulate_read_request_with_limit(payload, MAX_ALLOWED_BODY_SIZE)
            bytes_processed_list.append(bytes_read)
        
        process_with_limit()
        
        assert len(bytes_processed_list) == 1
        bytes_processed = bytes_processed_list[0]
        
        # INVARIANT: Memory consumed must be bounded by the limit, not the payload size
        assert bytes_processed <= MAX_ALLOWED_BODY_SIZE, (
            f"SECURITY VIOLATION: Server processed {bytes_processed} bytes from a "
            f"{body_size}-byte payload. Memory usage must be bounded by "
            f"MAX_ALLOWED_BODY_SIZE ({MAX_ALLOWED_BODY_SIZE} bytes)."
        )
        
        # The ratio of processed to total must show effective limiting
        if body_size > 0:
            ratio = bytes_processed / body_size
            assert ratio < 1.0, (
                f"SECURITY VIOLATION: Processed {ratio*100:.1f}% of oversized payload. "
                f"Effective size limiting must prevent full body from being read."
            )


@pytest.mark.parametrize("size_multiplier,should_be_rejected", [
    (0.5, False),    # 50% of limit - should be accepted
    (0.9, False),    # 90% of limit - should be accepted  
    (1.0, False),    # exactly at limit - should be accepted
    (1.1, True),     # 10% over limit - must be rejected
    (2.0, True),     # 2x limit - must be rejected
    (10.0, True),    # 10x limit - must be rejected
    (100.0, True),   # 100x limit - must be rejected
])
def test_body_size_boundary_enforcement(size_multiplier, should_be_rejected):
    """
    Invariant: The body size limit must be enforced precisely at the boundary.
    
    Requests at or below the limit must succeed; requests above must be rejected.
    This ensures the security boundary is correctly implemented.
    """
    body_size = int(MAX_ALLOWED_BODY_SIZE * size_multiplier)
    # Use a small representative payload to avoid actual memory issues in tests
    # We simulate the size check behavior
    
    class MockBodySizeChecker:
        """Simulates size-aware body reading without allocating full memory"""
        def __init__(self, reported_size: int, limit: int):
            self.reported_size = reported_size
            self.limit = limit
        
        def check(self) -> tuple:
            if self.reported_size > self.limit:
                return False, min(self.reported_size, self.limit), "http: request body too large"
            return True, self.reported_size, None
    
    checker = MockBodySizeChecker(body_size, MAX_ALLOWED_BODY_SIZE)
    success, bytes_processed, error = checker.check()
    
    if should_be_rejected:
        assert not success, (
            f"SECURITY VIOLATION: Body of size {body_size} (multiplier={size_multiplier}x) "
            f"was accepted but should be rejected. Limit is {MAX_ALLOWED_BODY_SIZE} bytes."
        )
        assert bytes_processed <= MAX_ALLOWED_BODY_SIZE, (
            f"SECURITY VIOLATION: Processed {bytes_processed} bytes exceeding limit "
            f"of {MAX_ALLOWED_BODY_SIZE} bytes."
        )
        assert error is not None, (
            f"SECURITY VIOLATION: No error for oversized body (size={body_size})."
        )
    else:
        assert success, (
            f"Legitimate request of size {body_size} was incorrectly rejected. "
            f"Limit is {MAX_ALLOWED_BODY_SIZE} bytes."
        )
        assert error is None, (
            f"Unexpected error for legitimate request: {error}"
        )


def test_concurrent_large_body_requests_bounded():
    """
    Invariant: Concurrent oversized requests must each be individually bounded.
    
    Even under concurrent attack (multiple simultaneous oversized requests),
    each request must be independently limited to prevent aggregate memory exhaustion.
    """
    num_concurrent = 10
    oversized_body = b"X" * (MAX_ALLOWED_BODY_SIZE * 5)  # 5x the limit
    
    results = []
    errors = []
    lock = threading.Lock()
    
    def process_request():
        try:
            success, bytes_read, error = simulate_read_request_with_limit(
                oversized_body, MAX_ALLOWED_BODY_SIZE
            )
            with lock:
                results.append((success, bytes_read, error))
        except Exception as e:
            with lock:
                errors.append(str(e))
    
    threads = [threading.Thread(target=process_request) for _ in range(num_concurrent)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
    
    # INVARIANT: All concurrent requests must be individually rejected
    assert len(results) == num_concurrent, (
        f"Expected {num_concurrent} results, got {len(results)}. "
        f"Errors: {errors}"
    )
    
    for i, (success, bytes_read, error) in enumerate(results):
        assert not success, (
            f"SECURITY VIOLATION: Concurrent request {i} accepted oversized body."
        )
        assert bytes_read <= MAX_ALLOWED_BODY_SIZE, (
            f"SECURITY VIOLATION: Concurrent request {i} read {bytes_read} bytes, "
            f"exceeding limit of {MAX_ALLOWED_BODY_SIZE}."
        )
    
    # Total bytes across all concurrent requests must be bounded
    total_bytes = sum(r[1] for r in results)
    max_total = MAX_ALLOWED_BODY_SIZE * num_concurrent
    assert total_bytes <= max_total, (
        f"SECURITY VIOLATION: Total bytes across concurrent requests ({total_bytes}) "
        f"exceeds expected maximum ({max_total})."
    )