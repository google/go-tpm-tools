# mock_wsd

`mock_wsd` is a standalone binary that mocks the `WorkloadAttestationService` specifically for the `GetKeyEndorsement` endpoint. 

The binary exposes UDS located at `/run/workload_attestation.sock`. It serves RESTful JSON API that answers requests formatted as `GetKeyEndorsementRequest` and returns `GetKeyEndorsementResponse`.

Internally, it instantiates `AttestationAgent` to fetch a standalone VMAttestation, wraps it in the `GetKeyEndorsementResponse` struct, and sets the label to `WORKLOAD_ATTESTATION`.

> **Note on Attestation Evidence**
> By default, `mock_wsd` is configured with `launchSpec.Experiments.EnableAttestationEvidence = false`, flip this value to `true` before compiling.

### 1. Build the binary

From the root of `go-tpm-tools`:

```bash
go build -o mock_wsd_bin ./cmd/mock_wsd
```

### 2. Start the `mock_wsd`

(Requires root privileges to listen on `/run/workload_attestation.sock` and access `/dev/tpmrm0`)

```bash
sudo ./mock_wsd_bin
```

### 3. Query `mock_wsd`

Once the server is running, you can query `mock_wsd` from another terminal. You can write the output to a JSON file (e.g., `evidence.json`) as follows:
```bash
curl --unix-socket /run/workload_attestation.sock \
	-H "Content-Type: application/json" \
	-d '{"challenge": "Y2hhbGxlbmdl", "key_handle": {"handle": "some_handle"}}' \
	http://localhost/v1/workload/attestation/key_endorsement | jq . > evidence.json
```

This will save the JSON API response (containing the nested `KeyEndorsement` -> `VmProtectedKeyEndorsement` -> `KeyAttestation` -> `VMAttestation`) into `evidence.json`.
