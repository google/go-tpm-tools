## Example Dev Workflow

1. **Set `launchSpec.Experiments.EnableAttestationEvidence` to `true` in `cmd/teeserver/serve.go`**

2. **Build the `teeserver` binary from the repository root:**

   ```bash
   go build -o teeserver ./cmd/teeserver
   ```

3. **Start the server in the background (requires root for TPM access):**

   ```bash
   sudo ./teeserver serve
   ```

4. **Request attestation evidence from the running server and save it to a file:**
   ```bash
   ./teeserver evidence --challenge "dGVzdF9jaGFsbGVuZ2U=" > evidence.json
   ```
