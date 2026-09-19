"""Security regressions for the AAuth teaching server."""

import importlib.util
import pathlib
import time
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("aauth_server", ROOT / "src/05-aauth/server.py")
aauth = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(aauth)


class AAuthSecurityTests(unittest.TestCase):
    issuer = "https://vchirrav-eng.github.io/aauth_research"
    person_server = "https://person.hello.coop"

    def setUp(self):
        aauth._seen_signatures.clear()
        self.proof_key = Ed25519PrivateKey.generate()
        self.issuer_key = Ed25519PrivateKey.generate()
        self.proof_jwk = {
            "kty": "OKP", "crv": "Ed25519",
            "x": aauth._b64u(self.proof_key.public_key().public_bytes_raw()),
        }
        aauth._jwks_overrides.clear()
        aauth._jwks_overrides[self.issuer] = [{
            "kid": "test-agent-key", "kty": "OKP", "crv": "Ed25519",
            "x": aauth._b64u(self.issuer_key.public_key().public_bytes_raw()),
        }]

    def _agent_token(self, key=None, kid="test-agent-key", alg="EdDSA"):
        now = int(time.time())
        return aauth._make_jwt(
            {"alg": alg, "typ": "aa-agent+jwt", "kid": kid},
            {"iss": self.issuer, "sub": "aauth:test@vchirrav-eng.github.io",
             "ps": self.person_server, "cnf": {"jwk": self.proof_jwk},
             "iat": now, "exp": now + 60}, key or self.issuer_key)

    def _request(self, token, with_digest=True):
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "list_reports"}}
        request = aauth._sign_request(
            self.proof_key, token, "POST", "mcp.example.com", "/mcp",
            body=body if with_digest else None)
        request.update(body)
        return request

    def test_forged_agent_jwt_is_rejected(self):
        forged_key = Ed25519PrivateKey.generate()
        token = self._agent_token(forged_key, kid="forged-key", alg="none")
        response = aauth.server.handle(self._request(token))
        self.assertEqual(response["error"]["code"], -32002)
        self.assertIn("unexpected JWT type or algorithm", response["error"]["message"])

    def test_body_digest_is_mandatory(self):
        response = aauth.server.handle(self._request(self._agent_token(), with_digest=False))
        self.assertEqual(response["error"]["code"], -32002)
        self.assertIn("must cover", response["error"]["message"])


if __name__ == "__main__":
    unittest.main()
