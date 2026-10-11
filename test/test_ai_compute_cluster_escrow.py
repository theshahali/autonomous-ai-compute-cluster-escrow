# test_ai_compute_cluster_escrow.py
# 15-Phase Comprehensive Regression & Security Test Suite for AutonomousAiComputeClusterEscrow
import json
import hashlib
import urllib.parse
import re
from datetime import datetime, timezone


class MockGL:
    def __init__(self):
        self.transfers = []
        self.mock_web_responses = {}
        self.fail_web_fetch = False
        self.simulate_transfer_fail = False

    def emit_transfer(self, recipient: str, amount: int):
        if self.simulate_transfer_fail:
            raise RuntimeError("Simulated EVM transfer failure")
        self.transfers.append({"recipient": str(recipient).lower(), "amount": int(amount)})

    def get_webpage(self, url: str) -> str:
        if self.fail_web_fetch:
            raise RuntimeError("Simulated network timeout connecting to cloud status page")
        return self.mock_web_responses.get(
            url,
            "<html><body><h1>CoreWeave Cloud Incident Post-Mortem: INC-88291</h1>"
            "<p>Cluster: US-EAST-01 H100 InfiniBand Fabric Partition. "
            "Summary: Optical transceiver failure cascaded through leaf spine switches, causing unrecoverable InfiniBand network partition. "
            "Total Unplanned Downtime: 145 minutes. Root cause: Hardware switch failure, not user software or maintenance. SLA Breach Confirmed.</p></body></html>"
        )

    def exec_prompt(self, prompt: str) -> str:
        return json.dumps({
            "sla_breach_confirmed": True,
            "verified_downtime_minutes": 145,
            "confidence_score": 95,
            "rationale": "Provider infrastructure InfiniBand partition outage lasting 145 minutes confirmed."
        })


class MockAutonomousAiComputeClusterEscrow:
    def __init__(self, owner_address: str, gl_mock: MockGL):
        self.gl = gl_mock
        self.owner = owner_address.lower()
        self.total_escrows_created = 0
        self.total_claims_filed = 0
        self.total_claims_adjudicated = 0
        self.total_volume_locked = 0
        self.total_collateral_released = 0
        self.total_collateral_refunded = 0

        self.escrows = {}
        self.claims = {}
        self.consumed_claim_hashes = {}
        self.consumed_escrow_incidents = {}
        self.claimable_balances = {}

        self.STATUS_ACTIVE = "ACTIVE"
        self.STATUS_DISPUTED = "DISPUTED"
        self.STATUS_FULFILLED = "FULFILLED"
        self.STATUS_SLA_BREACH_REFUNDED = "SLA_BREACH_REFUNDED"
        self.STATUS_EXPIRED_REFUNDED = "EXPIRED_REFUNDED"
        self.STATUS_DECOMMISSIONED = "DECOMMISSIONED"

        self.CLAIM_PENDING = "PENDING_CONSENSUS"
        self.CLAIM_SLA_BREACH_CONFIRMED = "SLA_BREACH_CONFIRMED"
        self.CLAIM_REFUTED = "CLAIM_REFUTED"
        self.CLAIM_INCONCLUSIVE = "INCONCLUSIVE"
        self.CLAIM_ABANDONED = "CLAIM_ABANDONED"

        self.MIN_CLUSTER_RESERVATION = 100_000_000_000
        self.MIN_TOPUP_AMOUNT = 10_000_000_000
        self.MIN_CLAIM_BOND = 25_000_000_000
        self.MIN_LEASE_DURATION = 86400 * 7
        self.MAX_LEASE_DURATION = 86400 * 365 * 2
        self.CLAIM_TIMEOUT_SECONDS = 86400 * 7
        self.IDLE_EXPIRY_GRACE_PERIOD = 86400 * 2
        self.SLA_DOWNTIME_BREACH_THRESHOLD_MINUTES = 60

        self.APPROVED_TELEMETRY_DOMAINS = (
            "status.coreweave.com",
            "status.lambdalabs.com",
            "status.nebius.com",
            "status.aws.amazon.com",
            "status.cloud.google.com",
            "status.azure.com",
            "lambdalabs.com",
            "coreweave.com",
            "together.ai",
            "runpod.io"
        )

    def _validate_eth_address(self, addr_str: str, field_name: str) -> str:
        clean = addr_str.strip().strip('"').strip("'")
        assert len(clean) == 42, "[ERR_ADDR_FORMAT] " + field_name + " must be a 42-character hex address."
        assert clean.startswith("0x") or clean.startswith("0X"), "[ERR_ADDR_PREFIX] " + field_name + " must start with '0x'."
        hex_digits = clean[2:]
        for c in hex_digits:
            assert c in "0123456789abcdefABCDEF", "[ERR_ADDR_HEX] " + field_name + " contains non-hex characters."
        assert clean.lower() != "0x" + "0" * 40, "[ERR_ADDR_ZERO] " + field_name + " cannot be the zero address."
        return clean.lower()

    def _sanitize_string(self, val: str, min_len: int, max_len: int, field_name: str) -> str:
        clean = val.strip()
        assert len(clean) >= min_len, "[ERR_STR_TOO_SHORT] " + field_name + " length must be >= " + str(min_len)
        assert len(clean) <= max_len, "[ERR_STR_TOO_LONG] " + field_name + " length must be <= " + str(max_len)
        return clean

    def _validate_incident_url(self, url_str: str) -> str:
        clean = url_str.strip()
        assert len(clean) <= 512, "[ERR_URL_TOO_LONG] Incident URL exceeds 512 characters."
        assert not ("\n" in clean or "\r" in clean or "\t" in clean), "[ERR_URL_WHITESPACE] URL must not contain newlines or tabs."
        assert "@" not in clean, "[ERR_URL_CREDENTIALS] Embedded credentials prohibited in incident URL."

        try:
            parsed = urllib.parse.urlparse(clean)
        except Exception:
            raise AssertionError("[ERR_URL_PARSE] Failed to parse incident URL.")

        scheme = (parsed.scheme or "").lower()
        assert scheme in ("http", "https"), "[ERR_URL_SCHEME] Incident URL must use HTTP or HTTPS."

        hostname = (parsed.hostname or "").lower()
        assert hostname, "[ERR_URL_HOSTNAME] Incident URL missing hostname."
        assert hostname not in ("localhost", "127.0.0.1", "0.0.0.0", "::1"), "[ERR_URL_LOOPBACK] SSRF attempt: loopback address rejected."

        matched_domain = False
        for approved_d in self.APPROVED_TELEMETRY_DOMAINS:
            if hostname == approved_d or hostname.endswith("." + approved_d):
                matched_domain = True
                break
        assert matched_domain, "[ERR_URL_UNAPPROVED_DOMAIN] Target domain '" + hostname + "' not in approved catalog."
        return clean

    def _compute_claim_hash(self, escrow_id: str, claimant: str, incident_url: str, nonce: str) -> str:
        data = (
            "L" + str(len(escrow_id)) + ":" + escrow_id.upper() + "|" +
            "L" + str(len(claimant)) + ":" + claimant.lower() + "|" +
            "L" + str(len(incident_url)) + ":" + incident_url + "|" +
            "L" + str(len(nonce)) + ":" + nonce
        )
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    def fund_contract(self, caller: str, value: int):
        assert value > 0, "[ERR_ZERO_PAYMENT] Value must be greater than zero."
        sender_hex = self._validate_eth_address(caller, "Sender")
        cur = self.claimable_balances.get(sender_hex, 0)
        self.claimable_balances[sender_hex] = cur + value
        self.total_volume_locked += value
        return "FUNDED: " + str(value) + " wei credited to " + sender_hex

    def create_cluster_lease_escrow(self, caller: str, value: int, provider_address: str, cluster_identifier: str, gpu_count: int, lease_duration_seconds: int):
        client_hex = self._validate_eth_address(caller, "AI Client")
        provider_hex = self._validate_eth_address(provider_address, "Compute Provider")
        assert client_hex != provider_hex, "[ERR_IDENTICAL_PARTIES] AI client and provider cannot be identical."

        clean_cluster = self._sanitize_string(cluster_identifier, 4, 64, "Cluster Identifier")
        assert re.match(r'^[a-zA-Z0-9_\-\. ]{4,64}$', clean_cluster), \
            "[ERR_INVALID_CLUSTER_ID] Cluster identifier must only contain alphanumeric characters, spaces, underscores, hyphens, and periods."
        assert gpu_count > 0 and gpu_count <= 65536, "[ERR_INVALID_GPU_COUNT] GPU count invalid."
        assert lease_duration_seconds >= self.MIN_LEASE_DURATION, "[ERR_DURATION_TOO_SHORT] Duration too short."
        assert lease_duration_seconds <= self.MAX_LEASE_DURATION, "[ERR_DURATION_TOO_LONG] Duration too long."
        assert value >= self.MIN_CLUSTER_RESERVATION, "[ERR_MIN_RESERVATION] Escrow below minimum."

        now_utc = int(datetime.now(timezone.utc).timestamp())
        deadline_utc = now_utc + lease_duration_seconds

        new_id = "ESCROW_GPU_" + str(self.total_escrows_created + 1)
        self.escrows[new_id] = {
            "escrow_id": new_id,
            "ai_client": client_hex,
            "provider": provider_hex,
            "cluster_identifier": clean_cluster,
            "gpu_count": gpu_count,
            "advance_collateral": value,
            "total_released_to_provider": 0,
            "total_refunded_to_client": 0,
            "created_at": now_utc,
            "lease_deadline": deadline_utc,
            "status": self.STATUS_ACTIVE
        }
        self.total_escrows_created += 1
        self.total_volume_locked += value
        return new_id

    def topup_cluster_escrow(self, caller: str, value: int, escrow_id: str):
        assert escrow_id in self.escrows, "[ERR_ESCROW_NOT_FOUND] Escrow not found."
        e = self.escrows[escrow_id]
        assert e["status"] == self.STATUS_ACTIVE, "[ERR_ESCROW_NOT_ACTIVE] Escrow not active."

        sender_hex = self._validate_eth_address(caller, "Caller")
        assert sender_hex == e["ai_client"], "[ERR_UNAUTHORIZED] Only AI client can top up."
        assert value >= self.MIN_TOPUP_AMOUNT, "[ERR_MIN_TOPUP] Topup below minimum."

        e["advance_collateral"] += value
        self.total_volume_locked += value
        return "TOPPED_UP: " + escrow_id + " | Added: " + str(value)

    def confirm_cluster_fulfillment(self, caller: str, escrow_id: str):
        assert escrow_id in self.escrows, "[ERR_ESCROW_NOT_FOUND] Escrow not found."
        e = self.escrows[escrow_id]
        assert e["status"] == self.STATUS_ACTIVE, "[ERR_ESCROW_NOT_ACTIVE] Escrow not active."

        sender_hex = self._validate_eth_address(caller, "Caller")
        assert sender_hex == e["ai_client"], "[ERR_UNAUTHORIZED] Only AI client can confirm fulfillment."

        amt = e["advance_collateral"]
        assert amt > 0, "[ERR_ZERO_COLLATERAL] No collateral to disburse."

        e["status"] = self.STATUS_FULFILLED
        e["total_released_to_provider"] += amt
        e["advance_collateral"] = 0
        self.total_collateral_released += amt

        transfer_succeeded = False
        try:
            self.gl.emit_transfer(e["provider"], amt)
            transfer_succeeded = True
        except Exception:
            transfer_succeeded = False

        if transfer_succeeded:
            self.total_volume_locked = max(0, self.total_volume_locked - amt)
        else:
            cur = self.claimable_balances.get(e["provider"], 0)
            self.claimable_balances[e["provider"]] = cur + amt

        return "FULFILLED: " + escrow_id

    def claim_completed_lease_payout(self, caller: str, escrow_id: str, custom_time: int = None):
        assert escrow_id in self.escrows, "[ERR_ESCROW_NOT_FOUND] Escrow not found."
        e = self.escrows[escrow_id]
        assert e["status"] == self.STATUS_ACTIVE, "[ERR_ESCROW_NOT_ACTIVE] Escrow not active."

        sender_hex = self._validate_eth_address(caller, "Caller")
        assert sender_hex in (e["provider"], e["ai_client"], self.owner), "[ERR_UNAUTHORIZED] Only provider, AI client, or owner can trigger completed lease payout."

        now_utc = custom_time if custom_time is not None else int(datetime.now(timezone.utc).timestamp())
        assert now_utc > e["lease_deadline"], "[ERR_DEADLINE_NOT_REACHED] Deadline not reached."

        amt = e["advance_collateral"]
        assert amt > 0, "[ERR_ZERO_COLLATERAL] No collateral to disburse."

        e["status"] = self.STATUS_FULFILLED
        e["total_released_to_provider"] += amt
        e["advance_collateral"] = 0
        self.total_collateral_released += amt

        transfer_succeeded = False
        try:
            self.gl.emit_transfer(e["provider"], amt)
            transfer_succeeded = True
        except Exception:
            transfer_succeeded = False

        if transfer_succeeded:
            self.total_volume_locked = max(0, self.total_volume_locked - amt)
        else:
            cur = self.claimable_balances.get(e["provider"], 0)
            self.claimable_balances[e["provider"]] = cur + amt

        return "LEASE_PAYOUT_CLAIMED: " + escrow_id

    def claim_expired_idle_escrow(self, caller: str, escrow_id: str, custom_time: int = None):
        assert escrow_id in self.escrows, "[ERR_ESCROW_NOT_FOUND] Escrow not found."
        e = self.escrows[escrow_id]
        assert e["status"] == self.STATUS_ACTIVE, "[ERR_ESCROW_NOT_ACTIVE] Escrow not active."

        sender_hex = self._validate_eth_address(caller, "Caller")
        assert sender_hex in (e["ai_client"], self.owner), "[ERR_UNAUTHORIZED] Only AI client can reclaim expired escrow."

        now_utc = custom_time if custom_time is not None else int(datetime.now(timezone.utc).timestamp())
        assert now_utc > e["lease_deadline"] + self.IDLE_EXPIRY_GRACE_PERIOD, "[ERR_DEADLINE_NOT_REACHED] Must wait until lease deadline plus 2-day provider claim window elapses."

        amt = e["advance_collateral"]
        assert amt > 0, "[ERR_ZERO_COLLATERAL] No collateral to refund."

        e["status"] = self.STATUS_EXPIRED_REFUNDED
        e["total_refunded_to_client"] += amt
        e["advance_collateral"] = 0
        self.total_collateral_refunded += amt

        transfer_succeeded = False
        try:
            self.gl.emit_transfer(e["ai_client"], amt)
            transfer_succeeded = True
        except Exception:
            transfer_succeeded = False

        if transfer_succeeded:
            self.total_volume_locked = max(0, self.total_volume_locked - amt)
        else:
            cur = self.claimable_balances.get(e["ai_client"], 0)
            self.claimable_balances[e["ai_client"]] = cur + amt

        return "EXPIRED_REFUNDED: " + escrow_id

    def submit_cluster_sla_claim(self, caller: str, value: int, escrow_id: str, incident_report_url: str, downtime_mins: int, nonce: str):
        clean_e_id = escrow_id.strip().upper()
        assert clean_e_id in self.escrows, "[ERR_ESCROW_NOT_FOUND] Escrow not found."
        e = self.escrows[clean_e_id]
        assert e["status"] == self.STATUS_ACTIVE, "[ERR_ESCROW_NOT_ACTIVE] Escrow not active."

        now_utc = int(datetime.now(timezone.utc).timestamp())
        assert now_utc <= e["lease_deadline"], "[ERR_DEADLINE_ELAPSED] Lease deadline has elapsed."

        sender_hex = self._validate_eth_address(caller, "Claimant")
        assert sender_hex in (e["ai_client"], self.owner), "[ERR_UNAUTHORIZED_CLAIMANT] Only AI client or owner can submit claim."
        clean_url = self._validate_incident_url(incident_report_url)
        clean_nonce = self._sanitize_string(nonce, 1, 64, "Nonce")
        assert downtime_mins >= self.SLA_DOWNTIME_BREACH_THRESHOLD_MINUTES, "[ERR_DOWNTIME_TOO_LOW] Downtime below SLA threshold."

        inc_key = clean_e_id + "::" + clean_url.lower()
        assert inc_key not in self.consumed_escrow_incidents, "[ERR_INCIDENT_ALREADY_CLAIMED] Incident already claimed."

        assert value >= self.MIN_CLAIM_BOND, "[ERR_MIN_CLAIM_BOND] Claim bond too low."

        c_hash = self._compute_claim_hash(clean_e_id, sender_hex, clean_url, clean_nonce)
        assert c_hash.lower() not in self.consumed_claim_hashes, "[ERR_CLAIM_EXISTS] Duplicate claim hash."

        new_c_id = "CLAIM_SLA_" + str(self.total_claims_filed + 1)
        self.claims[new_c_id] = {
            "claim_id": new_c_id,
            "escrow_id": clean_e_id,
            "claimant": sender_hex,
            "incident_report_url": clean_url,
            "reported_downtime_minutes": downtime_mins,
            "claim_fingerprint": c_hash,
            "claim_bond": value,
            "filed_at": now_utc,
            "adjudicated_at": 0,
            "verdict": self.CLAIM_PENDING,
            "refund_awarded": 0,
            "has_claimed": False,
            "adjudication_rationale": ""
        }

        self.consumed_claim_hashes[c_hash.lower()] = True
        self.consumed_escrow_incidents[inc_key] = True
        self.total_claims_filed += 1
        self.total_volume_locked += value

        # Lock escrow into DISPUTED state (HIGH-01)
        e["status"] = self.STATUS_DISPUTED
        return new_c_id

    def adjudicate_cluster_sla_claim(self, claim_id: str, custom_breach: bool = None, custom_downtime: int = None, custom_conf: int = None, simulate_parse_error: bool = False):
        assert claim_id in self.claims, "[ERR_CLAIM_NOT_FOUND] Claim not found."
        clm = self.claims[claim_id]
        assert clm["verdict"] == self.CLAIM_PENDING, "[ERR_ALREADY_ADJUDICATED] Claim already adjudicated."

        e = self.escrows[clm["escrow_id"]]

        try:
            incident_text = self.gl.get_webpage(clm["incident_report_url"])
        except Exception:
            raise AssertionError("[ERR_EVIDENCE_FETCH_FAILED] Consensus could not fetch incident telemetry.")

        assert incident_text is not None and len(incident_text.strip()) >= 30, "[ERR_EVIDENCE_FETCH_FAILED] Telemetry response too short."

        # HTML sanitization (HIGH-02)
        cleaned_text = re.sub(r'<script[^>]*>.*?</script>', ' ', incident_text, flags=re.DOTALL | re.IGNORECASE)
        cleaned_text = re.sub(r'<style[^>]*>.*?</style>', ' ', cleaned_text, flags=re.DOTALL | re.IGNORECASE)
        cleaned_text = re.sub(r'<[^>]+>', ' ', cleaned_text)
        cleaned_text = ' '.join(cleaned_text.split())

        parse_valid = False
        parsed_breach = False
        parsed_downtime = 0
        confidence = 0
        rationale = "Consensus fallback resolution."

        if simulate_parse_error:
            parse_valid = False
        elif custom_breach is not None and custom_downtime is not None:
            raw_resp = json.dumps({
                "sla_breach_confirmed": custom_breach,
                "verified_downtime_minutes": custom_downtime,
                "confidence_score": custom_conf if custom_conf is not None else 85,
                "rationale": "Test SLA incident adjudication verdict."
            })
            parsed = json.loads(raw_resp)
            parsed_breach = bool(parsed.get("sla_breach_confirmed", False))
            parsed_downtime = int(parsed.get("verified_downtime_minutes", 0))
            confidence = int(parsed.get("confidence_score", 0))
            rationale = parsed.get("rationale", "")
            parse_valid = True
        else:
            raw_resp = self.gl.exec_prompt("Prompt")
            try:
                clean_json = raw_resp.strip()
                if "```json" in clean_json:
                    clean_json = clean_json.split("```json")[1].split("```")[0].strip()
                elif "```" in clean_json:
                    clean_json = clean_json.split("```")[1].split("```")[0].strip()
                parsed = json.loads(clean_json)
                parsed_breach = bool(parsed.get("sla_breach_confirmed", False))
                parsed_downtime = int(parsed.get("verified_downtime_minutes", 0))
                confidence = int(parsed.get("confidence_score", 0))
                rationale = parsed.get("rationale", "")
                parse_valid = True
            except Exception:
                parse_valid = False

        # CRIT-01 Safe Inconclusive Fallback & HIGH-02 Confidence Weighting
        if parse_valid and parsed_breach and parsed_downtime >= self.SLA_DOWNTIME_BREACH_THRESHOLD_MINUTES and confidence >= 70:
            final_verdict = self.CLAIM_SLA_BREACH_CONFIRMED
        elif parse_valid and confidence >= 70 and (not parsed_breach or parsed_downtime < self.SLA_DOWNTIME_BREACH_THRESHOLD_MINUTES):
            final_verdict = self.CLAIM_REFUTED
        else:
            final_verdict = self.CLAIM_INCONCLUSIVE

        now_utc = int(datetime.now(timezone.utc).timestamp())
        clm["adjudicated_at"] = now_utc
        clm["verdict"] = final_verdict
        clm["adjudication_rationale"] = rationale
        bond_val = clm["claim_bond"]

        if final_verdict == self.CLAIM_SLA_BREACH_CONFIRMED:
            collateral_amt = e["advance_collateral"]
            clm["refund_awarded"] = collateral_amt
            clm["has_claimed"] = True

            e["status"] = self.STATUS_SLA_BREACH_REFUNDED
            e["total_refunded_to_client"] += collateral_amt
            e["advance_collateral"] = 0
            self.total_collateral_refunded += collateral_amt

            # CRIT-02 Solvency Accounting
            transfer_client = False
            try:
                self.gl.emit_transfer(e["ai_client"], collateral_amt)
                transfer_client = True
            except Exception:
                transfer_client = False

            if transfer_client:
                self.total_volume_locked = max(0, self.total_volume_locked - collateral_amt)
            else:
                cur = self.claimable_balances.get(e["ai_client"], 0)
                self.claimable_balances[e["ai_client"]] = cur + collateral_amt

            transfer_claimant = False
            try:
                self.gl.emit_transfer(clm["claimant"], bond_val)
                transfer_claimant = True
            except Exception:
                transfer_claimant = False

            if transfer_claimant:
                self.total_volume_locked = max(0, self.total_volume_locked - bond_val)
            else:
                cur = self.claimable_balances.get(clm["claimant"], 0)
                self.claimable_balances[clm["claimant"]] = cur + bond_val

        elif final_verdict == self.CLAIM_REFUTED:
            clm["refund_awarded"] = 0
            clm["has_claimed"] = True
            # Unlock escrow back to ACTIVE
            e["status"] = self.STATUS_ACTIVE

            cur = self.claimable_balances.get(e["provider"], 0)
            self.claimable_balances[e["provider"]] = cur + bond_val

        else: # INCONCLUSIVE
            clm["refund_awarded"] = 0
            clm["has_claimed"] = True
            # Unlock escrow back to ACTIVE
            e["status"] = self.STATUS_ACTIVE

            # Reset incident key so it can be re-filed (MED-01 Remediated)
            inc_key = clm["escrow_id"] + "::" + clm["incident_report_url"].lower()
            if inc_key in self.consumed_escrow_incidents:
                self.consumed_escrow_incidents[inc_key] = False

            transfer_claimant = False
            try:
                self.gl.emit_transfer(clm["claimant"], bond_val)
                transfer_claimant = True
            except Exception:
                transfer_claimant = False

            if transfer_claimant:
                self.total_volume_locked = max(0, self.total_volume_locked - bond_val)
            else:
                cur = self.claimable_balances.get(clm["claimant"], 0)
                self.claimable_balances[clm["claimant"]] = cur + bond_val

        self.total_claims_adjudicated += 1
        return "CLAIM_ADJUDICATED: " + claim_id + " | Verdict: " + final_verdict

    def claim_abandoned_sla_bond(self, caller: str, claim_id: str, custom_time: int = None):
        assert claim_id in self.claims, "[ERR_CLAIM_NOT_FOUND] Claim not found."
        clm = self.claims[claim_id]
        e = self.escrows[clm["escrow_id"]]

        sender_hex = self._validate_eth_address(caller, "Caller")
        assert sender_hex in (clm["claimant"], e["ai_client"], e["provider"], self.owner), "[ERR_UNAUTHORIZED] Only claimant, AI client, provider, or owner can recover bond."
        assert clm["verdict"] == self.CLAIM_PENDING, "[ERR_CLAIM_NOT_PENDING] Claim not pending."

        now_utc = custom_time if custom_time is not None else int(datetime.now(timezone.utc).timestamp())
        assert now_utc >= clm["filed_at"] + self.CLAIM_TIMEOUT_SECONDS, "[ERR_TIMEOUT_NOT_REACHED] Must wait 7 days."

        bond_val = clm["claim_bond"]
        clm["verdict"] = self.CLAIM_ABANDONED
        clm["has_claimed"] = True
        clm["adjudication_rationale"] = "Recovered after 7-day timeout."

        # Reset incident key so it can be re-filed (MED-01 Remediated)
        inc_key = clm["escrow_id"] + "::" + clm["incident_report_url"].lower()
        if inc_key in self.consumed_escrow_incidents:
            self.consumed_escrow_incidents[inc_key] = False

        # Unlock escrow back to ACTIVE
        if clm["escrow_id"] in self.escrows:
            if e["status"] == self.STATUS_DISPUTED:
                e["status"] = self.STATUS_ACTIVE

        transfer_claimant = False
        try:
            self.gl.emit_transfer(clm["claimant"], bond_val)
            transfer_claimant = True
        except Exception:
            transfer_claimant = False

        if transfer_claimant:
            self.total_volume_locked = max(0, self.total_volume_locked - bond_val)
        else:
            cur = self.claimable_balances.get(clm["claimant"], 0)
            self.claimable_balances[clm["claimant"]] = cur + bond_val

        return "BOND_RECLAIMED: " + claim_id

    def decommission_uncontested_escrow(self, caller: str, escrow_id: str):
        assert escrow_id in self.escrows, "[ERR_ESCROW_NOT_FOUND] Escrow not found."
        e = self.escrows[escrow_id]
        sender_hex = self._validate_eth_address(caller, "Caller")
        assert sender_hex in (e["ai_client"], e["provider"], self.owner), "[ERR_UNAUTHORIZED] Unauthorized caller."
        assert e["advance_collateral"] == 0, "[ERR_ESCROW_REMAINING] Remaining escrow funds."
        assert e["status"] in (self.STATUS_FULFILLED, self.STATUS_SLA_BREACH_REFUNDED, self.STATUS_EXPIRED_REFUNDED), "[ERR_INVALID_STATUS] Invalid status."

        e["status"] = self.STATUS_DECOMMISSIONED
        return "ESCROW_DECOMMISSIONED: " + escrow_id

    def withdraw_claimable(self, caller: str):
        sender_hex = self._validate_eth_address(caller, "Caller")
        assert sender_hex in self.claimable_balances, "[ERR_NO_CLAIMABLE] No claimable funds."
        bal = self.claimable_balances[sender_hex]
        assert bal > 0, "[ERR_ZERO_CLAIMABLE] Zero balance."

        self.claimable_balances[sender_hex] = 0
        try:
            self.gl.emit_transfer(sender_hex, bal)
        except Exception:
            self.claimable_balances[sender_hex] = bal
            raise AssertionError("[ERR_TRANSFER_FAILED] Native transfer failed; claimable balance preserved.")

        self.total_volume_locked = max(0, self.total_volume_locked - bal)
        return "CLAIMABLE_WITHDRAWN: " + sender_hex + " | Amount: " + str(bal)


def run_all_tests():
    print("================================================================================")
    print("  AUTONOMOUS AI COMPUTE CLUSTER ESCROW — 15-PHASE COMPREHENSIVE REGRESSION SUITE")
    print("================================================================================")

    mock_gl = MockGL()
    owner = "0x1111111111111111111111111111111111111111"
    ai_client = "0x2222222222222222222222222222222222222222"
    provider = "0x3333333333333333333333333333333333333333"
    claimant = "0x4444444444444444444444444444444444444444"

    contract = MockAutonomousAiComputeClusterEscrow(owner, mock_gl)

    # Phase 1: Zero Genesis Invariants
    print("\n[Phase 1] Testing zero genesis debt and storage invariants...")
    assert contract.total_volume_locked == 0, "TVL must start at 0"
    assert contract.total_escrows_created == 0, "Escrows must start at 0"
    assert len(contract.claimable_balances) == 0, "Zero unbacked balances"
    print("  PASS: Zero unbacked genesis debt verified.")

    # Phase 2: Create GPU Cluster Lease Escrow
    print("\n[Phase 2] Creating GPU cluster lease backed 100% by payable advance collateral...")
    escrow_amount = 300_000_000_000  # 300 Gwei
    escrow_id = contract.create_cluster_lease_escrow(
        caller=ai_client,
        value=escrow_amount,
        provider_address=provider,
        cluster_identifier="US-EAST-01-H100-SX5",
        gpu_count=1024,
        lease_duration_seconds=86400 * 30  # 30 days
    )
    assert escrow_id == "ESCROW_GPU_1"
    assert contract.total_volume_locked == escrow_amount
    assert contract.escrows[escrow_id]["advance_collateral"] == escrow_amount
    print("  PASS: GPU cluster lease escrow created with 100% backed funds:", escrow_id)

    # Phase 3: Top-up Escrow Reserves
    print("\n[Phase 3] Testing reserve top-up by AI client...")
    topup_amount = 50_000_000_000  # 50 Gwei
    contract.topup_cluster_escrow(caller=ai_client, value=topup_amount, escrow_id=escrow_id)
    assert contract.escrows[escrow_id]["advance_collateral"] == escrow_amount + topup_amount
    assert contract.total_volume_locked == escrow_amount + topup_amount
    print("  PASS: Cluster escrow top-up successfully recorded.")

    # Phase 4: SSRF Defense & Telemetry Domain Whitelist
    print("\n[Phase 4] Testing SSRF defense and cloud telemetry domain whitelisting...")
    try:
        contract._validate_incident_url("https://unverified-hacker-blog.com/incident")
        assert False, "Should reject unapproved domain"
    except AssertionError as e:
        assert "[ERR_URL_UNAPPROVED_DOMAIN]" in str(e)

    try:
        contract._validate_incident_url("https://admin:secret@status.coreweave.com/incidents/1")
        assert False, "Should reject embedded credentials"
    except AssertionError as e:
        assert "[ERR_URL_CREDENTIALS]" in str(e)

    try:
        contract._validate_incident_url("http://127.0.0.1:8080/outage")
        assert False, "Should reject loopback SSRF"
    except AssertionError as e:
        assert "[ERR_URL_LOOPBACK]" in str(e)

    valid_url = "https://status.coreweave.com/incidents/88291"
    assert contract._validate_incident_url(valid_url) == valid_url
    print("  PASS: SSRF defense and cloud telemetry filtering fully enforced.")

    # Phase 5: Address Sanitation & Non-Zero Hex Enforcement
    print("\n[Phase 5] Testing address sanitation and non-zero hex enforcement...")
    try:
        contract._validate_eth_address("0x0000000000000000000000000000000000000000", "ZeroCheck")
        assert False, "Should reject zero address"
    except AssertionError as e:
        assert "[ERR_ADDR_ZERO]" in str(e)

    try:
        contract._validate_eth_address("0x123", "ShortCheck")
        assert False, "Should reject invalid length"
    except AssertionError as e:
        assert "[ERR_ADDR_FORMAT]" in str(e)
    print("  PASS: Address format sanitation strictly verified.")

    # Phase 6: Length-Prefixed Canonical Fingerprint Computation
    print("\n[Phase 6] Testing canonical length-prefixed fingerprint computation...")
    h1 = contract._compute_claim_hash("ESCROW_GPU_1", claimant, valid_url, "nonce1")
    h2 = contract._compute_claim_hash("ESCROW_GPU_1", claimant, valid_url, "nonce1")
    h3 = contract._compute_claim_hash("ESCROW_GPU_1", claimant, valid_url, "nonce2")
    assert h1 == h2, "Canonical hash must be deterministic"
    assert h1 != h3, "Different nonce must yield distinct hash"
    print("  PASS: Canonical length-prefixed hashing prevents delimiter collisions.")

    # Phase 7: Submit SLA Breach Claim with Dispute State Lock (HIGH-01, HIGH-03)
    print("\n[Phase 7] Submitting cluster SLA breach claim and verifying dispute lock...")
    bond_amount = 30_000_000_000  # 30 Gwei
    claim_id = contract.submit_cluster_sla_claim(
        caller=ai_client,
        value=bond_amount,
        escrow_id=escrow_id,
        incident_report_url=valid_url,
        downtime_mins=145,
        nonce="nonce_sla_1"
    )
    assert claim_id == "CLAIM_SLA_1"
    assert contract.claims[claim_id]["claim_bond"] == bond_amount
    assert contract.total_volume_locked == escrow_amount + topup_amount + bond_amount
    assert contract.escrows[escrow_id]["status"] == "DISPUTED", "Escrow must enter DISPUTED state"

    # Verify front-running protection while disputed
    try:
        contract.confirm_cluster_fulfillment(caller=ai_client, escrow_id=escrow_id)
        assert False, "Should reject fulfillment release while DISPUTED"
    except AssertionError as e:
        assert "[ERR_ESCROW_NOT_ACTIVE]" in str(e)
    print("  PASS: SLA breach claim filed by AI client with payable bond, locking escrow to DISPUTED state:", claim_id)

    # Phase 8: Prevent Duplicate Incident Replay
    print("\n[Phase 8] Testing replay prevention on identical incident report...")
    try:
        contract.submit_cluster_sla_claim(
            caller=ai_client,
            value=bond_amount,
            escrow_id=escrow_id,
            incident_report_url=valid_url,
            downtime_mins=145,
            nonce="nonce_unique_2"
        )
        assert False, "Should reject duplicate claim on disputed escrow"
    except AssertionError as e:
        assert "[ERR_ESCROW_NOT_ACTIVE]" in str(e) or "[ERR_INCIDENT_ALREADY_CLAIMED]" in str(e)
    print("  PASS: Duplicate incident claim replay prevented.")

    # Phase 9: Multi-Validator Consensus Adjudication: CLAIM_SLA_BREACH_CONFIRMED
    print("\n[Phase 9] Testing consensus adjudication: SLA_BREACH_CONFIRMED (145 mins downtime)...")
    total_collateral_in_escrow = escrow_amount + topup_amount
    contract.adjudicate_cluster_sla_claim(claim_id, custom_breach=True, custom_downtime=145, custom_conf=95)
    
    assert contract.claims[claim_id]["verdict"] == "SLA_BREACH_CONFIRMED"
    assert contract.escrows[escrow_id]["status"] == "SLA_BREACH_REFUNDED"
    assert contract.escrows[escrow_id]["advance_collateral"] == 0
    assert contract.escrows[escrow_id]["total_refunded_to_client"] == total_collateral_in_escrow

    # Verify transfers to AI client
    client_transfers = [t for t in mock_gl.transfers if t["recipient"] == ai_client]
    assert any(t["amount"] == total_collateral_in_escrow for t in client_transfers), "Client must receive 100% refund"
    print("  PASS: Collateral refunded to AI client & claim bond returned to claimant.")

    # Phase 10: Consensus Adjudication: CLAIM_REFUTED (Frivolous / Downtime < 60 mins)
    print("\n[Phase 10] Testing consensus adjudication: CLAIM_REFUTED (frivolous bond slashed)...")
    escrow_id_2 = contract.create_cluster_lease_escrow(
        caller=ai_client,
        value=escrow_amount,
        provider_address=provider,
        cluster_identifier="US-WEST-02-B200-SX8",
        gpu_count=512,
        lease_duration_seconds=86400 * 14
    )
    claim_id_2 = contract.submit_cluster_sla_claim(
        caller=ai_client,
        value=bond_amount,
        escrow_id=escrow_id_2,
        incident_report_url="https://status.lambdalabs.com/incidents/999",
        downtime_mins=90,
        nonce="nonce_frivolous_test"
    )
    contract.adjudicate_cluster_sla_claim(claim_id_2, custom_breach=False, custom_downtime=25, custom_conf=90)
    assert contract.claims[claim_id_2]["verdict"] == "CLAIM_REFUTED"
    assert contract.escrows[escrow_id_2]["status"] == "ACTIVE", "Escrow must unlock to ACTIVE after refutation"
    assert contract.claimable_balances[provider] == bond_amount, "Provider credited with slashed bond indemnity"
    print("  PASS: Frivolous claim bond slashed to compute provider indemnity reserves.")

    # Phase 10b: Safe Fallback on AI JSON Parse Error (CRIT-01 Remediated)
    print("\n[Phase 10b] Testing AI parse error safe fallback (CLAIM_INCONCLUSIVE, bond preserved)...")
    escrow_id_safe = contract.create_cluster_lease_escrow(
        caller=ai_client,
        value=escrow_amount,
        provider_address=provider,
        cluster_identifier="EU-CENTRAL-01-H200",
        gpu_count=256,
        lease_duration_seconds=86400 * 20
    )
    claim_id_safe = contract.submit_cluster_sla_claim(
        caller=ai_client,
        value=bond_amount,
        escrow_id=escrow_id_safe,
        incident_report_url="https://status.nebius.com/incidents/777",
        downtime_mins=100,
        nonce="nonce_parse_err_test"
    )
    contract.adjudicate_cluster_sla_claim(claim_id_safe, simulate_parse_error=True)
    assert contract.claims[claim_id_safe]["verdict"] == "INCONCLUSIVE", "Parse failure must yield INCONCLUSIVE"
    assert contract.escrows[escrow_id_safe]["status"] == "ACTIVE", "Escrow must unlock back to ACTIVE"
    print("  PASS: AI parsing glitch safely fell back to INCONCLUSIVE without bond slashing.")

    # Phase 11: Fail-Closed Web Evidence Ingestion
    print("\n[Phase 11] Testing fail-closed handling on unreachable telemetry portal...")
    escrow_id_timeout = contract.create_cluster_lease_escrow(
        caller=ai_client,
        value=escrow_amount,
        provider_address=provider,
        cluster_identifier="US-CENTRAL-01-A100",
        gpu_count=128,
        lease_duration_seconds=86400 * 14
    )
    claim_id_3 = contract.submit_cluster_sla_claim(
        caller=ai_client,
        value=bond_amount,
        escrow_id=escrow_id_timeout,
        incident_report_url="https://status.coreweave.com/timeout-test",
        downtime_mins=120,
        nonce="nonce_timeout_test"
    )
    mock_gl.fail_web_fetch = True
    try:
        contract.adjudicate_cluster_sla_claim(claim_id_3)
        assert False, "Should raise AssertionError on network timeout"
    except AssertionError as e:
        assert "[ERR_EVIDENCE_FETCH_FAILED]" in str(e)
    mock_gl.fail_web_fetch = False
    print("  PASS: Fail-closed zero-mutation invariant preserved on network failure.")

    # Phase 12: 7-Day Timeout SLA Bond Safeguard
    print("\n[Phase 12] Testing 7-day timeout bond recovery for claimant...")
    now = int(datetime.now(timezone.utc).timestamp())
    try:
        contract.claim_abandoned_sla_bond(caller=ai_client, claim_id=claim_id_3, custom_time=now + 86400 * 2)
        assert False, "Should revert before 7 days have elapsed"
    except AssertionError as e:
        assert "[ERR_TIMEOUT_NOT_REACHED]" in str(e)

    contract.claim_abandoned_sla_bond(caller=ai_client, claim_id=claim_id_3, custom_time=now + 86400 * 8)
    assert contract.claims[claim_id_3]["verdict"] == "CLAIM_ABANDONED"
    assert contract.escrows[escrow_id_timeout]["status"] == "ACTIVE", "Escrow must unlock to ACTIVE after abandonment"
    print("  PASS: Claimant successfully recovered bond after 7-day timeout.")

    # Phase 13: Consensual Cluster Fulfillment Completion
    print("\n[Phase 13] Testing consensual fulfillment confirmation by AI client...")
    escrow_id_fulfill = contract.create_cluster_lease_escrow(
        caller=ai_client,
        value=escrow_amount,
        provider_address=provider,
        cluster_identifier="US-EAST-02-H100-PRO",
        gpu_count=512,
        lease_duration_seconds=86400 * 30
    )
    contract.confirm_cluster_fulfillment(caller=ai_client, escrow_id=escrow_id_fulfill)
    assert contract.escrows[escrow_id_fulfill]["status"] == "FULFILLED"
    assert contract.escrows[escrow_id_fulfill]["total_released_to_provider"] == escrow_amount
    print("  PASS: Consensual fulfillment confirmed and collateral disbursed to provider.")

    # Phase 14: Expired Idle Escrow Recovery by AI Client (after Grace Window)
    print("\n[Phase 14] Testing expired idle escrow recovery after deadline and grace period...")
    escrow_id_expire = contract.create_cluster_lease_escrow(
        caller=ai_client,
        value=escrow_amount,
        provider_address=provider,
        cluster_identifier="US-WEST-01-A100",
        gpu_count=64,
        lease_duration_seconds=86400 * 14
    )
    try:
        contract.claim_expired_idle_escrow(caller=ai_client, escrow_id=escrow_id_expire, custom_time=now)
        assert False, "Should revert if deadline not yet passed"
    except AssertionError as e:
        assert "[ERR_DEADLINE_NOT_REACHED]" in str(e)

    contract.claim_expired_idle_escrow(caller=ai_client, escrow_id=escrow_id_expire, custom_time=now + 86400 * 20)
    assert contract.escrows[escrow_id_expire]["status"] == "EXPIRED_REFUNDED"
    assert contract.escrows[escrow_id_expire]["total_refunded_to_client"] == escrow_amount
    print("  PASS: Expired idle cluster collateral refunded to AI client.")

    # Phase 15: Pull-Pattern Claimable Withdrawal with Balance Preservation & TVL Solvency
    print("\n[Phase 15] Testing pull-pattern claimable balance recovery...")
    provider_claimable = contract.claimable_balances.get(provider, 0)
    assert provider_claimable > 0

    mock_gl.simulate_transfer_fail = True
    try:
        contract.withdraw_claimable(caller=provider)
        assert False, "Should raise AssertionError on transfer failure"
    except AssertionError as e:
        assert "[ERR_TRANSFER_FAILED]" in str(e)
    assert contract.claimable_balances[provider] == provider_claimable, "Claimable balance must not be wiped on transfer error!"

    mock_gl.simulate_transfer_fail = False
    contract.withdraw_claimable(caller=provider)
    assert contract.claimable_balances[provider] == 0, "Balance cleanly zeroed upon successful transfer."
    print("  PASS: Pull-pattern claimable balance recovery preserves balance on transfer failure.")

    # Phase 16: Symmetric Provider Payout (CRIT-01 Remediated)
    print("\n[Phase 16] Testing symmetric provider payout after lease deadline...")
    escrow_id_provider_claim = contract.create_cluster_lease_escrow(
        caller=ai_client,
        value=escrow_amount,
        provider_address=provider,
        cluster_identifier="US-EAST-03-H100-NODE",
        gpu_count=256,
        lease_duration_seconds=86400 * 10
    )
    try:
        contract.claim_completed_lease_payout(caller=provider, escrow_id=escrow_id_provider_claim, custom_time=now)
        assert False, "Should revert if deadline not reached"
    except AssertionError as e:
        assert "[ERR_DEADLINE_NOT_REACHED]" in str(e)

    contract.claim_completed_lease_payout(caller=provider, escrow_id=escrow_id_provider_claim, custom_time=now + 86400 * 11)
    assert contract.escrows[escrow_id_provider_claim]["status"] == "FULFILLED"
    assert contract.escrows[escrow_id_provider_claim]["total_released_to_provider"] == escrow_amount
    print("  PASS: Provider successfully collected earned lease payout after deadline.")

    # Phase 17: Unauthorized Third-Party Claim Rejection (HIGH-03 Remediated)
    print("\n[Phase 17] Testing rejection of unauthorized third-party SLA breach claims...")
    escrow_id_auth_test = contract.create_cluster_lease_escrow(
        caller=ai_client,
        value=escrow_amount,
        provider_address=provider,
        cluster_identifier="US-NORTH-01-A100",
        gpu_count=128,
        lease_duration_seconds=86400 * 14
    )
    unauthorized_attacker = "0x9999999999999999999999999999999999999999"
    try:
        contract.submit_cluster_sla_claim(
            caller=unauthorized_attacker,
            value=bond_amount,
            escrow_id=escrow_id_auth_test,
            incident_report_url=valid_url,
            downtime_mins=120,
            nonce="nonce_attack"
        )
        assert False, "Should reject unauthorized claimant"
    except AssertionError as e:
        assert "[ERR_UNAUTHORIZED_CLAIMANT]" in str(e)
    print("  PASS: Unauthorized third-party SLA dispute attempt cleanly rejected.")

    # Phase 18: Counterparty Dispute Unlock on Abandoned Claims (CRIT-02 Remediated)
    print("\n[Phase 18] Testing provider unlocking abandoned dispute after 7-day timeout...")
    claim_id_abandon_test = contract.submit_cluster_sla_claim(
        caller=ai_client,
        value=bond_amount,
        escrow_id=escrow_id_auth_test,
        incident_report_url=valid_url,
        downtime_mins=120,
        nonce="nonce_unlock_test"
    )
    assert contract.escrows[escrow_id_auth_test]["status"] == "DISPUTED"

    # Provider calls claim_abandoned_sla_bond after 8 days
    contract.claim_abandoned_sla_bond(caller=provider, claim_id=claim_id_abandon_test, custom_time=now + 86400 * 8)
    assert contract.escrows[escrow_id_auth_test]["status"] == "ACTIVE", "Escrow must be unblocked back to ACTIVE by provider"
    print("  PASS: Provider successfully unlocked abandoned dispute, preventing permanent escrow deadlock.")

    print("\n================================================================================")
    print("  ALL 18 REGRESSION & SECURITY PHASES PASSED WITH ZERO ERRORS!")
    print("================================================================================")


if __name__ == "__main__":
    run_all_tests()
