"""Proton API client — SRP authentication + calendar PGP operations."""

import base64
import json
import logging
import os
import uuid
from datetime import datetime, timezone

import bcrypt
import httpx
import pgpy

from proton_srp import SRPUser, bcrypt_b64_encode, verify_modulus

log = logging.getLogger(__name__)

BASE_URL = "https://mail.proton.me/api"
SESSION_FILE = "/data/proton_session.json"


class ProtonClient:
    def __init__(self, username: str, password: str, mailbox_password: str):
        self.username = username
        self.password = password
        self.mailbox_password = mailbox_password

        self.uid: str | None = None
        self.access_token: str | None = None
        self.refresh_token: str | None = None

        self._http = httpx.Client(
            base_url=BASE_URL,
            headers={
                "x-pm-apiversion": "3",
                "x-pm-appversion": "Other",
                "Content-Type": "application/json",
            },
            timeout=30.0,
            follow_redirects=True,
        )

        # Key caches (invalidated on re-auth)
        self._salted_key_passphrase: bytes | None = None  # bcrypt-derived, cached on disk
        self._address_key: pgpy.PGPKey | None = None
        self._address_passphrase: bytes | None = None
        self._calendar_keys: dict = {}  # cal_id → (PGPKey, passphrase_bytes)

        self._load_session()

    # ── Session persistence ───────────────────────────────────────────────────

    def _load_session(self) -> None:
        try:
            with open(SESSION_FILE) as f:
                data = json.load(f)
            self.uid = data.get("UID")
            self.access_token = data.get("AccessToken")
            self.refresh_token = data.get("RefreshToken")
            skp = data.get("SaltedKeyPass")
            if skp:
                self._salted_key_passphrase = base64.b64decode(skp)
            self._set_auth_headers()
            log.debug("Loaded Proton session from %s", SESSION_FILE)
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    def _save_session(self) -> None:
        os.makedirs(os.path.dirname(SESSION_FILE), exist_ok=True)
        data: dict = {
            "UID": self.uid,
            "AccessToken": self.access_token,
            "RefreshToken": self.refresh_token,
        }
        if self._salted_key_passphrase is not None:
            data["SaltedKeyPass"] = base64.b64encode(self._salted_key_passphrase).decode()
        with open(SESSION_FILE, "w") as f:
            json.dump(data, f)

    def _set_auth_headers(self) -> None:
        if self.uid:
            self._http.headers["x-pm-uid"] = self.uid
        if self.access_token:
            self._http.headers["Authorization"] = f"Bearer {self.access_token}"

    # ── HTTP layer ────────────────────────────────────────────────────────────

    def _request(self, method: str, path: str, **kwargs) -> dict:
        if not self.access_token:
            self.authenticate()

        resp = self._http.request(method, path, **kwargs)
        if resp.status_code == 401:
            self._refresh()
            resp = self._http.request(method, path, **kwargs)

        resp.raise_for_status()
        data = resp.json()

        code = data.get("Code", 1000)
        if code not in (1000, 1001):
            raise RuntimeError(
                f"Proton API error {code}: {data.get('Error', 'unknown')}"
            )
        return data

    def _refresh(self) -> None:
        try:
            resp = self._http.post(
                "/auth/refresh",
                json={
                    "UID": self.uid,
                    "RefreshToken": self.refresh_token,
                    "ResponseType": "token",
                    "GrantType": "refresh_token",
                    "RedirectURI": "https://protonmail.com",
                },
            )
            data = resp.json()
            if resp.status_code == 200 and data.get("Code") == 1000:
                self.access_token = data["AccessToken"]
                self.refresh_token = data.get("RefreshToken", self.refresh_token)
                self._save_session()
                self._set_auth_headers()
                log.debug("Token refreshed")
                return
        except Exception as e:
            log.debug("Token refresh failed: %s", e)
        # Refresh failed → full re-auth
        self.authenticate()

    # ── SRP authentication ────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Full SRP authentication — fetches auth/info, runs SRP, stores tokens."""
        # Clear stale headers and caches
        self._http.headers.pop("x-pm-uid", None)
        self._http.headers.pop("Authorization", None)
        self._salted_key_passphrase = None
        self._address_key = None
        self._address_passphrase = None
        self._calendar_keys = {}

        # Step 1: auth/info
        resp = self._http.post("/auth/info", json={"Username": self.username})
        resp.raise_for_status()
        info = resp.json()
        if info.get("Code", 0) != 1000:
            raise RuntimeError(f"auth/info failed: {info.get('Error', info)}")

        version = info["Version"]
        modulus_bytes = verify_modulus(info["Modulus"])
        salt = base64.b64decode(info["Salt"])
        server_ephemeral = base64.b64decode(info["ServerEphemeral"])
        srp_session = info["SRPSession"]

        # Step 2: SRP challenge/response
        srp = SRPUser(self.password, modulus_bytes)
        client_ephemeral = srp.get_challenge()
        client_proof = srp.process_challenge(salt, server_ephemeral, version=version)
        if client_proof is None:
            raise ValueError("SRP safety check failed")

        # Step 3: auth
        auth_resp = self._http.post(
            "/auth",
            json={
                "Username": self.username,
                "ClientEphemeral": base64.b64encode(client_ephemeral).decode(),
                "ClientProof": base64.b64encode(client_proof).decode(),
                "SRPSession": srp_session,
                "PersistSession": True,
            },
        )
        auth_resp.raise_for_status()
        auth_data = auth_resp.json()
        if auth_data.get("Code", 0) != 1000:
            raise RuntimeError(
                f"Authentication failed: {auth_data.get('Error', auth_data)}"
            )

        # Step 4: verify server proof
        server_proof = base64.b64decode(auth_data["ServerProof"])
        if not srp.verify_session(server_proof):
            raise ValueError("Server proof mismatch — possible MITM attack")

        self.uid = auth_data["UID"]
        self.access_token = auth_data["AccessToken"]
        self.refresh_token = auth_data["RefreshToken"]
        self._set_auth_headers()
        # /core/v4/keys/salts is only accessible right after fresh SRP auth.
        # Derive and cache the saltedKeyPass now while we still have scope.
        self._fetch_salted_key_passphrase()
        self._save_session()
        log.info("Proton SRP authentication successful")

    # ── PGP key management ────────────────────────────────────────────────────

    def _derive_key_passphrase(self, key_salt_b64: str) -> bytes:
        """Derive PGP key passphrase from mailbox_password + per-key bcrypt salt.

        Equivalent to go-srp's MailboxPassword():
          encodedSalt = bcrypt_b64(keySalt, no_padding)
          hashed = bcrypt("$2y$10$" + encodedSalt, password)
          return hashed[-31:]
        """
        key_salt = base64.b64decode(key_salt_b64 + "==")
        # bcrypt_b64_encode uses standard→bcrypt alphabet; take 22 chars (no padding)
        salt_encoded = bcrypt_b64_encode(key_salt)[:22]
        bcrypt_salt = b"$2y$10$" + salt_encoded
        hashed = bcrypt.hashpw(self.mailbox_password.encode("utf-8"), bcrypt_salt)
        return hashed[-31:]  # last 31 bytes = hash portion after "$2y$10$<22-char-salt>"

    def _fetch_salted_key_passphrase(self) -> None:
        """Fetch /core/v4/keys/salts (only available right after fresh SRP auth)
        and derive the saltedKeyPass for the user's primary key."""
        try:
            user_resp = self._http.get("/core/v4/users")
            user_resp.raise_for_status()
            user_keys = user_resp.json().get("User", {}).get("Keys", [])
            primary_key_id = None
            for k in user_keys:
                if k.get("Primary"):
                    primary_key_id = k.get("ID")
                    break
            if not primary_key_id and user_keys:
                primary_key_id = user_keys[0].get("ID")

            salts_resp = self._http.get("/core/v4/keys/salts")
            salts_resp.raise_for_status()
            key_salts = {
                s["ID"]: s.get("KeySalt", "")
                for s in salts_resp.json().get("KeySalts", [])
            }

            key_salt_b64 = key_salts.get(primary_key_id, "") if primary_key_id else ""
            if key_salt_b64:
                self._salted_key_passphrase = self._derive_key_passphrase(key_salt_b64)
                log.debug("Derived saltedKeyPass from key salt")
            else:
                self._salted_key_passphrase = self.mailbox_password.encode("utf-8")
                log.debug("No key salt found; using raw mailbox_password")
        except Exception as e:
            log.warning("Failed to fetch key salts: %s — will re-auth on next key use", e)

    def _get_address_key(self) -> pgpy.PGPKey:
        """Unlock and return the primary address private key using V3 key management.

        Flow:
          1. Use cached saltedKeyPass (fetched right after SRP auth from /core/v4/keys/salts)
          2. GET /core/v4/users → user primary keys; unlock with saltedKeyPass
          3. GET /core/v4/addresses → address keys (each has an encrypted Token)
          4. Decrypt Token with user primary key → address key passphrase
          5. Unlock address key with decrypted passphrase
        """
        if self._address_key is not None:
            return self._address_key

        # If saltedKeyPass is missing (old session without cached salt), force re-auth
        if self._salted_key_passphrase is None:
            log.info("No cached key passphrase — re-authenticating to fetch key salts")
            self.authenticate()
            if self._salted_key_passphrase is None:
                raise RuntimeError("Failed to derive key passphrase after re-auth")

        salted_kp = self._salted_key_passphrase

        # Step 1: unlock user primary key
        user_data = self._request("GET", "/core/v4/users")
        user_keys = user_data.get("User", {}).get("Keys", [])

        user_key: pgpy.PGPKey | None = None
        for ki in user_keys:
            pem = ki.get("PrivateKey")
            if not pem:
                continue
            try:
                key, _ = pgpy.PGPKey.from_blob(pem)
                with key.unlock(salted_kp):
                    pass
                user_key = key
                log.debug("Unlocked user primary key %s", ki.get("ID", ""))
                break
            except Exception as e:
                log.debug("User key %s unlock failed: %s", ki.get("ID", ""), e)

        if user_key is None:
            raise RuntimeError(
                "Could not unlock user primary key — check PROTON_MAILBOX_PASSWORD"
            )

        # Step 2: unlock address key via its Token (V3 key management)
        addr_data = self._request("GET", "/core/v4/addresses")
        for addr in addr_data.get("Addresses", []):
            for ki in addr.get("Keys", []):
                pem = ki.get("PrivateKey")
                token_armored = ki.get("Token")
                if not pem:
                    continue
                try:
                    addr_key, _ = pgpy.PGPKey.from_blob(pem)
                    if token_armored:
                        # V3: Token is PGP-encrypted to the user's primary key
                        with user_key.unlock(salted_kp) as unlocked_user:
                            token_msg = pgpy.PGPMessage.from_blob(token_armored)
                            decrypted = unlocked_user.decrypt(token_msg)
                            addr_passphrase = decrypted.message
                            if isinstance(addr_passphrase, str):
                                addr_passphrase = addr_passphrase.encode("utf-8")
                        with addr_key.unlock(addr_passphrase):
                            pass
                        self._address_key = addr_key
                        self._address_passphrase = addr_passphrase
                        log.debug("Unlocked address key via Token")
                        return addr_key
                    elif addr_key.is_protected:
                        # Older accounts: address key encrypted with saltedKeyPass directly
                        with addr_key.unlock(salted_kp):
                            pass
                        self._address_key = addr_key
                        self._address_passphrase = salted_kp
                        return addr_key
                    else:
                        self._address_key = addr_key
                        self._address_passphrase = b""
                        return addr_key
                except Exception as e:
                    log.warning("Address key unlock failed (%s): %s", type(e).__name__, e)

        raise RuntimeError(
            "No usable address private key found — check PROTON_MAILBOX_PASSWORD"
        )

    def _get_calendar_keyring(self, cal_id: str) -> tuple:
        """Return (locked_cal_key, passphrase_bytes) for the given calendar."""
        if cal_id in self._calendar_keys:
            return self._calendar_keys[cal_id]

        addr_key = self._get_address_key()

        # Decrypt calendar passphrase with address key
        pass_data = self._request("GET", f"/calendar/v1/{cal_id}/passphrase")
        cal_passphrase: bytes | None = None
        for mp in pass_data.get("Passphrase", {}).get("MemberPassphrases", []):
            pem_pass = mp.get("Passphrase")
            if not pem_pass:
                continue
            try:
                with addr_key.unlock(self._address_passphrase) as unlocked_addr:
                    msg = pgpy.PGPMessage.from_blob(pem_pass)
                    decrypted = unlocked_addr.decrypt(msg)
                    cal_passphrase = decrypted.message
                    if isinstance(cal_passphrase, str):
                        cal_passphrase = cal_passphrase.encode()
                    break
            except Exception as e:
                log.debug("Passphrase entry failed (%s): %s", type(e).__name__, e)

        if cal_passphrase is None:
            raise RuntimeError(f"Could not decrypt calendar passphrase for {cal_id}")

        # Load and unlock-test the calendar private key
        keys_data = self._request("GET", f"/calendar/v1/{cal_id}/keys")
        for ki in keys_data.get("Keys", []):
            pem = ki.get("PrivateKey")
            if not pem:
                continue
            try:
                cal_key, _ = pgpy.PGPKey.from_blob(pem)
                with cal_key.unlock(cal_passphrase):
                    pass
                self._calendar_keys[cal_id] = (cal_key, cal_passphrase)
                return cal_key, cal_passphrase
            except Exception as e:
                log.debug("Calendar key unlock failed: %s", e)

        raise RuntimeError(f"Could not unlock any calendar key for {cal_id}")

    # ── Event encryption / decryption ─────────────────────────────────────────

    def _decrypt_event_content(
        self,
        cal_key: pgpy.PGPKey,
        cal_passphrase: bytes,
        shared_key_packet_b64: str,
        data_b64: str,
    ) -> dict:
        """Decrypt a Proton Calendar event by combining SharedKeyPacket + Data.

        Proton stores the PGP PKESK in SharedKeyPacket and the SEIPD (encrypted
        body) in SharedEvents[type=1].Data.  They must be concatenated to form a
        valid PGP message before decryption.
        """
        pkesk = base64.b64decode(shared_key_packet_b64 + "==")
        seipd = base64.b64decode(data_b64 + "==")
        msg = pgpy.PGPMessage.from_blob(pkesk + seipd)

        with cal_key.unlock(cal_passphrase) as unlocked_cal:
            decrypted = unlocked_cal.decrypt(msg)

        content = decrypted.message
        if isinstance(content, (bytes, bytearray)):
            content = bytes(content).decode("utf-8", errors="replace")

        # Parse iCalendar text (Proton stores event content as iCal inside the PGP)
        result: dict = {}
        current_key: str | None = None
        current_val: list[str] = []
        for raw_line in content.splitlines():
            if raw_line.startswith(" ") or raw_line.startswith("\t"):
                # Folded continuation line
                current_val.append(raw_line[1:])
                continue
            # Flush previous property
            if current_key is not None:
                val = "".join(current_val).strip()
                if current_key == "SUMMARY":
                    result["summary"] = val
                elif current_key == "DESCRIPTION":
                    result["description"] = val
                elif current_key == "LOCATION":
                    result["location"] = val
            current_key = None
            current_val = []
            for prefix, rkey in (("SUMMARY:", "SUMMARY"), ("DESCRIPTION:", "DESCRIPTION"), ("LOCATION:", "LOCATION")):
                if raw_line.startswith(prefix):
                    current_key = rkey
                    current_val = [raw_line[len(prefix):]]
                    break
        # Flush last property
        if current_key is not None:
            val = "".join(current_val).strip()
            result.setdefault(current_key.lower(), val)
        return result

    def _encrypt_and_sign_event_content(
        self,
        cal_key: pgpy.PGPKey,
        addr_key: pgpy.PGPKey,
        addr_passphrase: bytes,
        vevent_json: str,
    ) -> tuple[str, str, str]:
        """Encrypt event JSON with the calendar public key and sign with the address key.

        Returns (shared_key_packet_b64, data_packet_b64, signature_b64).
        Proton stores the PKESK in SharedKeyPacket, the SEIPD in Data, and a
        detached address-key signature in Signature.
        """
        msg = pgpy.PGPMessage.new(vevent_json)
        encrypted = cal_key.pubkey.encrypt(msg)

        # Split PKESK (session key packet) from SEIPD (data packet).
        pkesk_bytes = b"".join(bytes(sk) for sk in encrypted._sessionkeys)
        full_bytes = bytes(encrypted)
        seipd_bytes = full_bytes[len(pkesk_bytes):]

        # Detached signature of the plaintext, signed with the address key.
        # Proton expects an ASCII-armored PGP signature string (not base64 binary).
        with addr_key.unlock(addr_passphrase) as unlocked_addr:
            sig = unlocked_addr.sign(vevent_json)
        sig_armored = str(sig)  # "-----BEGIN PGP SIGNATURE-----\n...\n-----END PGP SIGNATURE-----"

        return (
            base64.b64encode(pkesk_bytes).decode(),
            base64.b64encode(seipd_bytes).decode(),
            sig_armored,
        )

    # ── Public calendar API ───────────────────────────────────────────────────

    def list_events(self, start_iso: str, end_iso: str) -> list[dict]:
        """Fetch and decrypt all calendar events in the given UTC range."""
        start_ts = int(
            datetime.fromisoformat(start_iso.replace("Z", "+00:00")).timestamp()
        )
        end_ts = int(
            datetime.fromisoformat(end_iso.replace("Z", "+00:00")).timestamp()
        )


        cals_data = self._request("GET", "/calendar/v1")
        calendars = cals_data.get("Calendars", [])

        all_events: list[dict] = []
        for cal in calendars:
            cal_id = cal["ID"]
            # Calendar name is inside Members[0].Name (per Proton API structure)
            cal_name = cal.get("Members", [{}])[0].get("Name", "") or cal.get("Name", "")
            try:
                cal_key, cal_passphrase = self._get_calendar_keyring(cal_id)
            except Exception as e:
                log.warning("Skipping calendar %r: %s", cal_name, e)
                continue

            events_data = self._request(
                "GET",
                f"/calendar/v1/{cal_id}/events",
                params={
                    "Page": 0,
                    "PageSize": 100,
                    "StartTime": start_ts,
                    "EndTime": end_ts,
                },
            )

            for event in events_data.get("Events", []):
                event_id = event["ID"]
                start_time = event.get("StartTime", 0)
                end_time = event.get("EndTime", 0)
                tz = event.get("StartTimezone", "UTC")
                shared_key_pkt = event.get("SharedKeyPacket", "")

                details: dict = {}
                # SharedEvents types:
                #   0 = external-invite plaintext iCal (fallback)
                #   1 = external-invite encrypted body (SharedKeyPacket + SEIPD)
                #   2 = native-event plaintext iCal (fallback)
                #   3 = native-event encrypted body (SharedKeyPacket + SEIPD)
                plain_ical: str = ""
                for content in event.get("SharedEvents", []):
                    ctype = content.get("Type")
                    raw = content.get("Data") or ""
                    if ctype in (1, 3) and raw and shared_key_pkt:
                        try:
                            details = self._decrypt_event_content(
                                cal_key, cal_passphrase, shared_key_pkt, raw
                            )
                            break
                        except Exception as e:
                            log.debug(
                                "Cannot decrypt event %s in %s: %s",
                                event_id, cal_name, e,
                            )
                    elif ctype in (0, 2) and raw and not plain_ical:
                        plain_ical = raw  # save as fallback

                # Fallback: parse plaintext iCal from external invites
                if not details and plain_ical:
                    for line in plain_ical.splitlines():
                        if line.startswith("SUMMARY:"):
                            details["summary"] = line[8:].strip()
                        elif line.startswith("DESCRIPTION:"):
                            details["description"] = line[12:].strip()
                        elif line.startswith("LOCATION:"):
                            details["location"] = line[9:].strip()

                # Client-side date range filter (API ignores StartTime/EndTime params)
                if start_time > end_ts or end_time < start_ts:
                    continue

                all_events.append(
                    {
                        "id": f"{cal_id}/{event_id}",
                        "calendar": cal_name,
                        "title": details.get("summary", "(encrypted)"),
                        "description": details.get("description", ""),
                        "location": details.get("location", ""),
                        "start": datetime.fromtimestamp(
                            start_time, tz=timezone.utc
                        ).isoformat(),
                        "end": datetime.fromtimestamp(
                            end_time, tz=timezone.utc
                        ).isoformat(),
                        "timezone": tz,
                    }
                )

        all_events.sort(key=lambda e: e["start"])
        return all_events

    def _build_ical(
        self,
        uid: str,
        dtstamp: str,
        dtstart: str,
        dtend: str,
        title: str | None = None,
        description: str | None = None,
        location: str | None = None,
        include_timing: bool = True,
        include_content: bool = True,
    ) -> str:
        """Build an iCalendar VCALENDAR string.

        Proton splits the event into two parts:
          - Type 2 (plaintext): timing fields only (DTSTART, DTEND, SEQUENCE)
          - Type 3 (encrypted): content fields (SUMMARY, DESCRIPTION, LOCATION) + UID/DTSTAMP
        """
        lines = [
            "BEGIN:VCALENDAR",
            "VERSION:2.0",
            "PRODID:-//MCP Proton//ProtonCalendar//EN",
            "BEGIN:VEVENT",
            f"UID:{uid}@proton.me",
            f"DTSTAMP:{dtstamp}",
        ]
        if include_timing:
            lines.append(f"DTSTART:{dtstart}")
            lines.append(f"DTEND:{dtend}")
            lines.append("SEQUENCE:0")
        if include_content:
            if title:
                lines.append(f"SUMMARY:{title}")
            if description:
                lines.append(f"DESCRIPTION:{description}")
            if location:
                lines.append(f"LOCATION:{location}")
        lines += ["END:VEVENT", "END:VCALENDAR"]
        return "\r\n".join(lines) + "\r\n"

    def create_event(
        self,
        title: str,
        start: str,
        end: str,
        description: str | None = None,
        location: str | None = None,
    ) -> str:
        """Create an event in the primary personal calendar. Returns '{calID}/{eventID}'.

        Uses PUT /calendar/v1/{calendarID}/events/sync (Proton's batch sync endpoint).

        Proton Calendar event structure:
          SharedKeyPacket: PKESK (encrypted session key)
          SharedEvents[Type 2]: Plaintext iCal with timing only (DTSTART/DTEND), signed
          SharedEvents[Type 3]: Encrypted iCal with content (SUMMARY etc.), signed
        """
        cals_data = self._request("GET", "/calendar/v1")
        calendars = cals_data.get("Calendars", [])
        # Choose the calendar with highest member permissions (owner/admin)
        cal = None
        for c in calendars:
            members = c.get("Members", [])
            if members and members[0].get("Permissions", 0) >= 96:
                cal = c
                break
        if cal is None:
            cal = calendars[0] if calendars else None
        if cal is None:
            raise RuntimeError("No calendars found in your Proton account")

        cal_id = cal["ID"]
        member_id = cal["Members"][0]["ID"]
        cal_key, _ = self._get_calendar_keyring(cal_id)
        addr_key = self._get_address_key()

        start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
        start_ts = int(start_dt.timestamp())
        end_ts = int(end_dt.timestamp())
        dtstart = start_dt.strftime("%Y%m%dT%H%M%SZ")
        dtend = end_dt.strftime("%Y%m%dT%H%M%SZ")
        dtstamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        uid = str(uuid.uuid4())

        # Type 2: plaintext iCal (timing fields only)
        ical_plain = self._build_ical(
            uid, dtstamp, dtstart, dtend,
            include_timing=True, include_content=False,
        )
        # Type 3: content iCal (content fields only, no DTSTART/DTEND)
        ical_content = self._build_ical(
            uid, dtstamp, dtstart, dtend,
            title=title, description=description, location=location,
            include_timing=False, include_content=True,
        )

        # Encrypt content and generate detached signatures
        shared_key_pkt, data_pkt, sig3 = self._encrypt_and_sign_event_content(
            cal_key, addr_key, self._address_passphrase, ical_content
        )
        # Sign plaintext part with address key
        with addr_key.unlock(self._address_passphrase) as unlocked_addr:
            sig2 = str(unlocked_addr.sign(ical_plain))

        payload = {
            "MemberID": member_id,
            "Events": [
                {
                    "Overwrite": 0,
                    "Event": {
                        "Permissions": 3,
                        "IsOrganizer": 1,
                        "SharedKeyPacket": shared_key_pkt,
                        "SharedEventContent": [
                            {"Type": 2, "Data": ical_plain, "Signature": sig2},
                            {"Type": 3, "Data": data_pkt, "Signature": sig3},
                        ],
                        "CalendarKeyPacket": "",
                        "CalendarEventContent": [],
                        "PersonalEventContent": None,
                        "StartTime": start_ts,
                        "StartTimezone": "UTC",
                        "EndTime": end_ts,
                        "EndTimezone": "UTC",
                        "FullDay": 0,
                        "Attendees": [],
                    },
                }
            ],
        }

        result = self._request("PUT", f"/calendar/v1/{cal_id}/events/sync", json=payload)
        # Response: {"Responses": [{"Index": 0, "Response": {"Code": 1000, "Event": {...}}}]}
        responses = result.get("Responses", [])
        if not responses:
            raise RuntimeError(f"Event sync returned no responses: {result}")
        event_resp = responses[0].get("Response", {})
        if event_resp.get("Code", 0) not in (1000, 1001):
            raise RuntimeError(
                f"Event creation failed: {event_resp.get('Error', event_resp)}"
            )
        event_id = event_resp.get("Event", {}).get("ID")
        if not event_id:
            raise RuntimeError(f"Event sync response has no event ID: {event_resp}")
        return f"{cal_id}/{event_id}"

    def delete_event(self, calendar_id: str, event_id: str) -> None:
        """Delete a calendar event via the sync endpoint."""
        # Resolve member ID for this calendar
        cals_data = self._request("GET", "/calendar/v1")
        member_id = ""
        for c in cals_data.get("Calendars", []):
            if c["ID"] == calendar_id:
                member_id = c["Members"][0]["ID"]
                break
        if not member_id:
            raise RuntimeError(f"Calendar {calendar_id!r} not found or has no members")

        payload = {
            "MemberID": member_id,
            "Events": [{"ID": event_id}],
        }
        result = self._request(
            "PUT", f"/calendar/v1/{calendar_id}/events/sync", json=payload
        )
        # Code 1001 with empty Responses = batch success (delete confirmed)
        responses = result.get("Responses", [])
        if responses:
            event_resp = responses[0].get("Response", {})
            code = event_resp.get("Code", 0)
            if code not in (1000, 1001):
                raise RuntimeError(
                    f"Event deletion failed: {event_resp.get('Error', event_resp)}"
                )
