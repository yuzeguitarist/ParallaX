#!/usr/bin/env python3
"""The formal checker finds a planted illegal transition, and the real model is clean."""

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

import plx_formal


class FormalModelTests(unittest.TestCase):
    def test_real_model_holds_and_matches_tla(self):
        reports = plx_formal.check_all()
        names = {report.name: report.states for report in reports}
        self.assertEqual(
            names,
            {
                "ParallaXSession": 63,
                "ParallaXQuic": 140,
                "ParallaXZeroRtt": 352,
                "ParallaXReplay": 26,
                "ParallaXProbe": 224,
                "ParallaXInbound": 32,
                "ParallaXKeys": 136,
                "ParallaXClose": 21,
                "ParallaXBbr": 56,
                "ParallaXPacket": 14,
            },
        )
        for machine in plx_formal.machines():
            got = {item.name: item.formula for item in machine.invariants}
            self.assertEqual(got, EXPECTED_INVARIANTS[machine.name])

    def test_stale_insert_classified_as_replay_is_rejected(self):
        machine = plx_formal.replay_machine()
        bug = plx_formal.act(
            "StaleLooksLikeReplay",
            'prot = "on" /\\ n < 2',
            kind='"stale"',
            last='"replayed"',
            stored="FALSE",
            n="n + 1",
        )
        broken = replace(machine, actions=machine.actions + (bug,))
        with self.assertRaises(plx_formal.FormalError) as caught:
            plx_formal.check_machine(broken)
        message = str(caught.exception)
        self.assertIn("StaleIsNotAReplay", message)
        self.assertIn("StaleLooksLikeReplay", message)

    def test_bad_mac_cannot_retain_quic(self):
        machine = plx_formal.probe_machine()
        bug = plx_formal.act(
            "RetainBadMac",
            'obs = "bad_mac" /\\ outcome = "pending"',
            outcome='"verified"',
            decision='"retain"',
            status='"verified"',
        )
        broken = replace(machine, actions=machine.actions + (bug,))
        with self.assertRaises(plx_formal.FormalError) as caught:
            plx_formal.check_machine(broken)
        message = str(caught.exception)
        self.assertIn("VerifiedOnlyIfAuthentic", message)
        self.assertIn("RetainBadMac", message)

    def test_bbr_loss_cannot_reenter_startup_full(self):
        machine = plx_formal.bbr_machine()
        bug = plx_formal.act(
            "LossResetsStartup",
            'mode = "probe_bw"',
            mode='"startup"',
            loss="TRUE",
        )
        broken = replace(machine, actions=machine.actions + (bug,))
        with self.assertRaises(plx_formal.FormalError) as caught:
            plx_formal.check_machine(broken)
        message = str(caught.exception)
        self.assertIn("StartupIsUnfilled", message)
        self.assertIn("LossResetsStartup", message)

    def test_app_data_before_identity_is_rejected(self):
        machine = plx_formal.session_machine()
        bug = plx_formal.act(
            "AppBeforeIdentity",
            'phase = "epoch0"',
            phase='"app"',
            app="TRUE",
        )
        broken = replace(machine, actions=machine.actions + (bug,))
        with self.assertRaises(plx_formal.FormalError) as caught:
            plx_formal.check_machine(broken)
        message = str(caught.exception)
        self.assertIn("AppOnlyAfterIdentity", message)
        self.assertIn("AppBeforeIdentity", message)

    def test_second_ticket_accept_is_rejected(self):
        machine = plx_formal.zero_rtt_machine()
        bug = plx_formal.act(
            "SecondAccept",
            "accepts = 1",
            accepts="accepts + 1",
            early="FALSE",
        )
        broken = replace(machine, actions=machine.actions + (bug,))
        with self.assertRaises(plx_formal.FormalError) as caught:
            plx_formal.check_machine(broken)
        message = str(caught.exception)
        self.assertIn("AcceptsAtMostOnce", message)
        self.assertIn("SecondAccept", message)

    def test_formula_parses_implication_and_membership(self):
        compiled = plx_formal.formula(
            'app => (phase = "app" /\\ epoch \\in {0, 1} /\\ ~binding)'
        )
        self.assertTrue(
            compiled.holds({"app": False, "phase": "idle", "epoch": 0, "binding": True})
        )
        self.assertTrue(
            compiled.holds({"app": True, "phase": "app", "epoch": 1, "binding": False})
        )
        self.assertFalse(
            compiled.holds({"app": True, "phase": "app", "epoch": 1, "binding": True})
        )

    def test_readme_names_every_invariant(self):
        text = (plx_formal.FORMAL / "README.md").read_text()
        for machine in plx_formal.machines():
            for item in machine.invariants:
                self.assertIn(item.name, text)

    def test_workflows_run_the_checker(self):
        formal = (plx_formal.ROOT / ".github/workflows/formal.yml").read_text()
        self.assertIn("python3 formal/plx_formal.py check", formal)
        self.assertIn("python3 formal/plx_formal.py correspond", formal)
        self.assertIn("python3 formal/plx_formal.py tlc --jar tla2tools.jar", formal)
        self.assertIn(
            "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88",
            formal,
        )
        ci = (plx_formal.ROOT / ".github/workflows/ci-pr.yml").read_text()
        self.assertIn("python3 -m unittest discover -s formal -p 'test_*.py'", ci)

    def test_ledger_matches_the_tree_and_rejects_a_new_file(self):
        plx_formal.check_ledger()
        files = plx_formal.rust_sources()
        files.add("src/brand_new.rs")
        with self.assertRaises(plx_formal.FormalError) as caught:
            plx_formal.check_ledger(files=files)
        self.assertIn("src/brand_new.rs", str(caught.exception))

    def test_correspondence_holds_and_catches_a_reorder(self):
        plx_formal.correspond()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for relative in plx_formal.CORRESPOND_FILES:
                source = plx_formal.ROOT / relative
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(source.read_text())
            runtime = root / "src/client/runtime.rs"
            runtime.write_text(
                runtime.read_text().replace(
                    "verify_server_identity_payload_blocking(",
                    "identity_check_removed(",
                    1,
                )
            )
            with self.assertRaises(plx_formal.FormalError) as caught:
                plx_formal.correspond(root)
        self.assertIn("verify_server_identity_payload_blocking", str(caught.exception))

    def test_extract_fn_does_not_bind_a_longer_name(self):
        src = (
            "fn insert_new_outcome_deferred() {\n"
            "    deferred_body\n"
            "}\n"
            "fn insert_new_outcome() {\n"
            "    immediate_body\n"
            "}\n"
        )
        body = plx_formal._extract_fn(src, "insert_new_outcome")
        self.assertIn("immediate_body", body)
        self.assertNotIn("deferred_body", body)
        generic = "fn probe_client_read_and_verify<T>(x: T) {\n    verify_body\n}\n"
        self.assertIn("verify_body", plx_formal._extract_fn(generic, "probe_client_read_and_verify"))


EXPECTED_INVARIANTS = {
    "ParallaXSession": {
        "AppOnlyAfterIdentity": 'app => (phase = "app" /\\ binding /\\ epoch = 1 /\\ usable /\\ keys)',
        "VerifiedImpliesBinding": 'phase \\in {"verified", "app"} => (binding /\\ epoch = 1 /\\ keys /\\ usable)',
        "RekeyedImpliesFreshCommit": 'phase = "rekeyed" => (replay = "inserted" /\\ binding /\\ epoch = 1 /\\ usable)',
        "ReplayClosesBeforeRekey": 'replay \\in {"replayed", "stale", "full"} => (phase = "rejected" /\\ epoch = 0 /\\ ~binding /\\ ~app /\\ ~usable)',
        "IdleAndReconnectAreFresh": 'phase = "idle" => (epoch = 0 /\\ ~binding /\\ ~keys /\\ ~usable /\\ ~app /\\ udp = "none" /\\ replay = "none" /\\ how = "none")',
        "AuthedHasNoKeys": 'phase = "authed" => (epoch = 0 /\\ ~keys /\\ ~usable /\\ ~binding /\\ how = "none")',
        "PostAuthDegenerateDoesNotSplice": 'how = "degen" => (phase = "failed" /\\ ~keys /\\ ~usable /\\ epoch = 0 /\\ ~binding /\\ ~app)',
        "RekeyDegenerateStaysAtEpochZero": 'how = "rekey_degen" => (phase = "failed" /\\ epoch = 0 /\\ keys /\\ ~usable /\\ ~binding /\\ ~app /\\ replay = "inserted")',
        "SpliceIsTheInboundReject": 'how = "splice" => (phase = "failed" /\\ ~keys /\\ epoch = 0 /\\ ~binding)',
        "TerminalDropsUsableKeys": 'phase \\in {"rejected", "closed", "failed"} => (~usable /\\ ~app /\\ udp = "none")',
        "UdpRetainOnlyAfterApp": 'udp = "retained" => (phase = "app" /\\ app /\\ usable)',
        "UdpDeclineStaysOnApp": 'udp = "tcp_only" => (phase = "app" /\\ app /\\ usable)',
        "UsableKeysImplyAuth": '(usable => keys) /\\ (keys => (phase # "idle"))',
        "EpochIsZeroOrOne": "epoch \\in {0, 1}",
        "RejectedOnlyAfterReplay": 'phase = "rejected" => replay \\in {"replayed", "stale", "full"}',
        "BindingMeansRekeyedEpoch": 'binding => (epoch = 1 /\\ replay = "inserted" /\\ phase \\in {"rekeyed", "verified", "app", "closed", "failed"})',
        "AttemptInBounds": "attempt \\in {0, 1, 2}",
    },
    "ParallaXQuic": {
        "CompleteOnlyAfterFinished": 'complete => (client = "done" /\\ saw_fin /\\ ~client_alert)',
        "ServerCompleteOnlyAfterBothMessages": 'server_complete => (server = "done" /\\ saw_ch /\\ saw_sfin /\\ ~server_alert)',
        "ResumptionSkipsCertificate": "complete /\\ psk => (~saw_cert /\\ ~saw_cv)",
        "FullHandshakeSeesCertificate": "complete /\\ ~psk => (saw_cert /\\ saw_cv /\\ saw_fin)",
        "AlertBeforeCompleteIsNotSuccess": 'client = "alert" => (client_alert /\\ ~complete /\\ ~post_alert)',
        "AlertAfterCompleteDoesNotUndo": 'post_alert => (complete /\\ client = "done" /\\ saw_fin /\\ ~client_alert)',
        "ServerAlertIsNotComplete": 'server = "alert" => (server_alert /\\ ~server_complete /\\ ~server_post_alert)',
        "ServerAlertAfterCompleteDoesNotUndo": 'server_post_alert => (server_complete /\\ server = "done" /\\ saw_sfin /\\ ~server_alert /\\ server_ticket)',
        "VerifyFollowsCertificate": "saw_cv => saw_cert",
        "PskNeverEntersCertificate": 'psk => (~saw_cert /\\ ~saw_cv /\\ client # "cert" /\\ client # "cv")',
        "TicketOnlyAfterComplete": 'nst => (complete /\\ client = "done")',
        "ServerTicketOnlyAfterComplete": 'server_ticket => (server_complete /\\ server = "done" /\\ saw_sfin)',
    },
    "ParallaXZeroRtt": {
        "EarlyDataRequiresFreshAccept": 'early => (offered /\\ decided /\\ burned /\\ accepts = 1 /\\ binder = "ok" /\\ guard = "free")',
        "FailClosedDoesNotBurnOrAccept": 'guard # "free" => (~early /\\ ~burned /\\ accepts = 0)',
        "BadBinderDoesNotBurnOrAccept": 'binder = "bad" => (~early /\\ ~burned /\\ accepts = 0)',
        "AcceptsAtMostOnce": "accepts \\in {0, 1}",
        "DurableAcceptStaysBurned": "durable => (burned /\\ early /\\ accepts = 1)",
        "RestartUndoesUndurableAccept": "restarted /\\ accepts = 0 => (~burned /\\ ~early /\\ ~durable)",
        "FullOrClashDoesNotBurn": 'reject \\in {"full", "clash"} => (decided /\\ ~burned /\\ ~early /\\ accepts = 0 /\\ guard = "free" /\\ binder = "ok")',
        "RelayWaitsForHandshake": 'relay => (hs /\\ ~dead /\\ probe = "verified" /\\ settings = "ok")',
        "RetainOnlyVerified": 'retained => (probe = "verified" /\\ settings = "ok" /\\ hs /\\ ~dead)',
        "StoreTicketOnlyVerified": 'stored => (probe = "verified" /\\ settings = "ok" /\\ hs /\\ ~dead)',
        "SettingsFailDoesNotStore": 'settings = "bad" => (~stored /\\ ~retained /\\ probe = "settings_fail")',
        "VerifiedProbeImpliesHandshake": 'probe = "verified" => (hs /\\ ~dead)',
        "ReplayDoesNotAcceptAgain": "replay_rejected => (replay_decided /\\ accepts = 1 /\\ burned)",
        "DeadDropsTheAttempt": "dead => (~hs /\\ ~relay /\\ ~retained /\\ ~stored)",
        "DecidedImpliesOffered": "decided => offered",
        "HandshakeFollowsEarlyProbe": 'hs => (probe = "early" \\/ probe = "verified" \\/ probe = "failed" \\/ probe = "settings_fail")',
    },
    "ParallaXReplay": {
        "OffStoresNothing": 'prot = "off" => (slot_n = "none" /\\ slot_t = "none" /\\ ~stored /\\ ~pruned)',
        "SlotIsPaired": '(slot_n = "none" /\\ slot_t = "none") \\/ (slot_n = "a" /\\ slot_t = "ta") \\/ (slot_n = "b" /\\ slot_t = "tb")',
        "InsertRecordsTheCandidate": 'kind = "insert" => (last = "inserted" /\\ stored /\\ cand_n = slot_n /\\ slot_n # "none")',
        "StaleIsNotAReplay": 'kind = "stale" => (last = "stale" /\\ ~stored)',
        "StaleCannotTakeReplay": 'scene \\in {"past", "future"} => kind # "replay"',
        "PastAndFutureAreStale": 'scene \\in {"past", "future"} /\\ n = 2 => (kind = "stale" /\\ last = "stale")',
        "EdgeAndSkewAreFresh": 'scene \\in {"edge", "skew"} /\\ n = 2 => (kind = "replay" /\\ last = "replayed")',
        "ReplayDoesNotRecord": 'kind = "replay" => (last = "replayed" /\\ ~stored /\\ slot_n # "none")',
        "ClashIsNotFull": 'scene = "transcript" => kind # "full"',
        "FullDoesNotEvict": 'kind = "full" => (last = "full" /\\ ~stored /\\ slot_n = "a" /\\ cand_n = "b")',
        "ProtectionOffIsInsert": 'prot = "off" /\\ kind # "none" => (kind = "off" /\\ last = "inserted")',
        "ExpireClearsTheSlot": 'kind = "expire" => (slot_n = "none" /\\ slot_t = "none" /\\ ~stored /\\ pruned)',
    },
    "ParallaXProbe": {
        "VerifiedOnlyIfAuthentic": 'outcome = "verified" => obs = "ok"',
        "BadMacIsFailed": 'obs = "bad_mac" /\\ outcome # "pending" => outcome = "failed"',
        "TimeoutIsUnreachable": 'obs = "timeout" /\\ outcome # "pending" => outcome = "unreachable"',
        "LostConnectionIsUnreachable": 'obs = "lost" /\\ outcome # "pending" => outcome = "unreachable"',
        "ShortReplyIsFailed": 'obs = "short" /\\ outcome # "pending" => outcome = "failed"',
        "LongBodyIsFailed": 'obs = "long" /\\ outcome # "pending" => outcome = "failed"',
        "SetupIsFailed": 'obs = "setup" /\\ outcome # "pending" => outcome = "failed"',
        "RetainOnlyMatchingAck": 'decision = "retain" => (status = "verified" /\\ offer = "match" /\\ have /\\ read = "ok")',
        "VerifiedWithoutConnHardFails": 'decision = "hard_fail" => (status = "verified" /\\ offer = "match" /\\ read = "ok" /\\ ~have)',
        "MismatchStaysOnTcp": 'offer = "mismatch" => (decision = "stay" /\\ read = "ok")',
        "VerifiedStayIsARejectedAck": 'decision = "stay" /\\ status = "verified" => (offer = "mismatch" \\/ read = "decode")',
        "Px1pTimeoutAborts": 'read = "timeout" => decision = "abort"',
        "Px1pEofAborts": 'read = "eof" => decision = "abort"',
    },
    "ParallaXInbound": {
        "MissingSniOnlyAfterAuth": 'gate = "missing" => (record_ok /\\ material /\\ ~has_sni)',
        "UnauthorizedOnlyAfterSni": 'gate = "unauth" => (record_ok /\\ material /\\ has_sni /\\ ~sni_ok)',
        "AuthenticatedClearsEveryGate": 'gate = "ok" => (record_ok /\\ material /\\ has_sni /\\ sni_ok)',
        "AuthFailIsNotASniDecision": 'gate = "auth_fail" => (~record_ok \\/ ~material)',
    },
    "ParallaXKeys": {
        "ClientZeroRttOnlyIfOffered": '(c_zrtt => offer) /\\ (c = "zrtt" => c_zrtt)',
        "ServerZeroRttOnlyIfAccepted": '(s_zrtt => accept) /\\ (s = "zrtt" => s_zrtt)',
        "AcceptImpliesOffer": "accept => offer",
        "ClientHandshakeKeysBeforeOneRtt": 'c_1rtt => (c_hs /\\ c = "app")',
        "ServerHandshakeKeysBeforeOneRtt": "s_1rtt => s_hs",
        "OfferedZeroRttBeforeHandshakeKeys": '(c = "hs" \\/ c = "app") /\\ offer => c_zrtt',
        "AcceptedZeroRttBeforeServerHello": '(s = "sh" \\/ s = "hs" \\/ s = "app" \\/ s = "nst") /\\ accept => s_zrtt',
        "FullHandshakeSkipsZeroRtt": "~offer => (~c_zrtt /\\ ~s_zrtt)",
        "TicketOnlyAfterServerOneRtt": 's = "nst" => (s_1rtt /\\ s_hs)',
        "NoStekEmitsNoTicket": '~stek => s # "nst"',
        "NoKeysBeforeClientHello": 'c = "start" => (~c_zrtt /\\ ~c_hs /\\ ~c_1rtt)',
    },
    "ParallaXClose": {
        "OpenHasNoClose": 'phase = "open" => (reason = "none" /\\ ~sent /\\ after # "close")',
        "ClosePacketOnlyForLocal": 'sent => (reason = "local" /\\ after = "close")',
        "PeerCloseIsSilent": 'reason = "peer" => (~sent /\\ after = "none")',
        "IdleCloseIsSilent": 'reason = "idle" => (~sent /\\ after = "none")',
        "TransmitAfterCloseIsTheClosePacket": '(phase \\in {"closing", "drained"} => after \\in {"none", "close"}) /\\ (after \\in {"appdata", "ack", "stream", "probe"} => phase = "open")',
        "DrainedHasAReason": 'phase = "drained" => reason \\in {"local", "peer", "idle"}',
    },
    "ParallaXBbr": {
        "StartupIsUnfilled": 'mode = "startup" => (~filled /\\ quiet < 3 /\\ phase = 0)',
        "ProbeBwMeansFull": 'mode = "probe_bw" => (filled /\\ quiet = 3)',
        "ProbeRttMeansFull": 'mode = "probe_rtt" => (filled /\\ quiet = 3 /\\ probe_due)',
        "ZeroSampleDoesNotCount": 'undid => (quiet = 0 /\\ mode = "startup" /\\ ~filled)',
        "PhaseInCycle": "phase \\in {0, 1, 2, 3, 4, 5, 6, 7}",
        "QuietInBounds": "quiet \\in {0, 1, 2, 3}",
    },
    "ParallaXPacket": {
        "ShortHeaderIsOneRtt": '(form = "short" /\\ space # "pending" => space = "1rtt") /\\ (space = "1rtt" => form = "short")',
        "LongTypesMatchTheirSpace": '(form = "initial" /\\ space # "pending" => space = "initial") /\\ (form = "zerortt" /\\ space # "pending" => space = "0rtt") /\\ (form = "handshake" /\\ space # "pending" => space = "handshake")',
        "RetryIsNotASpace": 'form = "retry" /\\ space # "pending" => space = "none"',
        "ClearFixedBitIsNotASpace": 'form = "bad_fixed" /\\ space # "pending" => space = "none"',
        "EmptyIsNotASpace": 'form = "empty" /\\ space # "pending" => space = "none"',
        "ZeroRttIsItsOwnSpace": 'space = "0rtt" => form = "zerortt"',
        "NoneOnlyForRejects": 'space = "none" => form \\in {"empty", "bad_fixed", "retry"}',
    },
}


if __name__ == "__main__":
    unittest.main()
