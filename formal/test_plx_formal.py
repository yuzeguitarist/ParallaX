#!/usr/bin/env python3
"""The formal checker finds a planted illegal transition, and the real model is clean."""

import tempfile
import unittest
from unittest.mock import patch
from dataclasses import replace
from pathlib import Path

import plx_formal


class FormalModelTests(unittest.TestCase):
    def test_tlc_never_executes_an_implicit_temporary_jar(self):
        with patch.object(plx_formal.subprocess, "Popen") as java:
            for command in ("tlc", "all"):
                with self.subTest(command=command), self.assertRaises(SystemExit) as error:
                    plx_formal.main([command])
                self.assertEqual(error.exception.code, 2)
            java.assert_not_called()

    def test_real_model_holds_and_matches_tla(self):
        reports = plx_formal.check_all()
        names = {report.name: report.states for report in reports}
        self.assertEqual(
            names,
            {
                "ParallaXSession": 114,
                "ParallaXQuic": 260,
                "ParallaXZeroRtt": 418,
                "ParallaXReplay": 26,
                "ParallaXProbe": 224,
                "ParallaXInbound": 32,
                "ParallaXKeys": 125,
                "ParallaXClose": 21,
                "ParallaXBbr": 56,
                "ParallaXPacket": 14,
                "ParallaXRecords": 176,
                "ParallaXFragments": 23,
                "ParallaXMux": 17762,
                "ParallaXIdentityChunks": 5464,
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

    def test_session_distinguishes_early_pending_splice_and_late_commit_close(self):
        machine = plx_formal.session_machine()
        cases = (
            ("EarlyStaleSplice", lambda a: replace(a, assign={**a.assign, "phase": '"epoch0"',
                                                             "keys": "TRUE", "usable": "TRUE"}),
             "PendingRefusalSplicesWithoutKeys"),
            ("InstallEpoch0", lambda a: replace(a, guard='phase = "authed"'), "EpochZeroRequiresAdmission"),
            ("ReplayStale", lambda a: replace(a, assign={**a.assign, "how": '"splice"'}), "ReplayClosesBeforeRekey"),
            ("ReplayMissingCache", lambda a: replace(a, assign={**a.assign, "how": '"splice"'}), "ReplayClosesBeforeRekey"),
            ("RekeyOk", lambda a: replace(a, guard=a.guard.replace('admission = "reserved"', 'admission = "missing"')),
             "BindingMeansRekeyedEpoch"),
        )
        for name, change, invariant in cases:
            with self.subTest(action=name):
                actions = tuple(change(a) if a.name == name else a for a in machine.actions)
                self.assertNotEqual(actions, machine.actions)
                with self.assertRaises(plx_formal.FormalError) as caught:
                    plx_formal.check_machine(replace(machine, actions=actions))
                self.assertIn(invariant, str(caught.exception))

    def test_pending_admission_correspondence_detects_removed_reservation_and_refusal(self):
        cases = (
            ("cache.reserve_pending(&entry, now)", "unchecked_pending_admission()", "early pending admission refuses"),
            ("if !fresh {", "if false {", "missing if !fresh"),
        )
        for before, after, message in cases:
            with self.subTest(anchor=before), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                for relative in plx_formal.CORRESPOND_FILES:
                    target = root / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text((plx_formal.ROOT / relative).read_text())
                target = root / "src/handshake/server.rs"
                source = target.read_text()
                self.assertIn(before, source)
                target.write_text(source.replace(before, after))
                with self.assertRaises(plx_formal.FormalError) as caught:
                    plx_formal.correspond(root)
                self.assertIn(message, str(caught.exception))

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

    def test_record_failure_cannot_roll_back_or_clear_poison(self):
        machine = plx_formal.records_machine()
        cases = (
            (plx_formal.act("RollbackReservation", 'phase = "failed" /\\ next # 0', next="0"),
             "ReservationIsNeverRolledBack"),
            (plx_formal.act("RollbackAllCounterCopies", 'phase = "failed" /\\ next # 0',
                           next="0", high="0", base="0", prior_end="0"),
             "ReservationIsNeverRolledBack"),
            (plx_formal.act("RollbackPublishedCounters", 'phase = "ready" /\\ next # 0',
                           next="0", high="0", base="0", prior_end="0"),
             "ReservationIsNeverRolledBack"),
            (plx_formal.act("ReviveAfterFailure", 'phase = "failed" /\\ poisoned', poisoned="FALSE"),
             "FailedBatchPoisonsPermanently"),
            (plx_formal.act("PublishBeforeSibling", 'phase = "reserved" /\\ remaining = 1',
                           phase='"ready"', published="TRUE"),
             "PublishOnlyWholeSuccess"),
        )
        for bad_action, invariant in cases:
            with self.subTest(action=bad_action.name), self.assertRaises(plx_formal.FormalError) as caught:
                plx_formal.check_machine(replace(machine, actions=machine.actions + (bad_action,)))
            self.assertIn(invariant, str(caught.exception))
            self.assertIn(bad_action.name, str(caught.exception))

    def test_record_reservation_history_survives_fresh_key_reset(self):
        machine = plx_formal.records_machine()
        rekey = next(action for action in machine.actions if action.name == "FreshKeyRekey")
        self.assertEqual(rekey.assign["next"], "0")
        for action in machine.actions:
            for epoch in (0, 1):
                ledger = f"reserved{epoch}"
                if ledger in action.assign:
                    self.assertIn(action.name, (f"Reserve1Epoch{epoch}", f"Reserve2Epoch{epoch}"))
                    self.assertIn(action.assign[ledger], (f"{ledger} + 1", f"{ledger} + 2"))
        report = plx_formal.check_machine(machine)
        self.assertIn("FreshKeyCanReuseSequence", report.witness_names)
        self.assertIn("RekeyKeepsPoison", report.witness_names)

    def test_fragment_completion_requires_all_bytes_and_clears_latch(self):
        machine = plx_formal.fragments_machine()
        cases = (
            (plx_formal.act("EmitPrefix", 'total = 3 /\\ cursor = 1 /\\ ~stopped',
                           total="0", cursor="0", frames="frames + 1", emitted="TRUE",
                           outcome='"complete"'),
             "EmitOnlyCompleteFrame"),
            (plx_formal.act("KeepOldLatch", "emitted /\\ ~stopped /\\ total = 0", total="1"),
             "CompletionClearsLatch"),
        )
        for bad_action, invariant in cases:
            with self.subTest(action=bad_action.name), self.assertRaises(plx_formal.FormalError) as caught:
                plx_formal.check_machine(replace(machine, actions=machine.actions + (bad_action,)))
            self.assertIn(invariant, str(caught.exception))
            self.assertIn(bad_action.name, str(caught.exception))

    def test_new_correspondence_contracts_detect_poison_and_latch_removal(self):
        cases = (
            ("src/crypto/session.rs", "self.next = 0;",
             "self.next = 0; self.poisoned = false;", "without clearing poison"),
            ("src/protocol/command.rs", "self.expected_total = None;",
             "/* completion latch reset removed */", "clears state before emission"),
        )
        for relative, before, after, message in cases:
            with self.subTest(file=relative), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                for source_path in plx_formal.CORRESPOND_FILES:
                    target = root / source_path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text((plx_formal.ROOT / source_path).read_text())
                target = root / relative
                source = target.read_text()
                self.assertEqual(source.count(before), 1)
                target.write_text(source.replace(before, after, 1))
                with self.assertRaises(plx_formal.FormalError) as caught:
                    plx_formal.correspond(root)
                self.assertIn(message, str(caught.exception))

    def test_mux_contracts_reject_early_release_cross_stream_abort_and_fin_bypass(self):
        machine = plx_formal.mux_machine()
        cases = (
            ("Fin0", lambda a: replace(a, assign={**a.assign, "charged0": "FALSE"}), "MuxOwnership0"),
            ("Reset0", lambda a: replace(a, assign={**a.assign, "task0": '"none"', "charged0": "FALSE",
                                                   "up0": "FALSE", "down0": "FALSE"}), "MuxResetKeepsSlotUntilExit0"),
            ("Reset0", lambda a: replace(a, assign={**a.assign, "task1": '"none"', "charged1": "FALSE",
                                                   "upload1": "FALSE", "up1": "FALSE", "down1": "FALSE"}), "MuxLocalEventsPreserveSibling"),
            ("DataDelivered0", lambda a: replace(a, guard=a.guard.replace("upload0 /\\ up0", "~upload0 /\\ up0")),
             "MuxDataRequiresUploadRoute0"),
            ("Open1", lambda a: replace(a, guard=a.guard.replace("capacity = 2 \\/ ~charged0", "capacity = 1 /\\ charged0")),
             "MuxCapacityCountsBothHalves"),
        )
        for prefix, change, invariant in cases:
            with self.subTest(action=prefix, invariant=invariant):
                actions = tuple(change(a) if a.name.startswith(prefix) else a for a in machine.actions)
                self.assertNotEqual(actions, machine.actions)
                with self.assertRaises(plx_formal.FormalError) as caught:
                    plx_formal.check_machine(replace(machine, actions=actions))
                self.assertIn(invariant, str(caught.exception))

    def test_identity_caller_rejects_gap_partial_cap_deadline_and_signature_bypasses(self):
        machine = plx_formal.identity_chunks_machine()
        cases = (
            ("IdentityPartial", {"phase": '"assembled"'}, "IdentityPartialCannotVerify"),
            ("IdentityWrongOffset", {"phase": '"completion"', "before_cursor": "cursor", "cursor": "incoming_end"},
             "IdentityAppendRequiresValidatedMetadata"),
            ("IdentityCapReject", {"phase": '"offset"', "total": "incoming_total"}, "IdentityBufferNeverExceedsCap"),
            ("IdentityChangedTotal", {"phase": '"offset"'}, "IdentityAppendRequiresValidatedMetadata"),
            ("IdentityEstablishmentTimeout", {"connect_sent": "TRUE"}, "IdentityFailureBlocksConnect"),
            ("IdentityBadSignature", {"phase": '"connect"', "connect_sent": "TRUE"}, "IdentityConnectWaitsForVerification"),
        )
        for name, assign, invariant in cases:
            with self.subTest(action=name):
                actions = tuple(replace(a, assign={**a.assign, **assign}) if a.name == name else a
                                for a in machine.actions)
                with self.assertRaises(plx_formal.FormalError) as caught:
                    plx_formal.check_machine(replace(machine, actions=actions))
                self.assertIn(invariant, str(caught.exception))

    def test_mux_carrier_teardown_waits_for_aborted_supervisors(self):
        machine = plx_formal.mux_machine()
        actions = tuple(replace(a, assign={**a.assign, "phase": '"closed"'})
                        if a.name == "CarrierTeardown" else a for a in machine.actions)
        with self.assertRaises(plx_formal.FormalError) as caught:
            plx_formal.check_machine(replace(machine, actions=actions))
        self.assertIn("MuxTeardownReleasesAllSlots", str(caught.exception))

    def test_snapshot_assignments_read_pre_step_fields(self):
        copy = plx_formal._compile_rhs("source", {"source": 0, "destination": 1})
        self.assertEqual(copy(("relaying", "none")), "relaying")
        self.assertEqual(copy((False, True)), False)
        with self.assertRaises(plx_formal.FormalError):
            plx_formal._compile_rhs("unknown_field", {"source": 0})

    def test_mux_and_px1i_correspondence_detect_live_slot_and_parser_gate_removal(self):
        cases = (
            ("src/handshake/server.rs", "streams.tasks.get(&frame.stream_id)",
             "streams.tasks.remove(&frame.stream_id)", "without releasing the task slot early"),
            ("src/client/runtime.rs", "chunk.offset as usize != assembled.len()",
             "false", "PX1I caller authenticates"),
        )
        for relative, before, after, message in cases:
            with self.subTest(file=relative), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                for source_path in plx_formal.CORRESPOND_FILES:
                    target = root / source_path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text((plx_formal.ROOT / source_path).read_text())
                target = root / relative
                source = target.read_text()
                self.assertEqual(source.count(before), 1)
                target.write_text(source.replace(before, after, 1))
                with self.assertRaises(plx_formal.FormalError) as caught:
                    plx_formal.correspond(root)
                self.assertIn(message, str(caught.exception))

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

    def test_correspondence_rejects_unlocked_replay_cache_initialization(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for relative in plx_formal.CORRESPOND_FILES:
                source = plx_formal.ROOT / relative
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(source.read_text())
            server = root / "src/handshake/server.rs"
            source = server.read_text()
            self.assertIn("slot.lock()", source)
            server.write_text(source.replace("slot.lock()", "unlocked_slot()", 1))
            with self.assertRaises(plx_formal.FormalError) as caught:
                plx_formal.correspond(root)
        self.assertIn("single-flight lock", str(caught.exception))

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
    "ParallaXMux": {
        "MuxCapacityCountsBothHalves": "capacity = 1 => ~(charged0 /\\ charged1)",
        "MuxLocalEventsPreserveSibling": 'event # "teardown" => ((focus = 0 => (task1 = before_task1 /\\ upload1 = before_upload1 /\\ up1 = before_up1 /\\ down1 = before_down1 /\\ charged1 = before_charged1)) /\\ (focus = 1 => (task0 = before_task0 /\\ upload0 = before_upload0 /\\ up0 = before_up0 /\\ down0 = before_down0 /\\ charged0 = before_charged0)))',
        "MuxRejectedOpenAndCoverAreInert": 'event \\in {"DuplicateOpen", "CapacityReject", "Cover"} => (task0 = before_task0 /\\ upload0 = before_upload0 /\\ up0 = before_up0 /\\ down0 = before_down0 /\\ charged0 = before_charged0 /\\ task1 = before_task1 /\\ upload1 = before_upload1 /\\ up1 = before_up1 /\\ down1 = before_down1 /\\ charged1 = before_charged1)',
        "MuxTeardownReleasesAllSlots": 'phase = "closed" => (~charged0 /\\ ~charged1 /\\ ~up0 /\\ ~up1 /\\ ~down0 /\\ ~down1)',
        "MuxOwnership0": '(charged0 => task0 # "none") /\\ (task0 # "none" => charged0) /\\ (upload0 => charged0)',
        "MuxLiveHalfKeepsSlot0": "(up0 \\/ down0) => charged0",
        "MuxFinIsHalfClose0": 'event = "Fin" /\\ focus = 0 => (~upload0 /\\ charged0 /\\ task0 = before_task0 /\\ up0 = before_up0 /\\ down0 = before_down0)',
        "MuxDataRequiresUploadRoute0": 'event = "DataDelivered" /\\ focus = 0 => (upload0 /\\ up0 /\\ charged0)',
        "MuxResetKeepsSlotUntilExit0": 'event = "Reset" /\\ focus = 0 => (task0 = "cancelling" /\\ charged0 /\\ ~upload0)',
        "MuxOwnership1": '(charged1 => task1 # "none") /\\ (task1 # "none" => charged1) /\\ (upload1 => charged1)',
        "MuxLiveHalfKeepsSlot1": "(up1 \\/ down1) => charged1",
        "MuxFinIsHalfClose1": 'event = "Fin" /\\ focus = 1 => (~upload1 /\\ charged1 /\\ task1 = before_task1 /\\ up1 = before_up1 /\\ down1 = before_down1)',
        "MuxDataRequiresUploadRoute1": 'event = "DataDelivered" /\\ focus = 1 => (upload1 /\\ up1 /\\ charged1)',
        "MuxResetKeepsSlotUntilExit1": 'event = "Reset" /\\ focus = 1 => (task1 = "cancelling" /\\ charged1 /\\ ~upload1)',
    },
    "ParallaXIdentityChunks": {
        "IdentityBufferNeverExceedsCap": "cursor \\in {0, 1, 2, 3} /\\ total \\in {0, 1, 2, 3} /\\ ~(total < cursor)",
        "IdentityAppendRequiresValidatedMetadata": 'phase = "completion" => (total = incoming_total /\\ incoming_offset = before_cursor /\\ cursor = incoming_end /\\ incoming_len # 0 /\\ incoming_offset < cursor /\\ ~(total < cursor))',
        "IdentityPartialCannotVerify": 'phase \\in {"assembled", "verified", "connect"} => (total # 0 /\\ cursor = total)',
        "IdentityVerificationNeedsWholeBoundPayload": "verified => (binding /\\ total # 0 /\\ cursor = total)",
        "IdentityFailureBlocksConnect": 'phase = "failed" => ~connect_sent',
        "IdentityConnectWaitsForVerification": 'connect_sent => (phase = "connect" /\\ verified /\\ binding /\\ cursor = total /\\ total # 0)',
    },
    "ParallaXRecords": {
        "ReservedRangesNeverOverlap": 'phase = "reserved" => (base = prior_end /\\ base < next /\\ next = high)',
        "ReservationIsNeverRolledBack": "next = high /\\ (epoch = 0 => next = reserved0) /\\ (epoch = 1 => next = reserved1)",
        "FailedBatchPoisonsPermanently": "failed => poisoned",
        "PoisonedCannotDispatch": 'poisoned => (phase # "reserved" /\\ ~published)',
        "PublishOnlyWholeSuccess": 'published => (phase = "ready" /\\ remaining = 0 /\\ ~poisoned /\\ ~failed)',
        "RecordWindowIsBounded": "next \\in {0, 1, 2, 3} /\\ epoch \\in {0, 1} /\\ reserved0 \\in {0, 1, 2, 3} /\\ reserved1 \\in {0, 1, 2, 3}",
    },
    "ParallaXFragments": {
        "FragmentsStayWithinTotal": '(total = 0 => cursor = 0) /\\ (total # 0 => (cursor < total /\\ total \\in {1, 2, 3}))',
        "EmitOnlyCompleteFrame": 'emitted => (outcome = "complete" /\\ last_size = last_total /\\ last_total # 0 /\\ frames # 0)',
        "CompletionClearsLatch": 'outcome = "complete" => (total = 0 /\\ cursor = 0)',
        "RejectedChunkEmitsNothing": 'outcome = "error" => (stopped /\\ ~emitted)',
        "PartialChunkEmitsNothing": 'outcome = "partial" => (~emitted /\\ total # 0 /\\ cursor # 0)',
        "FrameCountIsBounded": "frames \\in {0, 1, 2}",
    },
    "ParallaXSession": {
        "AppOnlyAfterIdentity": 'app => (phase = "app" /\\ binding /\\ epoch = 1 /\\ usable /\\ keys)',
        "VerifiedImpliesBinding": 'phase \\in {"verified", "app"} => (binding /\\ epoch = 1 /\\ keys /\\ usable)',
        "RekeyedImpliesFreshCommit": 'phase = "rekeyed" => (replay = "inserted" /\\ binding /\\ epoch = 1 /\\ usable)',
        "ReplayClosesBeforeRekey": 'replay \\in {"replayed", "stale", "full", "source_quota", "missing"} => (phase = "rejected" /\\ epoch = 0 /\\ keys /\\ ~binding /\\ ~app /\\ ~usable /\\ how # "splice")',
        "PendingRefusalSplicesWithoutKeys": 'admission \\in {"stale", "committed_nonce", "committed_transcript", "duplicate_pending", "pending_full", "busy"} => (phase = "failed" /\\ how = "splice" /\\ epoch = 0 /\\ ~keys /\\ ~usable /\\ ~binding /\\ ~app)',
        "EpochZeroRequiresAdmission": 'keys => admission \\in {"reserved", "missing"}',
        "AdmittedStillHasNoKeys": 'phase = "admitted" => (admission \\in {"reserved", "missing"} /\\ epoch = 0 /\\ ~keys /\\ ~usable /\\ ~binding)',
        "IdleAndReconnectAreFresh": 'phase = "idle" => (epoch = 0 /\\ ~binding /\\ ~keys /\\ ~usable /\\ ~app /\\ udp = "none" /\\ admission = "none" /\\ replay = "none" /\\ how = "none")',
        "AuthedHasNoKeys": 'phase = "authed" => (epoch = 0 /\\ ~keys /\\ ~usable /\\ ~binding /\\ admission = "none" /\\ how = "none")',
        "PostAuthDegenerateDoesNotSplice": 'how = "degen" => (phase = "failed" /\\ ~keys /\\ ~usable /\\ epoch = 0 /\\ ~binding /\\ ~app)',
        "RekeyDegenerateStaysAtEpochZero": 'how = "rekey_degen" => (phase = "failed" /\\ epoch = 0 /\\ keys /\\ ~usable /\\ ~binding /\\ ~app /\\ replay = "inserted")',
        "SpliceIsTheInboundReject": 'how = "splice" => (phase = "failed" /\\ ~keys /\\ epoch = 0 /\\ ~binding)',
        "TerminalDropsUsableKeys": 'phase \\in {"rejected", "closed", "failed"} => (~usable /\\ ~app /\\ udp = "none")',
        "UdpRetainOnlyAfterApp": 'udp = "retained" => (phase = "app" /\\ app /\\ usable)',
        "UdpDeclineStaysOnApp": 'udp = "tcp_only" => (phase = "app" /\\ app /\\ usable)',
        "UsableKeysImplyAuth": '(usable => keys) /\\ (keys => (phase # "idle"))',
        "EpochIsZeroOrOne": "epoch \\in {0, 1}",
        "RejectedOnlyAfterReplay": 'phase = "rejected" => replay \\in {"replayed", "stale", "full", "source_quota", "missing"}',
        "BindingMeansRekeyedEpoch": 'binding => (epoch = 1 /\\ admission = "reserved" /\\ replay = "inserted" /\\ phase \\in {"rekeyed", "verified", "app", "closed", "failed"})',
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
        "ServerAlertAfterCompleteDoesNotUndo": 'server_post_alert => (server_complete /\\ server = "done" /\\ saw_sfin /\\ ~server_alert)',
        "VerifyFollowsCertificate": "saw_cv => saw_cert",
        "PskNeverEntersCertificate": 'psk => (~saw_cert /\\ ~saw_cv /\\ client # "cert" /\\ client # "cv")',
        "TicketOnlyAfterComplete": 'nst => (complete /\\ client = "done")',
        "ServerTicketOnlyAfterComplete": 'server_ticket => (server_complete /\\ server = "done" /\\ saw_sfin)',
        "ServerNoStekIssuesNoTicket": "~stek => ~server_ticket",
        "PostAlertFollowsTheTicketCall": "server_post_alert => (~stek \\/ server_ticket)",
    },
    "ParallaXZeroRtt": {
        "EarlyDataRequiresFreshAccept": 'early => (offered /\\ decided /\\ burned /\\ accepts = 1 /\\ binder = "ok" /\\ guard = "free")',
        "FailClosedDoesNotBurnOrAccept": 'guard # "free" => (~early /\\ ~burned /\\ accepts = 0)',
        "BadBinderDoesNotBurnOrAccept": 'binder = "bad" => (~early /\\ ~burned /\\ accepts = 0)',
        "AcceptsAtMostOnce": "accepts \\in {0, 1}",
        "DurableAcceptStaysBurned": 'durable => (burned /\\ early /\\ accepts = 1 /\\ journal = "back")',
        "CheckoutIsUndurableAccept": 'journal = "out" => (burned /\\ early /\\ accepts = 1 /\\ ~durable /\\ guard = "free")',
        "CheckoutRejectsTheConcurrentOffer": 'journal = "out" /\\ replay_decided => (replay_rejected /\\ accepts = 1 /\\ burned /\\ ~durable)',
        "RestartUndoesUndurableAccept": 'restarted /\\ accepts = 0 => (~burned /\\ ~early /\\ ~durable /\\ journal = "idle")',
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
