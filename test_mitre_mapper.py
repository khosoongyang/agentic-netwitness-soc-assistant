import unittest
import json
import os
from unittest.mock import MagicMock

from mitre_mapper import (
    TimelineEvent,
    MitreTTPMapping,
    IncidentMitreAnalysis,
    normalize_incident_input,
    format_event_sequence,
    generate_markdown_table,
    map_incident_mitre_ttps,
    SYSTEM_PROMPT,
    HUMAN_PROMPT_TEMPLATE
)
from sync_engine import Incident, IncidentMetadata

class TestMitreMapper(unittest.TestCase):

    def setUp(self):
        self.sample_events = [
            {
                "id": "INC-6125",
                "document": "User received email with malicious link http://malicious.link/payload.exe",
                "metadata": {
                    "username": "BETHANY",
                    "hostname": "WORKSTATION-01",
                    "timestamp_str": "2026-01-17T17:20:19Z",
                    "timestamp_epoch": 1768670419,
                    "tactic": "initial-access",
                    "technique": "spearphishing link",
                    "source_type": "Email"
                }
            },
            {
                "id": "INC-6126",
                "document": "Outbound connection from unsigned executable wzOCcAIIZg.exe in C:\\Users\\BETHANY\\AppData\\Local\\Temp\\ to 155.140.254.18",
                "metadata": {
                    "username": "BETHANY",
                    "hostname": "WORKSTATION-01",
                    "timestamp_str": "2026-01-17T17:31:39Z",
                    "timestamp_epoch": 1768671099,
                    "tactic": "defense-evasion",
                    "technique": "conceal directory",
                    "source_type": "Endpoint"
                }
            },
            {
                "id": "INC-6127",
                "document": "services.exe spawned cmd.exe with argument net use y: \\\\10.100.20.74\\shared_files",
                "metadata": {
                    "username": "admin2",
                    "hostname": "WORKSTATION-01",
                    "timestamp_str": "2026-01-17T17:46:35Z",
                    "timestamp_epoch": 1768671995,
                    "tactic": "lateral-movement",
                    "technique": "remote services",
                    "source_type": "Endpoint"
                }
            }
        ]
        
        self.sample_dict_incident = {
            "id": "Incident-100",
            "raw_alerts": self.sample_events
        }

        self.sample_incident_obj = Incident(
            id="Incident-200",
            metadata=IncidentMetadata(),
            raw_alerts=self.sample_events,
            summary_text="Sample correlated incident summary",
            indicators=["155.140.254.18", "10.100.20.74"]
        )

    def test_normalize_incident_input_dict(self):
        """Test input normalization from dictionary input."""
        inc_id, events = normalize_incident_input(self.sample_dict_incident)
        self.assertEqual(inc_id, "Incident-100")
        self.assertEqual(len(events), 3)
        self.assertIn("BETHANY", events[0].user_or_host)
        self.assertIn("http://malicious.link", events[0].log_summary)
        # Check chronological sorting
        self.assertLess(float(events[0].alert_context["metadata"]["timestamp_epoch"]),
                        float(events[1].alert_context["metadata"]["timestamp_epoch"]))

    def test_normalize_incident_input_object(self):
        """Test input normalization from Pydantic Incident object."""
        inc_id, events = normalize_incident_input(self.sample_incident_obj)
        self.assertEqual(inc_id, "Incident-200")
        self.assertEqual(len(events), 3)
        self.assertEqual(events[0].source, "Email")
        self.assertEqual(events[1].source, "Endpoint")

    def test_normalize_incident_input_list(self):
        """Test input normalization from a raw list of events."""
        inc_id, events = normalize_incident_input(self.sample_events)
        self.assertEqual(inc_id, "Incident-Unknown")
        self.assertEqual(len(events), 3)

    def test_prompt_construction(self):
        """Test that prompt contains single context block and constraints against alert-by-alert evaluation."""
        inc_id, events = normalize_incident_input(self.sample_dict_incident)
        event_seq_text = format_event_sequence(events)
        human_prompt = HUMAN_PROMPT_TEMPLATE.format(
            incident_id=inc_id,
            event_sequence_text=event_seq_text
        )
        
        self.assertIn("DO NOT evaluate events in isolation", SYSTEM_PROMPT)
        self.assertIn("PRECISE SUB-TECHNIQUE RESOLUTION", SYSTEM_PROMPT)
        self.assertIn("T1566.002", SYSTEM_PROMPT)
        self.assertIn("Incident-100", human_prompt)
        self.assertIn("[Event #1]", event_seq_text)
        self.assertIn("[Event #2]", event_seq_text)

    def test_markdown_table_generation(self):
        """Test rendering IncidentMitreAnalysis to Markdown table with exact 5 required columns."""
        analysis = IncidentMitreAnalysis(
            incident_id="Incident-100",
            attack_chain_summary="Attacker delivered phishing link leading to malware execution and lateral movement.",
            mappings=[
                MitreTTPMapping(
                    timeline_phase="Initial Access",
                    observed_evidence="user BETHANY clicked on http://malicious.link",
                    tactic="Initial Access",
                    technique_name="Phishing: Spearphishing Link",
                    technique_id="T1566.002"
                ),
                MitreTTPMapping(
                    timeline_phase="Execution & Defense Evasion",
                    observed_evidence="Executed wzOCcAIIZg.exe from Temp directory",
                    tactic="Defense Evasion",
                    technique_name="Hide Artifacts: Conceal Execution Directory",
                    technique_id="T1564.001"
                )
            ]
        )

        table_md = generate_markdown_table(analysis)
        self.assertIn("| Timeline Phase / Activity | Observed Evidence | MITRE Tactic | MITRE Technique Name | MITRE ID |", table_md)
        self.assertIn("| Initial Access | user BETHANY clicked on http://malicious.link | Initial Access | Phishing: Spearphishing Link | T1566.002 |", table_md)
        self.assertIn("| Execution & Defense Evasion | Executed wzOCcAIIZg.exe from Temp directory | Defense Evasion | Hide Artifacts: Conceal Execution Directory | T1564.001 |", table_md)

    def test_map_incident_mitre_ttps_with_mock_response(self):
        """Test handler using explicit mock_response."""
        mock_data = {
            "incident_id": "Incident-100",
            "attack_chain_summary": "Full chain attack.",
            "mappings": [
                {
                    "timeline_phase": "Initial Access",
                    "observed_evidence": "User clicked http://malicious.link",
                    "tactic": "Initial Access",
                    "technique_name": "Phishing: Spearphishing Link",
                    "technique_id": "T1566.002"
                }
            ]
        }
        analysis, table_md = map_incident_mitre_ttps(self.sample_dict_incident, mock_response=mock_data)
        self.assertEqual(analysis.incident_id, "Incident-100")
        self.assertEqual(analysis.mappings[0].technique_id, "T1566.002")
        self.assertIn("T1566.002", table_md)

    def test_map_incident_mitre_ttps_with_mock_llm(self):
        """Test handler with mock LLM invocation verifying structured output flow."""
        from langchain_core.runnables import RunnableLambda

        mock_analysis = IncidentMitreAnalysis(
            incident_id="Incident-100",
            attack_chain_summary="Mocked LLM chain summary",
            mappings=[
                MitreTTPMapping(
                    timeline_phase="Initial Access",
                    observed_evidence="Phishing link clicked",
                    tactic="Initial Access",
                    technique_name="Phishing: Spearphishing Link",
                    technique_id="T1566.002"
                )
            ]
        )

        class MockLLM:
            def with_structured_output(self, schema, method="json_schema"):
                return RunnableLambda(lambda x: mock_analysis)

        analysis, table_md = map_incident_mitre_ttps(self.sample_dict_incident, llm=MockLLM())
        self.assertEqual(analysis.incident_id, "Incident-100")
        self.assertEqual(analysis.mappings[0].technique_id, "T1566.002")
        self.assertIn("Phishing: Spearphishing Link", table_md)

    def test_map_incident_fallback(self):
        """Test heuristic fallback mapper when no LLM is provided."""
        analysis, table_md = map_incident_mitre_ttps(self.sample_dict_incident, llm=None)
        self.assertEqual(analysis.incident_id, "Incident-100")
        self.assertTrue(len(analysis.mappings) > 0)
        self.assertIn("T1566.002", [m.technique_id for m in analysis.mappings])
        self.assertIn("| Timeline Phase / Activity | Observed Evidence | MITRE Tactic | MITRE Technique Name | MITRE ID |", table_md)

    def test_real_incident_file_mapping(self):
        """Test with actual incident report JSON file if available."""
        file_path = os.path.join("incident_reports", "Incident-001", "incident_data.json")
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            analysis, table_md = map_incident_mitre_ttps(data, llm=None)
            self.assertEqual(analysis.incident_id, "Incident-001")
            self.assertGreater(len(analysis.mappings), 0)
            self.assertIn("T1566.001", [m.technique_id for m in analysis.mappings])
            print("\n[+] Rendered Table for Incident-001:\n")
            print(table_md)

if __name__ == "__main__":
    unittest.main()
