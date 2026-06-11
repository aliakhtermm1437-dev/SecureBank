"""SecureBank AI Security Agent.

Bonus extension from the project rubric — combines a security-domain
LLM-style reasoning service (heuristic stub when no API key is set) with
an adversarial-ML resilience module.  Provides:

* /explain  – plain-English explanation of a Falco/QRadar/ML alert
* /triage   – priority + recommended SOAR playbook for an offense
* /review   – AI-assisted code review (CWE pattern matching)
* /adversarial/score   – robustness score for the fraud model
* /adversarial/retrain – schedule a retrain on the latest labelled data
"""
__version__ = "1.0.0"
