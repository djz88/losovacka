# -*- coding: utf-8 -*-
from django import forms

class RunDrawForm(forms.Form):
    items = forms.CharField(
        label="Účastníci (CSV)",
        help_text="Např. 1,2,3,4,5 nebo Alice,Bob,Carol",
        widget=forms.TextInput(attrs={"placeholder": "1,2,3,4,5"})
    )
    when = forms.CharField(
        label="Čas (UTC, minuta, ISO 8601)",
        required=False,
        help_text="Např. 2025-10-17T17:00:00Z. Nech prázdné, pokud chceš fair=předchozí minuta."
    )
    fair = forms.BooleanField(
        label="Fair = předchozí minuta (bez čekání)",
        required=False,
        initial=False
    )

    def clean(self):
        data = super().clean()
        fair = data.get("fair")
        when = data.get("when")
        if not fair and not when:
            raise forms.ValidationError("Zadej buď 'when', nebo zaškrtni 'fair'.")
        if fair and when:
            raise forms.ValidationError("Buď 'fair', nebo 'when' – ne obojí.")
        return data


class VerifyForm(forms.Form):
    audit_url = forms.URLField(
        label="URL s auditním JSON (volitelné)",
        required=False,
        widget=forms.URLInput(attrs={"placeholder": "https://.../audit.json"})
    )
    audit_json = forms.CharField(
        label="Audit JSON (volitelné)",
        required=False,
        widget=forms.Textarea(attrs={"rows": 8, "placeholder": '{"version":2,...}'})
    )

    def clean(self):
        data = super().clean()
        if not data.get("audit_url") and not data.get("audit_json"):
            raise forms.ValidationError("Vyplň URL nebo vlož audit JSON.")
        return data

