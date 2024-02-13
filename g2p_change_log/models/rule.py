from odoo import fields, models


class AuditlogRuleInherit(models.Model):
    _inherit = "auditlog.rule"

    other_contact = fields.Boolean(
        string="Include Only Registry Contacts",
        default=True,
        help=("Select this if you want to include only registry contacts"),
    )

    def create_logs(
        self,
        uid,
        res_model,
        res_ids,
        method,
        old_values=None,
        new_values=None,
        additional_log_values=None,
    ):
        model_id = self.pool._auditlog_model_cache[res_model]
        auditlog_rule = self.env["auditlog.rule"].search([("model_id", "=", model_id)])

        if res_model == "res.partner":
            partners = self.env[res_model].sudo().browse(res_ids)
            if auditlog_rule.other_contact and partners.filtered(
                lambda partner: not (partner.is_registrant or partner.is_group)
            ):
                return

        return super().create_logs(
            uid,
            res_model,
            res_ids,
            method,
            old_values,
            new_values,
            additional_log_values,
        )
