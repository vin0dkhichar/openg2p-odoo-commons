{
    "name": "OpenG2P Change Log",
    "category": "G2P",
    "version": "17.0.1.0.0",
    "sequence": 1,
    "author": "OpenG2P",
    "website": "https://openg2p.org",
    "license": "Other OSI approved licence",
    "development_status": "Alpha",
    # any module necessary for this one to work correctly
    "depends": ["base", "auditlog"],
    # always loaded
    "data": [
        # 'security/ir.model.access.csv',
        "data/auditlog_rule_data.xml",
        "views/rule_view.xml",
        "views/menu_view.xml",
        "views/audit_log_view.xml",
    ],
    "assets": {},
    "external_dependencies": {},
    "demo": [],
    "images": [],
    "application": True,
    "installable": True,
    "auto_install": False,
}