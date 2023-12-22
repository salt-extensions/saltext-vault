"""
Allows to link configuration values using :vconf:`config_val`.
"""


def setup(app):
    app.add_crossref_type(
        directivename="vconf",
        rolename="vconf",
        indextemplate="single: %s; topics/configuration_reference",
    )
    return {"parallel_read_safe": True, "parallel_write_safe": True}
