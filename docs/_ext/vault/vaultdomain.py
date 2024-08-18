"""
Allows to link configuration values using :vconf:`config_val`.
"""


def setup(app):
    app.add_crossref_type(
        directivename="vconf",
        rolename="vconf",
        indextemplate="single: configuration; %s",
    )
    return {"parallel_read_safe": True, "parallel_write_safe": True}
