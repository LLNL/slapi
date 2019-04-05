bin_SCRIPTS = slapi
CLEANFILES = $(bin_SCRIPTS)

EXTRA = \
        AUTHORS \
        COPYING \
        INSTALL \
        NEWS \
        README

doc_DATA = $(EXTRA)

do_subst = sed -e 's,[@]PACKAGE[@],$(PACKAGE),g' \
            -e 's,[@]VERSION[@],$(VERSION),g'

slapi: slapi.py
	$(do_subst) < $(srcdir)/slapi.py > slapi
	chmod +x slapi

uninstall-extra:
	$(docdir)

EXTRA_DIST = $(EXTRA)
