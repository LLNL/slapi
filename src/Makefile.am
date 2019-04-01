bin_SCRIPTS = slapi
CLEANFILES = $(bin_SCRIPTS)

do_subst = sed -e 's,[@]PACKAGE[@],$(PACKAGE),g' \
            -e 's,[@]VERSION[@],$(VERSION),g'

slapi: slapi.py
	$(do_subst) < $(srcdir)/slapi.py > slapi
	chmod +x slapi
