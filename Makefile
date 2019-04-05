# Make sure that user sets SERIES
# There are much better ways to do this, but
# we may not have GNU Make on AIX so
# just force the check for every rule...=(
PACKAGENAME = slapi
PACKAGEVERSION := $(shell cat VERSION)
PACKAGERELEASE := $(shell cat RELEASE)
BUILDSOURCE = --buildsource
URL = ssh://git@github.com:LLNL/$(PACKAGENAME).git

all: $(PACKAGENAME)

$(PACKAGENAME):
	cd src && \
	./autogen.sh && \
	./configure --prefix=/usr && \
	make -s

.PHONY:
cscope: .PHONY
	rm -f cscope.*
	find ${PWD}/src -name .pc -prune -o -name '*.[chxsS]' -print > cscope.files
	cscope -b -u -k -R

svntag:
	./scripts/svntag.pl $(PACKAGENAME) $(URL)

tag: .PHONY
	@echo Tagging this as $(PACKAGENAME)-$(PACKAGEVERSION)-$(PACKAGERELEASE)
	git tag -a $(PACKAGENAME)-$(PACKAGEVERSION)-$(PACKAGERELEASE) -m "Tagging this as $(PACKAGENAME)-$(PACKAGEVERSION)-$(PACKAGERELEASE)"
	@echo To push your new tag to BitBucket run:
	@echo git push origin --tags

tags: .PHONY
	ctags -R --exclude=.pc --exclude=.svn src

rpms-release:
	./scripts/build-rpm.pl --name $(PACKAGENAME) $(BUILDSOURCE) --scmtype git --scmurl $(URL)

rpms: $(PACKAGENAME)
	./scripts/build-rpm.pl --name $(PACKAGENAME) $(BUILDSOURCE) --snapshot -s . -f specs/$(PACKAGENAME).spec

clean:
	rm -rf .quilt tags cscope.*
	cd src && ./autoclean.sh
