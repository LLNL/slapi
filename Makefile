# Make sure that user sets SERIES
# There are much better ways to do this, but
# we may not have GNU Make on AIX so
# just force the check for every rule...=(
PACKAGENAME = slapi
PACKAGEVERSION := $(shell cat VERSION)
PACKAGERELEASE := $(shell cat RELEASE)
BUILDSOURCE = --buildsource
URL = ssh://git@cz-bitbucket.llnl.gov:7999/dsg/$(PACKAGENAME).git

all: $(PACKAGENAME)

$(PACKAGENAME):
	cd src && make -S

.PHONY:
cscope: .PHONY
	rm -f cscope.*
	find src -name .pc -prune -o -name '*.[chxsS]' -print > cscope.files
	cscope -b -k

tags: .PHONY
	ctags -R --exclude=.pc --exclude=.svn src

tag: .PHONY
	@echo Tagging this as $(PACKAGENAME)-$(PACKAGEVERSION)-$(PACKAGERELEASE)
	git tag -a $(PACKAGENAME)-$(PACKAGEVERSION)-$(PACKAGERELEASE) -m "Tagging this as $(PACKAGENAME)-$(PACKAGEVERSION)-$(PACKAGERELEASE)"
	@echo To push your new tag to BitBucket run:
	@echo git push origin --tags

rpms-release:
	./scripts/build-rpm.pl --name $(PACKAGENAME) $(BUILDSOURCE) --scmtype git --scmurl $(URL)

rpms: $(PACKAGENAME)
	./scripts/build-rpm.pl --name $(PACKAGENAME) $(BUILDSOURCE) --snapshot -s . -f specs/$(PACKAGENAME).spec

clean:
	rm -rf .quilt
	rm -rf .quilt tags cscope.*
	cd src && make -S -s clean
