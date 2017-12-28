TOP := $(shell pwd)
PROJECT = auth-cas
SOURCE = $(TOP)/$(PROJECT)
BUILDDIR = $(TOP)/build

all: $(BUILDDIR)/$(PHAR)

builddir:
	mkdir -p $(BUILDDIR)

dependencies: $(BUILDDIR)/osTicket-plugins

$(BUILDDIR)/osTicket-plugins: builddir
	@if [ ! -d $@ ]; then \
		echo "osTicket-plugins dep missing, fetching..."; \
		git clone https://github.com/osTicket/osTicket-plugins.git $@; \
	fi

$(BUILDDIR)/$(PHAR): dependencies
	cd $(BUILDDIR)/osTicket-plugins \
		&& php -dphar.readonly=0 make.php \
			build $(SOURCE) \
		&& mv $(TOP)/$(PROJECT).phar $@ \

clean:
	rm -rf $(BUILDDIR)