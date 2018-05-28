TOP := $(shell pwd)
PROJECT = auth-cas
SOURCE = $(TOP)/$(PROJECT)
BUILDDIR = $(TOP)/build
PHAR = $(PROJECT).phar

all: $(BUILDDIR)/$(PHAR)

builddir:
	mkdir -p $(BUILDDIR)

dependencies: $(BUILDDIR)/osTicket-plugins

deploy-docker: $(BUILDDIR)/$(PHAR)
	docker cp $(BUILDDIR)/$(PHAR) \
		$$(docker-compose ps -q osticket):/data/upload/include/plugins/auth-cas.phar

$(BUILDDIR)/osTicket-plugins: builddir
	@if [ ! -d $@ ]; then \
		echo "osTicket-plugins dep missing, fetching..."; \
		git clone --depth=1 \
			https://github.com/osTicket/osTicket-plugins.git $@; \
	fi

$(BUILDDIR)/$(PHAR): dependencies
	cd $(BUILDDIR)/osTicket-plugins \
		&& php -dphar.readonly=0 make.php \
			build $(SOURCE) \
		&& mv $(TOP)/$(PHAR) $@ \

clean:
	rm -rf $(BUILDDIR)