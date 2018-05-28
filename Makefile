TOP := $(shell pwd)
PROJECT = auth-cas
SOURCE = $(TOP)/$(PROJECT)
BUILDDIR = $(TOP)/build
PHAR = $(PROJECT).phar

all: $(BUILDDIR)/$(PHAR)

builddir:
	mkdir -p $(BUILDDIR)

dependencies: $(BUILDDIR)/osticket-plugin-devtools

deploy-docker: $(BUILDDIR)/$(PHAR)
	docker cp $(BUILDDIR)/$(PHAR) \
		$$(docker-compose ps -q osticket):/data/upload/include/plugins/auth-cas.phar

$(BUILDDIR)/osticket-plugin-devtools: builddir
	@if [ ! -d $@ ]; then \
		echo "osticket-plugin-devtools dep missing, fetching..."; \
		git clone --depth=1 \
			https://github.com/kevinoconnor7/osticket-plugin-devtools.git $@; \
	fi

$(BUILDDIR)/$(PHAR): dependencies
	cd $(BUILDDIR)/osticket-plugin-devtools \
		&& php -dphar.readonly=0 manage.php \
			plugin build $(SOURCE) \
		&& mv $(PHAR) $@ \

clean:
	rm -rf $(BUILDDIR)
